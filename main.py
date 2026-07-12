import os, re, unicodedata, asyncio, gc
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

# ── Config ────────────────────────────────────────────────────────────────────
KIRA_API_KEY   = os.getenv("KIRA_API_KEY",         "kira_e564cf7a91b3650799537c8bdabaed07")
KIRA_BASE_URL  = os.getenv("KIRA_BASE_URL",         "https://kiraai.vn/api/v1")
KIRA_MODEL     = os.getenv("KIRA_MODEL",            "kira-mini-1.0")
SUPABASE_URL   = os.getenv("SUPABASE_URL",          "")
SUPABASE_KEY   = os.getenv("SUPABASE_SERVICE_KEY",  "")
CONFIDENCE_THR = float(os.getenv("CONFIDENCE_THR",  "0.65"))
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL",     "10"))
BATCH_SIZE     = int(os.getenv("BATCH_SIZE",        "10"))

LABEL_NAMES = ["CLEAN", "SPAM", "TOXIC", "MEANINGLESS"]

SYSTEM_PROMPT = """Bạn là hệ thống kiểm duyệt nội dung tiếng Việt cho nền tảng hỏi đáp học sinh.

Phân loại nội dung vào 1 trong 4 nhãn:
- CLEAN: nội dung bình thường, phù hợp
- SPAM: quảng cáo, link rác, nội dung lặp vô nghĩa
- TOXIC: xúc phạm, tục tĩu, bắt nạt, nội dung độc hại
- MEANINGLESS: quá ngắn, không có nghĩa, toàn ký tự lạ

Trả lời ĐÚNG theo format JSON sau, không giải thích thêm:
{"label": "CLEAN", "confidence": 0.95, "reason": ""}

Trong đó:
- label: một trong 4 nhãn trên
- confidence: độ tin cậy từ 0.0 đến 1.0
- reason: lý do ngắn gọn nếu không phải CLEAN, để trống nếu CLEAN"""

# ── Globals ───────────────────────────────────────────────────────────────────
kira_client = None
supabase    = None
scan_task   = None

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global kira_client, supabase, scan_task

    if not KIRA_API_KEY:
        print("⚠️  KIRA_API_KEY chưa được set!")
    else:
        kira_client = OpenAI(
            base_url=KIRA_BASE_URL,
            api_key=KIRA_API_KEY,
        )
        print(f"✅ Kira AI ready! Model: {KIRA_MODEL}")

    if SUPABASE_URL and SUPABASE_KEY:
        try:
            from supabase import create_client
            supabase  = create_client(SUPABASE_URL, SUPABASE_KEY)
            scan_task = asyncio.create_task(scanner_loop())
            print("✅ Supabase OK! Scanner started!")
        except Exception as e:
            print(f"⚠️  Supabase error: {e}")
    else:
        print("ℹ️  Supabase chưa cấu hình → Scanner disabled")

    yield

    if scan_task:
        scan_task.cancel()
        try:
            await scan_task
        except asyncio.CancelledError:
            pass
    print("👋 Shutdown!")


app = FastAPI(
    title    = "HoiBai ML Moderator",
    version  = "3.0.0",
    lifespan = lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFC", text)
    text = re.sub(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        '[URL]', text
    )
    text = re.sub(r'\b0\d{9,10}\b', '[PHONE]', text)
    text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def hard_rules(text: str) -> tuple:
    t = text.strip()
    if len(t) < 2:
        return "MEANINGLESS", 1.0, "Quá ngắn"
    if re.match(r'^(.)\1+$', t):
        return "MEANINGLESS", 1.0, "Ký tự lặp"
    if re.match(r'^\d+$', t):
        return "MEANINGLESS", 1.0, "Toàn số"
    if not re.search(
        r'[a-zA-Zàáảãạăắặẳẵậâấầẩẫèéẻẽẹêếềểễệ'
        r'ìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]',
        t, re.IGNORECASE
    ):
        return "MEANINGLESS", 1.0, "Không có chữ cái"
    return None, 0.0, ""


def kira_classify(text: str, content_type: str = "question") -> tuple:
    if not kira_client:
        return "CLEAN", 0.5, "Kira chưa cấu hình"

    cleaned = clean_text(text)
    if not cleaned:
        return "MEANINGLESS", 1.0, "Text rỗng"

    user_msg = f"[{content_type.upper()}] {cleaned}"

    try:
        response = kira_client.chat.completions.create(
            model    = KIRA_MODEL,
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature = 0.0,
            max_tokens  = 100,
        )

        raw = response.choices[0].message.content.strip()

        # Parse JSON từ response
        import json
        # Tìm JSON trong response phòng trường hợp model trả thêm text
        match = re.search(r'\{.*?\}', raw, re.DOTALL)
        if not match:
            return "CLEAN", 0.5, "Parse error"

        data  = json.loads(match.group())
        label = data.get("label", "CLEAN").upper()
        conf  = float(data.get("confidence", 0.5))
        reason = data.get("reason", "")

        if label not in LABEL_NAMES:
            label = "CLEAN"

        if label != "CLEAN" and conf < CONFIDENCE_THR:
            return "CLEAN", conf, f"Dưới ngưỡng {CONFIDENCE_THR:.0%}"

        return label, round(conf, 4), reason

    except Exception as e:
        print(f"⚠️  Kira API error: {e}")
        return "CLEAN", 0.5, f"API error: {e}"


def classify(text: str, content_type: str = "question") -> tuple:
    label, conf, reason = hard_rules(text)
    if label:
        return label, conf, reason
    return kira_classify(text, content_type)


# ── Background Scanner ────────────────────────────────────────────────────────
async def scanner_loop():
    consecutive_empty = 0
    print("🔍 Scanner started!")
    while True:
        try:
            count = await scan_batch()
            if count == 0:
                consecutive_empty += 1
                sleep = min(SCAN_INTERVAL * consecutive_empty, 300)
                await asyncio.sleep(sleep)
            else:
                consecutive_empty = 0
                await asyncio.sleep(SCAN_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"❌ Scanner error: {e}")
            await asyncio.sleep(30)


async def scan_batch() -> int:
    if not supabase:
        return 0
    try:
        qs  = supabase.table("questions")\
                .select("id,title,body,user_id,points_cost")\
                .eq("status", "pending")\
                .limit(BATCH_SIZE).execute()
        ans = supabase.table("answers")\
                .select("id,body,user_id")\
                .eq("moderation_status", "pending")\
                .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs.data or []):
            text = f"{q['title']} {q.get('body', '') or ''}"
            items.append(("question", q, text))
        for a in (ans.data or []):
            items.append(("answer", a, a["body"]))

        if not items:
            return 0

        print(f"🔍 Quét {len(items)} items...")
        loop = asyncio.get_event_loop()
        for itype, data, text in items:
            await loop.run_in_executor(
                None,
                lambda i=itype, d=data, t=text: process_sync(i, d, t)
            )
        return len(items)

    except Exception as e:
        print(f"❌ scan_batch: {e}")
        return 0


def process_sync(itype: str, data: dict, text: str):
    try:
        label, conf, reason = classify(text, itype)
        allowed = label == "CLEAN"
        print(f"  [{itype}] {data['id'][:8]}... → {label} ({conf:.0%}) {reason}")

        if itype == "question":
            if allowed:
                supabase.table("questions")\
                    .update({"status": "open"})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("questions")\
                    .delete().eq("id", data["id"]).execute()
                try:
                    p = supabase.table("profiles")\
                        .select("points")\
                        .eq("id", data["user_id"])\
                        .single().execute()
                    if p.data:
                        new_pts = p.data["points"] + data.get("points_cost", 0)
                        supabase.table("profiles")\
                            .update({"points": new_pts})\
                            .eq("id", data["user_id"]).execute()
                        supabase.table("point_transactions").insert({
                            "user_id": data["user_id"],
                            "amount" : data.get("points_cost", 0),
                            "reason" : "refund_violation",
                            "ref_id" : data["id"],
                        }).execute()
                except Exception as e:
                    print(f"  ⚠️  Hoàn điểm lỗi: {e}")
                log_violation(
                    data["user_id"], data["id"],
                    "question", label, reason, conf
                )

        elif itype == "answer":
            if allowed:
                supabase.table("answers")\
                    .update({"moderation_status": "approved"})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("answers")\
                    .delete().eq("id", data["id"]).execute()
                log_violation(
                    data["user_id"], data["id"],
                    "answer", label, reason, conf
                )

    except Exception as e:
        print(f"  ❌ process error: {e}")


def log_violation(user_id, ref_id, ref_type, label, reason, conf):
    try:
        supabase.table("moderation_logs").insert({
            "user_id"  : user_id,
            "ref_id"   : ref_id,
            "ref_type" : ref_type,
            "label"    : label,
            "reason"   : reason or f"AI {conf:.0%}",
            "action"   : "deleted",
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Log error: {e}")


# ── Schemas ───────────────────────────────────────────────────────────────────
class ModerateRequest(BaseModel):
    text   : str
    context: str = "question"


class ModerateResponse(BaseModel):
    label     : str
    confidence: float
    allowed   : bool
    reason    : str
    scores    : dict = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.post("/moderate", response_model=ModerateResponse)
async def moderate(req: ModerateRequest):
    loop = asyncio.get_event_loop()
    label, conf, reason = await loop.run_in_executor(
        None, lambda: classify(req.text, req.context)
    )
    return ModerateResponse(
        label      = label,
        confidence = conf,
        allowed    = label == "CLEAN",
        reason     = reason,
    )


@app.post("/moderate/batch")
async def moderate_batch(items: list[dict]):
    if not items:
        return {"results": []}
    loop    = asyncio.get_event_loop()
    results = []
    for item in items[:50]:
        text    = item.get("text", "")
        context = item.get("context", "question")
        label, conf, reason = await loop.run_in_executor(
            None, lambda t=text, c=context: classify(t, c)
        )
        results.append({
            "label"     : label,
            "confidence": conf,
            "allowed"   : label == "CLEAN",
            "reason"    : reason,
        })
    return {"results": results, "count": len(results)}


@app.get("/health")
async def health():
    pending_q = pending_a = 0
    if supabase:
        try:
            pq = supabase.table("questions")\
                .select("id", count="exact")\
                .eq("status", "pending").execute()
            pa = supabase.table("answers")\
                .select("id", count="exact")\
                .eq("moderation_status", "pending").execute()
            pending_q = pq.count or 0
            pending_a = pa.count or 0
        except:
            pass
    return {
        "status"      : "ok",
        "kira_ready"  : kira_client is not None,
        "model"       : KIRA_MODEL,
        "scanner"     : "running" if (
                            supabase and scan_task
                            and not scan_task.done()
                        ) else "disabled",
        "pending"     : {
            "questions": pending_q,
            "answers"  : pending_a,
        },
        "version"     : "3.0.0",
    }


@app.get("/stats")
async def stats():
    if not supabase:
        return {"error": "Supabase not configured"}
    try:
        logs = supabase.table("moderation_logs")\
            .select("label,ref_type").execute()
        from collections import Counter
        return {
            "total_violations": len(logs.data or []),
            "by_label"        : dict(Counter(
                r["label"] for r in (logs.data or [])
            )),
            "by_type"         : dict(Counter(
                r["ref_type"] for r in (logs.data or [])
            )),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/")
async def root():
    return {
        "service"  : "HoiBai ML Moderator",
        "version"  : "3.0.0",
        "model"    : KIRA_MODEL,
        "endpoints": {
            "POST /moderate"      : "Kiểm duyệt 1 nội dung",
            "POST /moderate/batch": "Kiểm duyệt nhiều nội dung",
            "GET  /health"        : "Health check",
            "GET  /stats"         : "Thống kê vi phạm",
        }
    }
