import os, re, unicodedata, asyncio
from contextlib import asynccontextmanager
from openai import OpenAI

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
KIRA_API_KEY   = os.getenv("KIRA_API_KEY",       "kira_e564cf7a91b3650799537c8bdabaed07")
KIRA_BASE_URL  = os.getenv("KIRA_BASE_URL",       "https://kiraai.vn/api/v1")
KIRA_MODEL     = os.getenv("KIRA_MODEL",          "kira-mini-1.0")
SUPABASE_URL   = os.getenv("SUPABASE_URL",        "")
SUPABASE_KEY   = os.getenv("SUPABASE_SERVICE_KEY","")
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL",  "15"))
BATCH_SIZE     = int(os.getenv("BATCH_SIZE",      "5"))

# ── Globals ───────────────────────────────────────────────────────────────────
kira     = None
supabase = None
scan_task= None

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global kira, supabase, scan_task

    # Khởi tạo KiraAI client
    kira = OpenAI(base_url=KIRA_BASE_URL, api_key=KIRA_API_KEY)
    print(f"✅ KiraAI client ready! Model: {KIRA_MODEL}")

    # Test kết nối
    try:
        test = kira.chat.completions.create(
            model  = KIRA_MODEL,
            messages=[{"role":"user","content":"test"}],
            max_tokens=5,
        )
        print(f"✅ KiraAI test OK: {test.choices[0].message.content}")
    except Exception as e:
        print(f"⚠️  KiraAI test failed: {e}")

    # Kết nối Supabase
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
        try: await scan_task
        except asyncio.CancelledError: pass
    print("👋 Shutdown!")

app = FastAPI(title="HoiBai ML Moderator", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Helpers ───────────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    if not text: return ""
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r'https?://\S+', '[URL]', text)
    text = re.sub(r'\b0\d{9,10}\b', '[PHONE]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:500]  # Giới hạn 500 ký tự

def hard_rules(text: str) -> tuple:
    """Rule cứng không cần AI"""
    t = text.strip()
    if len(t) < 2:
        return "MEANINGLESS", "Quá ngắn"
    if re.match(r'^(.)\1+$', t):
        return "MEANINGLESS", "Ký tự lặp"
    if re.match(r'^\d+$', t):
        return "MEANINGLESS", "Toàn số"
    if not re.search(
        r'[a-zA-Zàáảãạăắặẳẵậâấầẩẫèéẻẽẹêếềểễệ'
        r'ìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]',
        t, re.IGNORECASE
    ):
        return "MEANINGLESS", "Không có chữ cái"
    return None, ""

SYSTEM_PROMPT = """Bạn là hệ thống kiểm duyệt nội dung cho web hỏi đáp bài tập học sinh Việt Nam lớp 1-12.

Phân loại nội dung vào 1 trong 4 nhãn:
- CLEAN: Câu hỏi/trả lời bài tập hợp lệ, bình thường
- SPAM: Quảng cáo, rao vặt, link ngoài, nội dung không liên quan học tập, câu trả lời vô dụng (lên google tìm đi, tự làm đi...)
- TOXIC: Chửi bới, xúc phạm, đe dọa, bắt nạt, ngôn ngữ thù địch
- MEANINGLESS: Vô nghĩa, ký tự ngẫu nhiên, không có nội dung rõ ràng

Trả lời CHỈ bằng JSON format:
{"label": "CLEAN|SPAM|TOXIC|MEANINGLESS", "confidence": 0.0-1.0, "reason": "lý do ngắn gọn"}

Không giải thích thêm gì ngoài JSON."""

def ai_classify(text: str, content_type: str = "question") -> tuple:
    """Phân loại bằng KiraAI"""
    if not kira:
        return "CLEAN", 0.5, "KiraAI chưa sẵn sàng"

    cleaned = clean_text(text)
    if not cleaned:
        return "MEANINGLESS", 1.0, "Text rỗng"

    user_prompt = f"Loại nội dung: {content_type}\nNội dung: {cleaned}"

    try:
        response = kira.chat.completions.create(
            model    = KIRA_MODEL,
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens  = 100,
            temperature = 0.1,  # Thấp để kết quả ổn định
        )

        raw = response.choices[0].message.content.strip()

        # Parse JSON
        import json
        # Tìm JSON trong response
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            data       = json.loads(match.group())
            label      = data.get("label", "CLEAN").upper()
            confidence = float(data.get("confidence", 0.8))
            reason     = data.get("reason", "")

            # Validate label
            if label not in ("CLEAN","SPAM","TOXIC","MEANINGLESS"):
                label = "CLEAN"

            return label, confidence, reason
        else:
            print(f"⚠️  KiraAI response không parse được: {raw}")
            return "CLEAN", 0.5, "Parse error → fallback"

    except Exception as e:
        print(f"❌ KiraAI error: {e}")
        return "CLEAN", 0.5, f"API error → fallback"

def classify(text: str, content_type: str = "question") -> tuple:
    """Full pipeline: hard rules → KiraAI"""
    label, reason = hard_rules(text)
    if label:
        return label, 1.0, reason
    return ai_classify(text, content_type)

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
    if not supabase: return 0
    try:
        qs  = supabase.table("questions")\
                .select("id,title,body,user_id,points_cost")\
                .eq("status","pending")\
                .limit(BATCH_SIZE).execute()
        ans = supabase.table("answers")\
                .select("id,body,user_id")\
                .eq("moderation_status","pending")\
                .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs.data or []):
            text = f"{q['title']} {q.get('body','') or ''}"
            items.append(("question", q, text))
        for a in (ans.data or []):
            items.append(("answer", a, a["body"]))

        if not items: return 0

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
                    .update({"status":"open"})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("questions")\
                    .delete().eq("id", data["id"]).execute()
                # Hoàn điểm
                try:
                    p = supabase.table("profiles")\
                        .select("points").eq("id", data["user_id"])\
                        .single().execute()
                    if p.data:
                        supabase.table("profiles")\
                            .update({"points": p.data["points"] + data.get("points_cost",0)})\
                            .eq("id", data["user_id"]).execute()
                        supabase.table("point_transactions").insert({
                            "user_id": data["user_id"],
                            "amount" : data.get("points_cost", 0),
                            "reason" : "refund_violation",
                            "ref_id" : data["id"],
                        }).execute()
                except Exception as e:
                    print(f"  ⚠️  Hoàn điểm lỗi: {e}")
                log_violation(data["user_id"], data["id"], "question", label, reason, conf)

        elif itype == "answer":
            if allowed:
                supabase.table("answers")\
                    .update({"moderation_status":"approved"})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("answers")\
                    .delete().eq("id", data["id"]).execute()
                log_violation(data["user_id"], data["id"], "answer", label, reason, conf)

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
    if not kira:
        return ModerateResponse(
            label="CLEAN", confidence=0.5,
            allowed=True, reason="KiraAI chưa sẵn sàng"
        )
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
    if not items: return {"results": []}
    loop    = asyncio.get_event_loop()
    results = []
    for item in items[:20]:  # Giới hạn 20/batch
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
                .eq("status","pending").execute()
            pa = supabase.table("answers")\
                .select("id", count="exact")\
                .eq("moderation_status","pending").execute()
            pending_q = pq.count or 0
            pending_a = pa.count or 0
        except: pass
    return {
        "status"      : "ok",
        "ai_ready"    : kira is not None,
        "model"       : KIRA_MODEL,
        "scanner"     : "running" if (supabase and scan_task
                         and not scan_task.done()) else "disabled",
        "pending"     : {"questions": pending_q, "answers": pending_a},
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
            "by_label"        : dict(Counter(r["label"]    for r in (logs.data or []))),
            "by_type"         : dict(Counter(r["ref_type"] for r in (logs.data or []))),
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {
        "service"  : "HoiBai AI Moderator",
        "version"  : "3.0.0",
        "model"    : KIRA_MODEL,
        "endpoints": {
            "POST /moderate"      : "Kiểm duyệt 1 nội dung",
            "POST /moderate/batch": "Kiểm duyệt nhiều nội dung",
            "GET  /health"        : "Health check",
            "GET  /stats"         : "Thống kê vi phạm",
        }
    }
