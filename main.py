import os, re, unicodedata, asyncio
from contextlib import asynccontextmanager
from openai import OpenAI

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
KIRA_API_KEY   = os.getenv("KIRA_API_KEY",        "")
KIRA_BASE_URL  = os.getenv("KIRA_BASE_URL",        "https://kiraai.vn/api/v1")
KIRA_MODEL     = os.getenv("KIRA_MODEL",           "kira-mini-1.0")
SUPABASE_URL   = os.getenv("SUPABASE_URL",         "")
SUPABASE_KEY   = os.getenv("SUPABASE_SERVICE_KEY", "")
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL",    "15"))
BATCH_SIZE     = int(os.getenv("BATCH_SIZE",       "5"))

LABEL_NAMES = {0:"CLEAN", 1:"SPAM", 2:"TOXIC", 3:"MEANINGLESS"}

kira      = None
supabase  = None
scan_task = None

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global kira, supabase, scan_task

    kira = OpenAI(base_url=KIRA_BASE_URL, api_key=KIRA_API_KEY)
    print(f"✅ KiraAI ready! Model: {KIRA_MODEL}")

    try:
        test = kira.chat.completions.create(
            model    = KIRA_MODEL,
            messages = [{"role":"user","content":"test"}],
            max_tokens = 5,
        )
        print(f"✅ KiraAI test OK: {test.choices[0].message.content}")
    except Exception as e:
        print(f"⚠️  KiraAI test failed: {e}")

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

app = FastAPI(title="HoiBai AI Moderator", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── System Prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Bạn là hệ thống kiểm duyệt nội dung cho web hỏi đáp bài tập học sinh Việt Nam lớp 1-12.

Phân loại nội dung vào 1 trong 4 nhãn:
- CLEAN: Câu hỏi/trả lời bài tập hợp lệ, liên quan đến học tập
- SPAM: Quảng cáo, rao vặt, link ngoài, câu trả lời vô dụng (lên google đi, tự làm đi...)
- TOXIC: Chửi bới, xúc phạm, đe dọa, bắt nạt, ngôn ngữ thù địch, nội dung người lớn, nhạy cảm về giới tính, tình dục
- MEANINGLESS: Vô nghĩa, ký tự ngẫu nhiên, hoặc KHÔNG LIÊN QUAN học tập (hỏi về game, idol, chuyện cá nhân...)

Ví dụ TOXIC: "Làm thế nào có những LGBT", nội dung 18+, chửi bới
Ví dụ MEANINGLESS: "ai chơi liên quân không", "idol em là ai", "hôm nay ăn gì"
Ví dụ CLEAN: bài toán, bài văn, câu hỏi lý hóa sinh sử địa anh văn...

Trả lời CHỈ bằng JSON:
{"label": "CLEAN|SPAM|TOXIC|MEANINGLESS", "confidence": 0.0-1.0, "reason": "lý do ngắn gọn"}"""

# ── Helpers ───────────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    if not text: return ""
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r'https?://\S+', '[URL]', text)
    text = re.sub(r'\b0\d{9,10}\b', '[PHONE]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:500]

def hard_rules(text: str) -> tuple:
    t = text.strip()
    if len(t) < 2:               return "MEANINGLESS", "Quá ngắn"
    if re.match(r'^(.)\1+$', t): return "MEANINGLESS", "Ký tự lặp"
    if re.match(r'^\d+$', t):    return "MEANINGLESS", "Toàn số"
    if not re.search(
        r'[a-zA-Zàáảãạăắặẳẵậâấầẩẫèéẻẽẹêếềểễệ'
        r'ìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]',
        t, re.IGNORECASE
    ):
        return "MEANINGLESS", "Không có chữ cái"
    return None, ""

def ai_classify(text: str, content_type: str = "question") -> tuple:
    if not kira:
        return "CLEAN", 0.5, "KiraAI chưa sẵn sàng"

    cleaned = clean_text(text)
    if not cleaned:
        return "MEANINGLESS", 1.0, "Text rỗng"

    user_prompt = f"Loại nội dung: {content_type}\nNội dung: {cleaned}"

    try:
        response = kira.chat.completions.create(
            model       = KIRA_MODEL,
            messages    = [
                {"role":"system","content":SYSTEM_PROMPT},
                {"role":"user",  "content":user_prompt},
            ],
            max_tokens  = 300,
            temperature = 0.1,
        )

        raw          = response.choices[0].message.content.strip()
        finish_reason= response.choices[0].finish_reason

        import json
        data  = None
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try: data = json.loads(match.group())
            except: data = None

        if data is None:
            label_m  = re.search(r'"label"\s*:\s*"([^"]+)"', raw)
            conf_m   = re.search(r'"confidence"\s*:\s*([0-9.]+)', raw)
            reason_m = re.search(r'"reason"\s*:\s*"([^"]*)"', raw)
            if label_m:
                data = {
                    "label"     : label_m.group(1),
                    "confidence": float(conf_m.group(1)) if conf_m else 0.7,
                    "reason"    : reason_m.group(1) if reason_m else "(truncated)",
                }

        if data is not None:
            label      = str(data.get("label","CLEAN")).upper()
            confidence = float(data.get("confidence", 0.8))
            reason     = data.get("reason","") or ""
            if label not in ("CLEAN","SPAM","TOXIC","MEANINGLESS"):
                label = "CLEAN"
            return label, confidence, reason
        else:
            print(f"⚠️  Parse failed (finish={finish_reason}): {raw!r}")
            return "CLEAN", 0.5, "Parse error → fallback"

    except Exception as e:
        print(f"❌ KiraAI error: {e}")
        return "CLEAN", 0.5, "API error → fallback"

def classify(text: str, content_type: str = "question") -> tuple:
    label, reason = hard_rules(text)
    if label: return label, 1.0, reason
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
        # Câu hỏi mới pending
        qs_pending = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        # Câu hỏi cũ chưa scan (removed_by_ai là null)
        qs_rescan = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","open")\
            .is_("removed_by_ai","null")\
            .limit(BATCH_SIZE).execute()

        # Answers pending
        ans = supabase.table("answers")\
            .select("id,body,user_id")\
            .eq("moderation_status","pending")\
            .limit(BATCH_SIZE).execute()

        # Reports cần xử lý
        reports = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs_pending.data or []):
            items.append(("question_pending", q,
                f"{q['title']} {q.get('body','') or ''}"))
        for q in (qs_rescan.data or []):
            items.append(("question_rescan", q,
                f"{q['title']} {q.get('body','') or ''}"))
        for a in (ans.data or []):
            items.append(("answer", a, a["body"]))
        for rep in (reports.data or []):
            items.append(("report", rep, ""))

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
        # Xử lý reports riêng
        if itype == "report":
            _handle_report(data)
            return

        label, conf, reason = classify(text,
            "question" if "question" in itype else "answer")
        allowed = label == "CLEAN"
        print(f"  [{itype}] {data['id'][:8]}... → {label} ({conf:.0%}) {reason}")

        if "question" in itype:
            if allowed:
                update_data = {"removed_by_ai": False}
                if itype == "question_pending":
                    update_data["status"] = "open"
                supabase.table("questions")\
                    .update(update_data)\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("questions").update({
                    "status"         : "removed",
                    "removed_by_ai"  : True,
                    "removed_reason" : reason or label,
                    "removed_content": text[:1000],
                }).eq("id", data["id"]).execute()

                if itype == "question_pending":
                    _refund_points(data)

                log_violation(data["user_id"], data["id"],
                              "question", label, reason, conf)
                print(f"  🚫 Removed question {data['id'][:8]} → {label}")

        elif itype == "answer":
            if allowed:
                supabase.table("answers").update({
                    "moderation_status": "approved",
                    "removed_by_ai"    : False,
                }).eq("id", data["id"]).execute()
            else:
                supabase.table("answers").update({
                    "moderation_status": "removed",
                    "removed_by_ai"    : True,
                    "removed_reason"   : reason or label,
                    "removed_content"  : text[:1000],
                }).eq("id", data["id"]).execute()
                log_violation(data["user_id"], data["id"],
                              "answer", label, reason, conf)
                print(f"  🚫 Removed answer {data['id'][:8]} → {label}")

    except Exception as e:
        print(f"  ❌ process error: {e}")

def _refund_points(q: dict):
    try:
        p = supabase.table("profiles")\
            .select("points").eq("id", q["user_id"])\
            .single().execute()
        if p.data:
            supabase.table("profiles")\
                .update({"points": p.data["points"] + q.get("points_cost",0)})\
                .eq("id", q["user_id"]).execute()
            supabase.table("point_transactions").insert({
                "user_id": q["user_id"],
                "amount" : q.get("points_cost", 0),
                "reason" : "refund_violation",
                "ref_id" : q["id"],
            }).execute()
    except Exception as e:
        print(f"  ⚠️  Refund error: {e}")

def _handle_report(report: dict):
    """Xử lý báo cáo từ user — scan lại nội dung bị báo cáo"""
    try:
        ref_id   = report["ref_id"]
        ref_type = report["ref_type"]

        if ref_type == "question":
            r = supabase.table("questions")\
                .select("id,title,body,user_id,points_cost")\
                .eq("id", ref_id).single().execute()
            if r.data:
                text  = f"{r.data['title']} {r.data.get('body','') or ''}"
                label, conf, reason = classify(text, "question")
                if label != "CLEAN":
                    supabase.table("questions").update({
                        "status"         : "removed",
                        "removed_by_ai"  : True,
                        "removed_reason" : f"Report: {reason or label}",
                        "removed_content": text[:1000],
                    }).eq("id", ref_id).execute()
                    _refund_points(r.data)
                    log_violation(r.data["user_id"], ref_id,
                                  "question", label, reason, conf)
                    print(f"  🚩 Report → removed question {ref_id[:8]}")

        elif ref_type == "answer":
            r = supabase.table("answers")\
                .select("id,body,user_id")\
                .eq("id", ref_id).single().execute()
            if r.data:
                label, conf, reason = classify(r.data["body"], "answer")
                if label != "CLEAN":
                    supabase.table("answers").update({
                        "moderation_status": "removed",
                        "removed_by_ai"    : True,
                        "removed_reason"   : f"Report: {reason or label}",
                        "removed_content"  : r.data["body"][:1000],
                    }).eq("id", ref_id).execute()
                    log_violation(r.data["user_id"], ref_id,
                                  "answer", label, reason, conf)
                    print(f"  🚩 Report → removed answer {ref_id[:8]}")

        # Đánh dấu report đã xử lý
        supabase.table("reports")\
            .update({"status": "resolved"})\
            .eq("id", report["id"]).execute()

    except Exception as e:
        print(f"  ⚠️  Handle report error: {e}")

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
        label=label, confidence=conf,
        allowed=(label=="CLEAN"), reason=reason,
    )

@app.post("/moderate/batch")
async def moderate_batch(items: list[dict]):
    if not items: return {"results": []}
    loop    = asyncio.get_event_loop()
    results = []
    for item in items[:20]:
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
    pending_q = pending_a = pending_r = 0
    if supabase:
        try:
            pq = supabase.table("questions")\
                .select("id", count="exact")\
                .eq("status","pending").execute()
            pa = supabase.table("answers")\
                .select("id", count="exact")\
                .eq("moderation_status","pending").execute()
            pr = supabase.table("reports")\
                .select("id", count="exact")\
                .eq("status","pending").execute()
            pending_q = pq.count or 0
            pending_a = pa.count or 0
            pending_r = pr.count or 0
        except: pass
    return {
        "status"   : "ok",
        "ai_ready" : kira is not None,
        "model"    : KIRA_MODEL,
        "scanner"  : "running" if (supabase and scan_task
                      and not scan_task.done()) else "disabled",
        "pending"  : {
            "questions": pending_q,
            "answers"  : pending_a,
            "reports"  : pending_r,
        },
        "version"  : "3.0.0",
    }

@app.get("/stats")
async def stats():
    if not supabase:
        return {"error": "Supabase not configured"}
    try:
        logs = supabase.table("moderation_logs")\
            .select("label,ref_type").execute()
        rpts = supabase.table("reports")\
            .select("status,reason").execute()
        from collections import Counter
        return {
            "total_violations": len(logs.data or []),
            "by_label"        : dict(Counter(
                r["label"] for r in (logs.data or []))),
            "by_type"         : dict(Counter(
                r["ref_type"] for r in (logs.data or []))),
            "reports"         : {
                "total"   : len(rpts.data or []),
                "by_status": dict(Counter(
                    r["status"] for r in (rpts.data or []))),
                "by_reason": dict(Counter(
                    r["reason"] for r in (rpts.data or []))),
            },
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
