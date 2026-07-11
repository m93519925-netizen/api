import os, re, unicodedata, asyncio, json
from contextlib import asynccontextmanager
from typing import Optional

import torch
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_PATH      = os.getenv("MODEL_PATH",           "./model")
SUPABASE_URL    = os.getenv("SUPABASE_URL",          "")
SUPABASE_KEY    = os.getenv("SUPABASE_SERVICE_KEY",  "")
CONFIDENCE_THR  = float(os.getenv("CONFIDENCE_THR", "0.65"))
SCAN_INTERVAL   = int(os.getenv("SCAN_INTERVAL",    "10"))    # giây
BATCH_SIZE      = int(os.getenv("BATCH_SIZE",       "10"))
MAX_LENGTH      = 128

LABEL_NAMES = {0: "CLEAN", 1: "SPAM", 2: "TOXIC", 3: "MEANINGLESS"}

# ── Globals ───────────────────────────────────────────────────────────────────
tokenizer  = None
model      = None
device     = None
supabase   = None
scan_task  = None

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global tokenizer, model, device, supabase, scan_task

    # Load model
    print(f"⏳ Loading model từ {MODEL_PATH}...")
    device    = torch.device("cpu")  # Northflank free = CPU
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model     = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    model     = model.to(device)
    model.eval()

    total = sum(p.numel() for p in model.parameters())
    print(f"✅ Model loaded! {total/1e6:.1f}M params | Device: {device}")

    # Kết nối Supabase nếu có
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            from supabase import create_client
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            print("✅ Supabase connected!")

            # Bắt đầu background scanner
            scan_task = asyncio.create_task(scanner_loop())
            print("🔄 Background scanner started!")
        except Exception as e:
            print(f"⚠️  Supabase error: {e} → Scanner disabled")
    else:
        print("ℹ️  Supabase chưa cấu hình → Scanner disabled")

    yield

    # Cleanup
    if scan_task:
        scan_task.cancel()
        try:
            await scan_task
        except asyncio.CancelledError:
            pass
    print("👋 Shutdown complete!")

app = FastAPI(
    title       = "HoiBai ML Moderator",
    description = "Content moderation API cho HoiBai K1-12",
    version     = "2.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["POST", "GET"],
    allow_headers  = ["*"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    """Làm sạch text theo cách notebook đã train"""
    if not text: return ""
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '[URL]', text)
    text = re.sub(r'\b0\d{9,10}\b', '[PHONE]', text)
    text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()

def hard_rules(text: str) -> tuple[Optional[str], str]:
    """Rule cứng không cần model"""
    t = text.strip()
    if len(t) < 2:
        return "MEANINGLESS", "Quá ngắn"
    if re.match(r'^(.)\1+$', t):
        return "MEANINGLESS", "Ký tự lặp"
    if re.match(r'^\d+$', t):
        return "MEANINGLESS", "Toàn số"
    if not re.search(
        r'[a-zA-Z'
        r'àáảãạăắặẳẵậâấầẩẫèéẻẽẹêếềểễệ'
        r'ìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụ'
        r'ưứừửữựỳýỷỹỵđ]', t, re.IGNORECASE
    ):
        return "MEANINGLESS", "Không có chữ cái"
    return None, ""

def ml_classify(text: str, content_type: str = "question") -> tuple[str, float, str]:
    """Classify bằng PhoBERT — match đúng format notebook đã train"""
    # Thêm prefix [QUESTION] hoặc [ANSWER] như notebook
    prefix  = f"[{content_type.upper()}]"
    cleaned = clean_text(text)
    if not cleaned:
        return "MEANINGLESS", 1.0, "Text rỗng sau clean"

    combined = f"{prefix} {cleaned}"

    inputs = tokenizer(
        combined,
        return_tensors  = "pt",
        padding         = "max_length",
        truncation      = True,
        max_length      = MAX_LENGTH,
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs   = torch.softmax(outputs.logits, dim=-1)
        pred    = torch.argmax(probs, dim=-1).item()
        conf    = probs[0][pred].item()

    label = LABEL_NAMES[pred]

    # Nếu không chắc thì cho qua
    if label != "CLEAN" and conf < CONFIDENCE_THR:
        return "CLEAN", conf, f"Dưới ngưỡng {CONFIDENCE_THR:.0%}"

    return label, round(conf, 4), ""

def classify(text: str, content_type: str = "question") -> tuple[str, float, str]:
    """Full pipeline: hard rules → ML"""
    label, reason = hard_rules(text)
    if label:
        return label, 1.0, reason
    return ml_classify(text, content_type)

# ── Background Scanner ─────────────────────────────────────────────────────────
async def scanner_loop():
    """Quét liên tục nội dung pending trong Supabase"""
    consecutive_empty = 0
    print("🔍 Scanner loop started!")

    while True:
        try:
            count = await scan_batch()

            if count == 0:
                consecutive_empty += 1
                # Ngủ lâu hơn nếu không có gì
                sleep_time = min(SCAN_INTERVAL * consecutive_empty, 300)
                await asyncio.sleep(sleep_time)
            else:
                consecutive_empty = 0
                await asyncio.sleep(SCAN_INTERVAL)

        except asyncio.CancelledError:
            print("🛑 Scanner stopped!")
            break
        except Exception as e:
            print(f"❌ Scanner error: {e}")
            await asyncio.sleep(30)

async def scan_batch() -> int:
    """Quét 1 batch pending items"""
    if not supabase:
        return 0

    try:
        # Lấy pending questions
        qs = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status", "pending")\
            .limit(BATCH_SIZE)\
            .execute()

        # Lấy pending answers
        ans = supabase.table("answers")\
            .select("id,body,user_id")\
            .eq("moderation_status", "pending")\
            .limit(BATCH_SIZE)\
            .execute()

        items = []
        for q in (qs.data or []):
            text = f"{q['title']} {q.get('body','') or ''}"
            items.append(("question", q, text))
        for a in (ans.data or []):
            items.append(("answer", a, a["body"]))

        if not items:
            return 0

        print(f"🔍 Quét {len(items)} items...")

        for itype, data, text in items:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: process_item_sync(itype, data, text)
            )

        return len(items)

    except Exception as e:
        print(f"❌ scan_batch error: {e}")
        return 0

def process_item_sync(itype: str, data: dict, text: str):
    """Xử lý 1 item (sync vì ML là CPU-bound)"""
    try:
        label, conf, reason = classify(text, itype)
        allowed = label == "CLEAN"

        print(f"  [{itype}] {data['id'][:8]}... → {label} ({conf:.0%}){' | '+reason if reason else ''}")

        if itype == "question":
            _handle_question(data, label, allowed, reason, conf)
        elif itype == "answer":
            _handle_answer(data, label, allowed, reason, conf)

    except Exception as e:
        print(f"  ❌ process error {data.get('id','?')}: {e}")

def _handle_question(q: dict, label: str, allowed: bool, reason: str, conf: float):
    if allowed:
        supabase.table("questions")\
            .update({"status": "open"})\
            .eq("id", q["id"]).execute()
    else:
        # Xóa câu hỏi
        supabase.table("questions")\
            .delete().eq("id", q["id"]).execute()

        # Hoàn điểm
        try:
            profile = supabase.table("profiles")\
                .select("points").eq("id", q["user_id"])\
                .single().execute()
            if profile.data:
                new_pts = profile.data["points"] + q.get("points_cost", 0)
                supabase.table("profiles")\
                    .update({"points": new_pts})\
                    .eq("id", q["user_id"]).execute()
                supabase.table("point_transactions").insert({
                    "user_id": q["user_id"],
                    "amount" : q.get("points_cost", 0),
                    "reason" : "refund_violation",
                    "ref_id" : q["id"],
                }).execute()
        except Exception as e:
            print(f"  ⚠️  Hoàn điểm lỗi: {e}")

        # Ghi log
        _log_violation(q["user_id"], q["id"], "question", label, reason, conf)
        print(f"  🚫 Deleted question {q['id'][:8]} → {label}")

def _handle_answer(a: dict, label: str, allowed: bool, reason: str, conf: float):
    if allowed:
        supabase.table("answers")\
            .update({"moderation_status": "approved"})\
            .eq("id", a["id"]).execute()
    else:
        supabase.table("answers")\
            .delete().eq("id", a["id"]).execute()
        _log_violation(a["user_id"], a["id"], "answer", label, reason, conf)
        print(f"  🚫 Deleted answer {a['id'][:8]} → {label}")

def _log_violation(user_id, ref_id, ref_type, label, reason, conf):
    try:
        supabase.table("moderation_logs").insert({
            "user_id"   : user_id,
            "ref_id"    : ref_id,
            "ref_type"  : ref_type,
            "label"     : label,
            "reason"    : reason or f"ML {conf:.0%}",
            "action"    : "deleted",
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Log error: {e}")

# ── Schemas ───────────────────────────────────────────────────────────────────
class ModerateRequest(BaseModel):
    text   : str
    context: str = "question"  # "question" | "answer"

class ModerateResponse(BaseModel):
    label     : str
    confidence: float
    allowed   : bool
    reason    : str
    scores    : dict = {}

class BatchRequest(BaseModel):
    items: list[dict]  # [{"text": "...", "context": "question"}]

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.post("/moderate", response_model=ModerateResponse)
async def moderate(req: ModerateRequest):
    """Kiểm duyệt 1 nội dung — dùng trong PHP ask.php / question.php"""
    if model is None:
        # Fallback: cho phép nếu model chưa load
        return ModerateResponse(
            label="CLEAN", confidence=0.5,
            allowed=True, reason="Model loading..."
        )

    loop  = asyncio.get_event_loop()
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
async def moderate_batch(req: BatchRequest):
    """Kiểm duyệt nhiều nội dung cùng lúc"""
    if not req.items:
        return {"results": []}

    if model is None:
        return {"results": [
            {"label":"CLEAN","confidence":0.5,"allowed":True,"reason":"Model loading"}
            for _ in req.items
        ]}

    loop    = asyncio.get_event_loop()
    results = []

    for item in req.items[:50]:  # Giới hạn 50 items/batch
        text    = item.get("text", "")
        context = item.get("context", "question")
        label, conf, reason = await loop.run_in_executor(
            None, lambda: classify(text, context)
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
    """Health check — Northflank dùng để monitor"""
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
        "model_loaded": model is not None,
        "device"      : str(device) if device else "unknown",
        "scanner"     : "running" if (supabase and scan_task and not scan_task.done()) else "disabled",
        "pending"     : {
            "questions": pending_q,
            "answers"  : pending_a,
        },
        "version"     : "2.0.0",
    }

@app.get("/stats")
async def stats():
    """Thống kê moderation"""
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        logs = supabase.table("moderation_logs")\
            .select("label, ref_type")\
            .execute()

        from collections import Counter
        label_counts = Counter(r["label"]    for r in (logs.data or []))
        type_counts  = Counter(r["ref_type"] for r in (logs.data or []))

        return {
            "total_violations": len(logs.data or []),
            "by_label"        : dict(label_counts),
            "by_type"         : dict(type_counts),
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {
        "service": "HoiBai ML Moderator",
        "version": "2.0.0",
        "endpoints": {
            "POST /moderate"       : "Kiểm duyệt 1 nội dung",
            "POST /moderate/batch" : "Kiểm duyệt nhiều nội dung",
            "GET  /health"         : "Health check",
            "GET  /stats"          : "Thống kê vi phạm",
        }
    }
