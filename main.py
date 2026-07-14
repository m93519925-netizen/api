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
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL",    "30"))
BATCH_SIZE     = int(os.getenv("BATCH_SIZE",       "5"))

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
        print("ℹ️  Supabase chưa cấu hình")

    yield

    if scan_task:
        scan_task.cancel()
        try: await scan_task
        except asyncio.CancelledError: pass
    print("👋 Shutdown!")

app = FastAPI(title="HoiBai AI Moderator", version="4.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── System Prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Bạn là hệ thống kiểm duyệt nội dung cho web hỏi đáp bài tập học sinh Việt Nam lớp 1-12.

Phân loại nội dung vào 1 trong 4 nhãn:
- CLEAN: Câu hỏi/trả lời bài tập hợp lệ, liên quan đến học tập
- SPAM: Quảng cáo, rao vặt, link ngoài, câu trả lời vô dụng
- TOXIC: Chửi bới, xúc phạm, đe dọa, nội dung người lớn, nhạy cảm về giới tính/tình dục
- MEANINGLESS: Vô nghĩa, ký tự ngẫu nhiên, không liên quan học tập (game, idol, chuyện cá nhân...)

Ví dụ TOXIC: nội dung LGBT không liên quan học tập, 18+, chửi bới
Ví dụ MEANINGLESS: "ai chơi liên quân không", "idol em là ai", "anh em thấy tôi đẹp không"
Ví dụ CLEAN: bài toán, bài văn, câu hỏi lý hóa sinh sử địa anh văn...

Trả lời CHỈ bằng JSON:
{"label": "CLEAN|SPAM|TOXIC|MEANINGLESS", "confidence": 0.0-1.0, "reason": "lý do ngắn gọn bằng tiếng Việt"}"""

APPEAL_PROMPT = """Bạn là hệ thống xét duyệt kháng cáo cho web hỏi đáp bài tập học sinh Việt Nam.

Một nội dung đã bị AI xóa. Người dùng đã gửi kháng cáo giải thích tại sao nội dung của họ không vi phạm.

Hãy xem xét:
1. Nội dung gốc có thực sự vi phạm không?
2. Lý do kháng cáo có hợp lý không?
3. AI có nhận dạng sai không?

Trả lời CHỈ bằng JSON:
{"decision": "approved|rejected", "confidence": 0.0-1.0, "reason": "lý do quyết định bằng tiếng Việt"}"""

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
    try:
        response = kira.chat.completions.create(
            model       = KIRA_MODEL,
            messages    = [
                {"role":"system","content":SYSTEM_PROMPT},
                {"role":"user",  "content":f"Loại: {content_type}\nNội dung: {cleaned}"},
            ],
            max_tokens  = 300,
            temperature = 0.1,
        )
        raw = response.choices[0].message.content.strip()
        import json
        data  = None
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try: data = json.loads(match.group())
            except: pass
        if data is None:
            lm = re.search(r'"label"\s*:\s*"([^"]+)"', raw)
            cm = re.search(r'"confidence"\s*:\s*([0-9.]+)', raw)
            rm = re.search(r'"reason"\s*:\s*"([^"]*)"', raw)
            if lm:
                data = {
                    "label"     : lm.group(1),
                    "confidence": float(cm.group(1)) if cm else 0.7,
                    "reason"    : rm.group(1) if rm else "",
                }
        if data:
            label = str(data.get("label","CLEAN")).upper()
            conf  = float(data.get("confidence", 0.8))
            reason= data.get("reason","") or ""
            if label not in ("CLEAN","SPAM","TOXIC","MEANINGLESS"):
                label = "CLEAN"
            return label, conf, reason
        return "CLEAN", 0.5, "Parse error"
    except Exception as e:
        print(f"❌ KiraAI error: {e}")
        return "CLEAN", 0.5, "API error"

def ai_review_appeal(original_content: str, removed_reason: str,
                     appeal_content: str, content_type: str) -> tuple:
    """AI xét duyệt kháng cáo"""
    if not kira:
        return "approved", 0.5, "KiraAI chưa sẵn sàng"
    try:
        user_msg = f"""Loại nội dung: {content_type}
Nội dung gốc bị xóa: {original_content[:300]}
Lý do AI xóa: {removed_reason}
Lý do kháng cáo của người dùng: {appeal_content[:300]}"""

        response = kira.chat.completions.create(
            model       = KIRA_MODEL,
            messages    = [
                {"role":"system","content":APPEAL_PROMPT},
                {"role":"user",  "content":user_msg},
            ],
            max_tokens  = 300,
            temperature = 0.1,
        )
        raw = response.choices[0].message.content.strip()
        import json
        data  = None
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try: data = json.loads(match.group())
            except: pass
        if data:
            decision = str(data.get("decision","rejected")).lower()
            conf     = float(data.get("confidence", 0.7))
            reason   = data.get("reason","") or ""
            if decision not in ("approved","rejected"):
                decision = "rejected"
            return decision, conf, reason
        return "rejected", 0.5, "Parse error"
    except Exception as e:
        print(f"❌ Appeal review error: {e}")
        return "rejected", 0.5, "API error"

def classify(text: str, content_type: str = "question") -> tuple:
    label, reason = hard_rules(text)
    if label: return label, 1.0, reason
    return ai_classify(text, content_type)

# ── Notifications ─────────────────────────────────────────────────────────────
def send_notification(user_id: str, ntype: str, title: str,
                      message: str, ref_id: str = None,
                      ref_type: str = None, appeal_id: str = None):
    try:
        supabase.table("notifications").insert({
            "user_id"  : user_id,
            "type"     : ntype,
            "title"    : title,
            "message"  : message,
            "ref_id"   : ref_id,
            "ref_type" : ref_type,
            "appeal_id": appeal_id,
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Notification error: {e}")

# ── Background Scanner ────────────────────────────────────────────────────────
async def scanner_loop():
    print("🔍 Scanner started! Interval: 30s")
    while True:
        try:
            await scan_batch()
            await asyncio.sleep(SCAN_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"❌ Scanner error: {e}")
            await asyncio.sleep(30)

async def scan_batch():
    if not supabase: return

    try:
        # 1. Câu hỏi pending
        qs_pending = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        # 2. Câu hỏi open chưa scan (removed_by_ai là null)
        qs_rescan = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","open")\
            .is_("removed_by_ai","null")\
            .limit(BATCH_SIZE).execute()

        # 3. Answers pending
        ans_pending = supabase.table("answers")\
            .select("id,body,user_id,question_id")\
            .eq("moderation_status","pending")\
            .limit(BATCH_SIZE).execute()

        # 4. Answers chưa scan
        ans_rescan = supabase.table("answers")\
            .select("id,body,user_id,question_id")\
            .eq("moderation_status","approved")\
            .is_("removed_by_ai","null")\
            .limit(BATCH_SIZE).execute()

        # 5. Kháng cáo pending
        appeals = supabase.table("appeals")\
            .select("id,user_id,ref_id,ref_type,content")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        # 6. Reports pending
        reports = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs_pending.data  or []): items.append(("q_pending", q))
        for q in (qs_rescan.data   or []): items.append(("q_rescan",  q))
        for a in (ans_pending.data or []): items.append(("a_pending", a))
        for a in (ans_rescan.data  or []): items.append(("a_rescan",  a))
        for ap in (appeals.data    or []): items.append(("appeal",    ap))
        for r  in (reports.data    or []): items.append(("report",    r))

        if items:
            print(f"🔍 Quét {len(items)} items...")
            loop = asyncio.get_event_loop()
            for itype, data in items:
                await loop.run_in_executor(
                    None,
                    lambda i=itype, d=data: process_item(i, d)
                )

    except Exception as e:
        print(f"❌ scan_batch: {e}")

def process_item(itype: str, data: dict):
    try:
        if itype == "appeal":
            _handle_appeal(data)
            return
        if itype == "report":
            _handle_report(data)
            return

        # Classify content
        if "q_" in itype:
            text = f"{data['title']} {data.get('body','') or ''}"
            ctype = "question"
        else:
            text  = data["body"]
            ctype = "answer"

        label, conf, reason = classify(text, ctype)
        allowed = label == "CLEAN"

        print(f"  [{itype}] {data['id'][:8]}... → {label} ({conf:.0%}) {reason}")

        if "q_" in itype:
            _handle_question_result(data, itype, label, allowed, reason, conf)
        else:
            _handle_answer_result(data, itype, label, allowed, reason, conf)

    except Exception as e:
        print(f"  ❌ process error [{itype}]: {e}")

def _handle_question_result(q, itype, label, allowed, reason, conf):
    if allowed:
        update = {"removed_by_ai": False}
        if itype == "q_pending":
            update["status"] = "open"
        supabase.table("questions")\
            .update(update).eq("id", q["id"]).execute()
    else:
        # Lưu nội dung + đánh dấu removed
        text = f"{q['title']} {q.get('body','') or ''}"
        supabase.table("questions").update({
            "status"         : "removed",
            "removed_by_ai"  : True,
            "removed_reason" : reason or label,
            "removed_content": text[:1000],
        }).eq("id", q["id"]).execute()

        # Hoàn điểm nếu pending
        if itype == "q_pending":
            _refund_points(q["user_id"], q.get("points_cost", 0), q["id"])

        # Ghi log
        _log_violation(q["user_id"], q["id"], "question", label, reason, conf)

        # Thông báo cho user
        label_vi = {
            "SPAM"       : "Spam/Quảng cáo",
            "TOXIC"      : "Nội dung không phù hợp",
            "MEANINGLESS": "Không liên quan học tập",
        }.get(label, label)

        send_notification(
            user_id  = q["user_id"],
            ntype    = "content_removed",
            title    = "⚠️ Câu hỏi của bạn đã bị xóa",
            message  = f'Câu hỏi "{q["title"][:50]}..." bị xóa vì: {label_vi}. '
                      f'Lý do: {reason}. Bấm để xem và kháng cáo nếu AI nhận dạng sai.',
            ref_id   = q["id"],
            ref_type = "question",
        )
        print(f"  🚫 Removed question {q['id'][:8]} → {label}")

def _handle_answer_result(a, itype, label, allowed, reason, conf):
    if allowed:
        update = {"removed_by_ai": False}
        if itype == "a_pending":
            update["moderation_status"] = "approved"
            # Thông báo cho chủ câu hỏi có câu trả lời mới
            _notify_new_answer(a)
        supabase.table("answers")\
            .update(update).eq("id", a["id"]).execute()
    else:
        text = a["body"]
        supabase.table("answers").update({
            "moderation_status": "removed",
            "removed_by_ai"    : True,
            "removed_reason"   : reason or label,
            "removed_content"  : text[:1000],
        }).eq("id", a["id"]).execute()

        _log_violation(a["user_id"], a["id"], "answer", label, reason, conf)

        label_vi = {
            "SPAM"       : "Spam/Quảng cáo",
            "TOXIC"      : "Nội dung không phù hợp",
            "MEANINGLESS": "Không liên quan học tập",
        }.get(label, label)

        send_notification(
            user_id  = a["user_id"],
            ntype    = "content_removed",
            title    = "⚠️ Câu trả lời của bạn đã bị xóa",
            message  = f'Câu trả lời bị xóa vì: {label_vi}. '
                      f'Lý do: {reason}. Bấm để xem và kháng cáo nếu AI nhận dạng sai.',
            ref_id   = a["id"],
            ref_type = "answer",
        )
        print(f"  🚫 Removed answer {a['id'][:8]} → {label}")

def _notify_new_answer(answer: dict):
    """Thông báo chủ câu hỏi có câu trả lời mới"""
    try:
        q = supabase.table("questions")\
            .select("id,title,user_id")\
            .eq("id", answer["question_id"])\
            .single().execute()
        if q.data and q.data["user_id"] != answer["user_id"]:
            send_notification(
                user_id  = q.data["user_id"],
                ntype    = "answer_posted",
                title    = "💬 Có câu trả lời mới!",
                message  = f'Câu hỏi "{q.data["title"][:50]}..." vừa nhận được câu trả lời mới.',
                ref_id   = q.data["id"],
                ref_type = "question",
            )
    except Exception as e:
        print(f"  ⚠️  Notify answer error: {e}")

def _handle_appeal(appeal: dict):
    """AI xét duyệt kháng cáo"""
    try:
        ref_id   = appeal["ref_id"]
        ref_type = appeal["ref_type"]

        # Lấy nội dung gốc
        if ref_type == "question":
            r = supabase.table("questions")\
                .select("id,title,body,user_id,points_cost,removed_reason,removed_content")\
                .eq("id", ref_id).single().execute()
        else:
            r = supabase.table("answers")\
                .select("id,body,user_id,removed_reason,removed_content")\
                .eq("id", ref_id).single().execute()

        if not r.data:
            supabase.table("appeals")\
                .update({"status":"rejected","review_note":"Không tìm thấy nội dung"})\
                .eq("id", appeal["id"]).execute()
            return

        item = r.data
        original = item.get("removed_content") or \
                   (f"{item.get('title','')} {item.get('body','')}" if ref_type=="question"
                    else item.get("body",""))

        # AI xét duyệt
        decision, conf, reason = ai_review_appeal(
            original_content = original,
            removed_reason   = item.get("removed_reason",""),
            appeal_content   = appeal["content"],
            content_type     = ref_type,
        )

        print(f"  ⚖️  Appeal {appeal['id'][:8]} → {decision} ({conf:.0%}) {reason}")

        # Cập nhật appeal
        from datetime import datetime, timezone
        supabase.table("appeals").update({
            "status"     : decision,
            "review_note": reason,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", appeal["id"]).execute()

        if decision == "approved":
            # Khôi phục nội dung
            if ref_type == "question":
                supabase.table("questions").update({
                    "status"        : "open",
                    "removed_by_ai" : False,
                    "removed_reason": None,
                }).eq("id", ref_id).execute()

                # Hoàn điểm nếu đã trừ
                if item.get("points_cost"):
                    _refund_points(item["user_id"],
                                   item["points_cost"], ref_id)
            else:
                supabase.table("answers").update({
                    "moderation_status": "approved",
                    "removed_by_ai"    : False,
                    "removed_reason"   : None,
                }).eq("id", ref_id).execute()

            # Thông báo thành công
            send_notification(
                user_id   = appeal["user_id"],
                ntype     = "appeal_approved",
                title     = "✅ Kháng cáo thành công!",
                message   = f'Kháng cáo của bạn đã được chấp nhận. '
                            f'Nội dung đã được khôi phục. Lý do: {reason}',
                ref_id    = ref_id,
                ref_type  = ref_type,
                appeal_id = appeal["id"],
            )
        else:
            # Thông báo thất bại
            send_notification(
                user_id   = appeal["user_id"],
                ntype     = "appeal_rejected",
                title     = "❌ Kháng cáo không thành công",
                message   = f'Kháng cáo của bạn đã được xem xét nhưng không được chấp nhận. '
                            f'Lý do: {reason}',
                ref_id    = ref_id,
                ref_type  = ref_type,
                appeal_id = appeal["id"],
            )

    except Exception as e:
        print(f"  ❌ Appeal error: {e}")

def _handle_report(report: dict):
    """Xử lý báo cáo từ user"""
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
                    _refund_points(r.data["user_id"],
                                   r.data.get("points_cost",0), ref_id)
                    _log_violation(r.data["user_id"], ref_id,
                                   "question", label, reason, conf)
                    send_notification(
                        user_id  = r.data["user_id"],
                        ntype    = "content_removed",
                        title    = "⚠️ Câu hỏi bị xóa sau khi bị báo cáo",
                        message  = f'Câu hỏi của bạn bị xóa sau khi người dùng báo cáo. '
                                  f'Lý do: {reason}. Bạn có thể kháng cáo.',
                        ref_id   = ref_id,
                        ref_type = "question",
                    )
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
                    _log_violation(r.data["user_id"], ref_id,
                                   "answer", label, reason, conf)
                    send_notification(
                        user_id  = r.data["user_id"],
                        ntype    = "content_removed",
                        title    = "⚠️ Câu trả lời bị xóa sau khi bị báo cáo",
                        message  = f'Câu trả lời của bạn bị xóa sau khi người dùng báo cáo. '
                                  f'Lý do: {reason}. Bạn có thể kháng cáo.',
                        ref_id   = ref_id,
                        ref_type = "answer",
                    )
                    print(f"  🚩 Report → removed answer {ref_id[:8]}")

        supabase.table("reports")\
            .update({"status":"resolved"})\
            .eq("id", report["id"]).execute()

    except Exception as e:
        print(f"  ❌ Report error: {e}")

def _refund_points(user_id: str, amount: int, ref_id: str):
    if not amount: return
    try:
        p = supabase.table("profiles")\
            .select("points").eq("id", user_id)\
            .single().execute()
        if p.data:
            supabase.table("profiles")\
                .update({"points": p.data["points"] + amount})\
                .eq("id", user_id).execute()
            supabase.table("point_transactions").insert({
                "user_id": user_id,
                "amount" : amount,
                "reason" : "refund_violation",
                "ref_id" : ref_id,
            }).execute()
    except Exception as e:
        print(f"  ⚠️  Refund error: {e}")

def _log_violation(user_id, ref_id, ref_type, label, reason, conf):
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

@app.get("/health")
async def health():
    counts = {}
    if supabase:
        try:
            for tbl, flt in [
                ("questions",  {"status"           : "pending"}),
                ("answers",    {"moderation_status": "pending"}),
                ("appeals",    {"status"           : "pending"}),
                ("reports",    {"status"           : "pending"}),
            ]:
                key, val = list(flt.items())[0]
                r = supabase.table(tbl)\
                    .select("id", count="exact")\
                    .eq(key, val).execute()
                counts[tbl] = r.count or 0
        except: pass
    return {
        "status"  : "ok",
        "ai_ready": kira is not None,
        "model"   : KIRA_MODEL,
        "scanner" : "running" if (supabase and scan_task
                     and not scan_task.done()) else "disabled",
        "pending" : counts,
        "version" : "4.0.0",
    }

@app.get("/stats")
async def stats():
    if not supabase:
        return {"error": "Supabase not configured"}
    try:
        from collections import Counter
        logs  = supabase.table("moderation_logs").select("label,ref_type").execute()
        rpts  = supabase.table("reports").select("status,reason").execute()
        apps  = supabase.table("appeals").select("status").execute()
        return {
            "violations": {
                "total"   : len(logs.data or []),
                "by_label": dict(Counter(r["label"]    for r in (logs.data or []))),
                "by_type" : dict(Counter(r["ref_type"] for r in (logs.data or []))),
            },
            "reports": {
                "total"    : len(rpts.data or []),
                "by_status": dict(Counter(r["status"] for r in (rpts.data or []))),
            },
            "appeals": {
                "total"    : len(apps.data or []),
                "by_status": dict(Counter(r["status"] for r in (apps.data or []))),
            },
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {
        "service": "HoiBai AI Moderator",
        "version": "4.0.0",
        "model"  : KIRA_MODEL,
    }
