import os, re, unicodedata, asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import Counter

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL  = os.getenv("SUPABASE_URL",         "")
SUPABASE_KEY  = os.getenv("SUPABASE_SERVICE_KEY", "")
MCP_SECRET    = os.getenv("MCP_SECRET",           "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL",    "30"))
BATCH_SIZE    = int(os.getenv("BATCH_SIZE",       "5"))

supabase  = None
scan_task = None

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global supabase, scan_task

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

app = FastAPI(title="HoiBai Moderator (MCP)", version="5.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Hard Rules (không dùng AI, chỉ rule cứng) ────────────────────────────────
def hard_rules(text: str) -> tuple:
    """
    Trả về (label, reason) nếu vi phạm rule cứng,
    hoặc (None, "") nếu cần admin xem xét.
    """
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

    # Từ khóa nghi ngờ — đưa vào hàng chờ admin duyệt
    SUSPICIOUS_PATTERNS = [
        r'(?i)(sex|porn|18\+|địt|lồn|cặc|đụ|fuck|shit)',
        r'(?i)(quảng cáo|mua ngay|liên hệ|zalo|telegram|t\.me/)',
        r'https?://\S+',
        r'\b0\d{9,10}\b',
    ]
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, t):
            return "SUSPICIOUS", f"Khớp pattern: {pattern}"

    return None, ""

def classify_content(text: str) -> tuple:
    """Phân loại nội dung bằng rule cứng, không dùng AI."""
    label, reason = hard_rules(text)
    if label:
        return label, reason
    return "PENDING_REVIEW", "Cần admin xem xét"

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

# ── Points helpers ────────────────────────────────────────────────────────────
def _refund_points(user_id: str, amount: int, ref_id: str):
    if not amount: return
    try:
        p = supabase.table("profiles")\
            .select("points").eq("id", user_id).single().execute()
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

def _log_violation(user_id, ref_id, ref_type, label, reason):
    try:
        supabase.table("moderation_logs").insert({
            "user_id"  : user_id,
            "ref_id"   : ref_id,
            "ref_type" : ref_type,
            "label"    : label,
            "reason"   : reason,
            "action"   : "flagged",
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Log error: {e}")

# ── Background Scanner ────────────────────────────────────────────────────────
async def scanner_loop():
    print(f"🔍 Scanner started! Interval: {SCAN_INTERVAL}s")
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
        # Câu hỏi mới (pending)
        qs = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        # Câu trả lời mới (pending)
        ans = supabase.table("answers")\
            .select("id,body,user_id,question_id")\
            .eq("moderation_status","pending")\
            .limit(BATCH_SIZE).execute()

        # Reports pending
        reports = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,reporter_id")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs.data  or []): items.append(("question", q))
        for a in (ans.data or []): items.append(("answer",   a))
        for r in (reports.data or []): items.append(("report", r))

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
        if itype == "report":
            _handle_report(data)
            return

        # Lấy text để check rule cứng
        if itype == "question":
            text = f"{data['title']} {data.get('body','') or ''}"
        else:
            text = data["body"]

        label, reason = hard_rules(text)

        if label in ("MEANINGLESS", "SUSPICIOUS"):
            # Vi phạm rule cứng → đánh dấu cần admin duyệt
            _flag_for_review(itype, data, label, reason)
        else:
            # Sạch → approve
            if itype == "question":
                supabase.table("questions")\
                    .update({"status": "open", "removed_by_ai": False})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("answers")\
                    .update({"moderation_status": "approved", "removed_by_ai": False})\
                    .eq("id", data["id"]).execute()
                _notify_new_answer(data)

            print(f"  ✅ [{itype}] {data['id'][:8]} → approved")

    except Exception as e:
        print(f"  ❌ process error [{itype}]: {e}")

def _flag_for_review(itype: str, data: dict, label: str, reason: str):
    """Đánh dấu nội dung nghi ngờ để admin xem xét."""
    try:
        if itype == "question":
            text = f"{data['title']} {data.get('body','') or ''}"
            supabase.table("questions").update({
                "status"         : "pending",
                "removed_reason" : f"[Chờ admin] {label}: {reason}",
            }).eq("id", data["id"]).execute()
        else:
            supabase.table("answers").update({
                "moderation_status": "pending",
                "removed_reason"   : f"[Chờ admin] {label}: {reason}",
            }).eq("id", data["id"]).execute()
            text = data["body"]

        _log_violation(data["user_id"], data["id"], itype, label, reason)
        print(f"  🚩 [{itype}] {data['id'][:8]} → flagged ({label}: {reason})")

    except Exception as e:
        print(f"  ❌ flag error: {e}")

def _notify_new_answer(answer: dict):
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

def _handle_report(report: dict):
    """Đánh dấu report để admin xem xét — không tự xóa."""
    try:
        ref_id      = report["ref_id"]
        ref_type    = report["ref_type"]
        reporter_id = report.get("reporter_id")

        # Giữ status pending để admin thấy trong MCP
        # Chỉ log lại
        print(f"  🚩 Report {report['id'][:8]} → chờ admin duyệt")

        # Thông báo reporter là đã nhận report
        if reporter_id:
            send_notification(
                user_id  = reporter_id,
                ntype    = "report_resolved",
                title    = "📨 Báo cáo đã được tiếp nhận",
                message  = "Báo cáo của bạn đã được ghi nhận và sẽ được admin xem xét sớm. "
                           "Cảm ơn bạn đã đóng góp cho cộng đồng!",
                ref_id   = ref_id,
                ref_type = ref_type,
            )

    except Exception as e:
        print(f"  ❌ Report error: {e}")

# ── MCP Auth ──────────────────────────────────────────────────────────────────
def verify_mcp(authorization: str = Header(None)):
    if MCP_SECRET and authorization != f"Bearer {MCP_SECRET}":
        raise HTTPException(401, "Unauthorized")

# ── Schemas ───────────────────────────────────────────────────────────────────
class ModerateRequest(BaseModel):
    text   : str
    context: str = "question"

class ModerateResponse(BaseModel):
    label     : str
    allowed   : bool
    reason    : str

class MCPToolCall(BaseModel):
    tool : str
    input: dict = {}

# ── /moderate endpoint (PHP gọi) ──────────────────────────────────────────────
@app.post("/moderate", response_model=ModerateResponse)
async def moderate(req: ModerateRequest):
    """PHP gọi endpoint này khi user submit — chỉ dùng rule cứng."""
    text = req.text.strip()
    label, reason = hard_rules(text)

    if label in ("MEANINGLESS", "SUSPICIOUS"):
        return ModerateResponse(
            label=label, allowed=False, reason=reason
        )
    # Còn lại → cho phép, scanner sẽ xem xét sau
    return ModerateResponse(
        label="CLEAN", allowed=True, reason="Passed rules"
    )

# ── MCP Info ──────────────────────────────────────────────────────────────────
@app.get("/mcp")
async def mcp_info():
    return {
        "name"       : "HoiBai Moderation",
        "description": "Admin duyệt nội dung HoiBai qua Claude",
        "version"    : "5.0.0",
        "tools"      : [
            {
                "name"       : "list_flagged",
                "description": "Liệt kê câu hỏi/câu trả lời bị gắn cờ nghi ngờ vi phạm, chờ admin duyệt",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "type": {"type":"string","description":"'question', 'answer', hoặc 'all' (mặc định)"},
                    },
                },
            },
            {
                "name"       : "list_pending_reports",
                "description": "Liệt kê báo cáo vi phạm từ người dùng đang chờ admin xử lý",
                "inputSchema": {"type":"object","properties":{}},
            },
            {
                "name"       : "list_pending_appeals",
                "description": "Liệt kê kháng cáo từ người dùng đang chờ admin duyệt",
                "inputSchema": {"type":"object","properties":{}},
            },
            {
                "name"       : "get_content_detail",
                "description": "Xem chi tiết nội dung câu hỏi hoặc câu trả lời (kèm ảnh nếu có)",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"  : {"type":"string","description":"ID nội dung"},
                        "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
                    },
                    "required": ["ref_id","ref_type"],
                },
            },
            {
                "name"       : "approve_content",
                "description": "Duyệt nội dung — cho phép hiển thị (câu hỏi bị gắn cờ hoặc answer pending)",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"  : {"type":"string","description":"ID nội dung"},
                        "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
                        "reason"  : {"type":"string","description":"Lý do duyệt"},
                    },
                    "required": ["ref_id","ref_type"],
                },
            },
            {
                "name"       : "remove_content",
                "description": "Xóa nội dung vi phạm sau khi admin xem xét",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"   : {"type":"string","description":"ID nội dung"},
                        "ref_type" : {"type":"string","description":"'question' hoặc 'answer'"},
                        "reason"   : {"type":"string","description":"Lý do xóa"},
                        "report_id": {"type":"string","description":"ID report liên quan (nếu có)"},
                    },
                    "required": ["ref_id","ref_type","reason"],
                },
            },
            {
                "name"       : "approve_appeal",
                "description": "Chấp nhận kháng cáo — khôi phục nội dung bị xóa",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "appeal_id": {"type":"string","description":"ID kháng cáo"},
                        "reason"   : {"type":"string","description":"Lý do chấp nhận"},
                    },
                    "required": ["appeal_id","reason"],
                },
            },
            {
                "name"       : "reject_appeal",
                "description": "Từ chối kháng cáo — giữ nguyên quyết định xóa",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "appeal_id": {"type":"string","description":"ID kháng cáo"},
                        "reason"   : {"type":"string","description":"Lý do từ chối"},
                    },
                    "required": ["appeal_id","reason"],
                },
            },
            {
                "name"       : "resolve_report",
                "description": "Đánh dấu báo cáo đã xử lý (sau khi remove_content hoặc xác nhận không vi phạm)",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "report_id"  : {"type":"string","description":"ID báo cáo"},
                        "action_taken": {"type":"boolean","description":"true nếu đã xóa nội dung, false nếu không vi phạm"},
                        "reason"     : {"type":"string","description":"Lý do quyết định"},
                    },
                    "required": ["report_id","action_taken","reason"],
                },
            },
            {
                "name"       : "get_stats",
                "description": "Xem thống kê tổng quan hệ thống",
                "inputSchema": {"type":"object","properties":{}},
            },
        ]
    }

# ── MCP Execute ───────────────────────────────────────────────────────────────
@app.post("/mcp/call")
async def mcp_call(req: MCPToolCall,
                   authorization: str = Header(None)):
    verify_mcp(authorization)

    tool = req.tool
    inp  = req.input

    # ── list_flagged ──────────────────────────────────────────────────────────
    if tool == "list_flagged":
        content_type = inp.get("type", "all")
        lines = []

        if content_type in ("question", "all"):
            r = supabase.table("questions")\
                .select("id,title,body,user_id,removed_reason,created_at,profiles(username)")\
                .eq("status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at", desc=False)\
                .limit(20).execute()
            if r.data:
                lines.append(f"📚 **{len(r.data)} CÂU HỎI bị gắn cờ:**\n")
                for q in r.data:
                    lines.append(
                        f"🆔 `{q['id']}`\n"
                        f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"
                        f"📋 {q.get('title','')[:100]}\n"
                        f"🚩 Lý do gắn cờ: {q.get('removed_reason','')}\n"
                        f"🕐 {q.get('created_at','')[:16]}\n---"
                    )

        if content_type in ("answer", "all"):
            r = supabase.table("answers")\
                .select("id,body,user_id,question_id,removed_reason,created_at,profiles(username)")\
                .eq("moderation_status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at", desc=False)\
                .limit(20).execute()
            if r.data:
                lines.append(f"\n💬 **{len(r.data)} CÂU TRẢ LỜI bị gắn cờ:**\n")
                for a in r.data:
                    lines.append(
                        f"🆔 `{a['id']}`\n"
                        f"👤 {a['profiles']['username'] if a.get('profiles') else '?'}\n"
                        f"📄 {a.get('body','')[:100]}...\n"
                        f"🚩 Lý do gắn cờ: {a.get('removed_reason','')}\n"
                        f"🕐 {a.get('created_at','')[:16]}\n---"
                    )

        if not lines:
            return {"result": "✅ Không có nội dung nào bị gắn cờ chờ duyệt."}
        return {"result": "\n".join(lines)}

    # ── list_pending_reports ──────────────────────────────────────────────────
    if tool == "list_pending_reports":
        r = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,detail,created_at,profiles(username)")\
            .eq("status","pending")\
            .order("created_at", desc=False)\
            .limit(20).execute()

        if not r.data:
            return {"result": "✅ Không có báo cáo nào đang chờ xử lý."}

        lines = [f"🚩 **{len(r.data)} báo cáo đang chờ admin:**\n"]
        for rep in r.data:
            lines.append(
                f"🆔 Report: `{rep['id']}`\n"
                f"👤 Người báo cáo: {rep['profiles']['username'] if rep.get('profiles') else '?'}\n"
                f"📌 Loại: {rep['ref_type']} | ID nội dung: `{rep['ref_id']}`\n"
                f"⚠️  Lý do: {rep['reason']}\n"
                f"📝 Chi tiết: {rep.get('detail') or '(không có)'}\n"
                f"🕐 Gửi: {rep['created_at'][:16]}\n---"
            )
        return {"result": "\n".join(lines)}

    # ── list_pending_appeals ──────────────────────────────────────────────────
    if tool == "list_pending_appeals":
        r = supabase.table("appeals")\
            .select("id,user_id,ref_id,ref_type,content,created_at,profiles(username)")\
            .eq("status","pending")\
            .order("created_at", desc=False)\
            .limit(20).execute()

        if not r.data:
            return {"result": "✅ Không có kháng cáo nào đang chờ duyệt."}

        lines = [f"⚖️  **{len(r.data)} kháng cáo đang chờ admin:**\n"]
        for a in r.data:
            lines.append(
                f"🆔 Appeal: `{a['id']}`\n"
                f"👤 User: {a['profiles']['username'] if a.get('profiles') else a['user_id'][:8]}\n"
                f"📌 Loại: {a['ref_type']} | ID nội dung: `{a['ref_id']}`\n"
                f"💬 Lý do kháng cáo: {a['content'][:300]}\n"
                f"🕐 Gửi: {a['created_at'][:16]}\n---"
            )
        return {"result": "\n".join(lines)}

    # ── get_content_detail ────────────────────────────────────────────────────
    if tool == "get_content_detail":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")

        if ref_type == "question":
            r = supabase.table("questions")\
                .select("*,profiles(username)")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu hỏi."}
            q = r.data
            result = (
                f"📚 **CÂU HỎI**\n"
                f"🆔 ID: `{q['id']}`\n"
                f"👤 Tác giả: {q['profiles']['username'] if q.get('profiles') else '?'}\n"
                f"📌 Khối: {q.get('grade_group','')} | Môn: {q.get('subject','')}\n"
                f"📋 Tiêu đề: {q.get('title','')}\n"
                f"📄 Nội dung: {q.get('body','') or '(không có)'}\n"
                f"🖼️  Ảnh: {q.get('image_url') or '(không có)'}\n"
                f"📊 Status: {q.get('status','')}\n"
                f"🚩 Lý do gắn cờ: {q.get('removed_reason') or '(chưa gắn cờ)'}\n"
                f"👁️  Lượt xem: {q.get('views',0)}\n"
                f"⭐ Điểm thưởng: {q.get('points_cost',0)}\n"
                f"🕐 Đăng: {q.get('created_at','')[:16]}"
            )
            if q.get("image_url"):
                result += f"\n\n🖼️  **Link ảnh:** {q['image_url']}"

        else:
            r = supabase.table("answers")\
                .select("*,profiles(username),questions(title)")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu trả lời."}
            a = r.data
            result = (
                f"💬 **CÂU TRẢ LỜI**\n"
                f"🆔 ID: `{a['id']}`\n"
                f"👤 Tác giả: {a['profiles']['username'] if a.get('profiles') else '?'}\n"
                f"❓ Câu hỏi: {a['questions']['title'] if a.get('questions') else a.get('question_id','')}\n"
                f"📄 Nội dung: {a.get('body','')}\n"
                f"🖼️  Ảnh: {a.get('image_url') or '(không có)'}\n"
                f"📊 Status: {a.get('moderation_status','')}\n"
                f"🚩 Lý do gắn cờ: {a.get('removed_reason') or '(chưa gắn cờ)'}\n"
                f"🕐 Đăng: {a.get('created_at','')[:16]}"
            )
            if a.get("image_url"):
                result += f"\n\n🖼️  **Link ảnh:** {a['image_url']}"

        return {"result": result}

    # ── approve_content ───────────────────────────────────────────────────────
    if tool == "approve_content":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        reason   = inp.get("reason","Admin duyệt hợp lệ")

        if ref_type == "question":
            r = supabase.table("questions")\
                .select("user_id,title")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu hỏi."}
            supabase.table("questions").update({
                "status"        : "open",
                "removed_by_ai" : False,
                "removed_reason": None,
            }).eq("id", ref_id).execute()
            send_notification(
                user_id  = r.data["user_id"],
                ntype    = "appeal_approved",
                title    = "✅ Câu hỏi của bạn đã được duyệt",
                message  = f'Câu hỏi "{r.data.get("title","")[:50]}" đã được admin duyệt và hiển thị. '
                           f'Lý do: {reason}',
                ref_id   = ref_id,
                ref_type = "question",
            )
        else:
            r = supabase.table("answers")\
                .select("user_id,question_id")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu trả lời."}
            supabase.table("answers").update({
                "moderation_status": "approved",
                "removed_by_ai"    : False,
                "removed_reason"   : None,
            }).eq("id", ref_id).execute()
            # Thông báo chủ câu hỏi
            _notify_new_answer({
                "id"         : ref_id,
                "user_id"    : r.data["user_id"],
                "question_id": r.data["question_id"],
            })
            send_notification(
                user_id  = r.data["user_id"],
                ntype    = "appeal_approved",
                title    = "✅ Câu trả lời của bạn đã được duyệt",
                message  = f'Câu trả lời của bạn đã được admin duyệt. Lý do: {reason}',
                ref_id   = ref_id,
                ref_type = "answer",
            )

        return {"result": f"✅ Đã duyệt {ref_type} `{ref_id[:8]}`. Thông báo đã gửi cho user."}

    # ── remove_content ────────────────────────────────────────────────────────
    if tool == "remove_content":
        ref_id    = inp.get("ref_id","")
        ref_type  = inp.get("ref_type","")
        reason    = inp.get("reason","Admin xóa nội dung vi phạm")
        report_id = inp.get("report_id","")

        if ref_type == "question":
            r = supabase.table("questions")\
                .select("user_id,points_cost,title")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu hỏi."}
            supabase.table("questions").update({
                "status"         : "removed",
                "removed_by_ai"  : True,
                "removed_reason" : f"Admin: {reason}",
            }).eq("id", ref_id).execute()
            _refund_points(r.data["user_id"],
                           r.data.get("points_cost",0), ref_id)
            _log_violation(r.data["user_id"], ref_id,
                           "question", "REMOVED", f"Admin: {reason}")
            send_notification(
                user_id  = r.data["user_id"],
                ntype    = "content_removed",
                title    = "⚠️ Câu hỏi bị xóa bởi Admin",
                message  = f'Câu hỏi "{r.data.get("title","")[:50]}" đã bị Admin xóa. '
                           f'Lý do: {reason}. Bạn có thể kháng cáo nếu cho rằng quyết định này sai.',
                ref_id   = ref_id,
                ref_type = "question",
            )
        else:
            r = supabase.table("answers")\
                .select("user_id,body")\
                .eq("id", ref_id).single().execute()
            if not r.data:
                return {"result": "Không tìm thấy câu trả lời."}
            supabase.table("answers").update({
                "moderation_status": "removed",
                "removed_by_ai"    : True,
                "removed_reason"   : f"Admin: {reason}",
                "removed_content"  : r.data.get("body","")[:1000],
            }).eq("id", ref_id).execute()
            _log_violation(r.data["user_id"], ref_id,
                           "answer", "REMOVED", f"Admin: {reason}")
            send_notification(
                user_id  = r.data["user_id"],
                ntype    = "content_removed",
                title    = "⚠️ Câu trả lời bị xóa bởi Admin",
                message  = f'Câu trả lời của bạn đã bị Admin xóa. '
                           f'Lý do: {reason}. Bạn có thể kháng cáo nếu cho rằng quyết định này sai.',
                ref_id   = ref_id,
                ref_type = "answer",
            )

        # Đánh dấu report resolved nếu có
        if report_id:
            supabase.table("reports")\
                .update({"status":"resolved"})\
                .eq("id", report_id).execute()

        return {"result": f"🚫 Đã xóa {ref_type} `{ref_id[:8]}`. Thông báo đã gửi cho user."}

    # ── approve_appeal ────────────────────────────────────────────────────────
    if tool == "approve_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin chấp nhận kháng cáo")

        ap = supabase.table("appeals")\
            .select("*").eq("id", appeal_id).single().execute()
        if not ap.data:
            return {"result": "Không tìm thấy kháng cáo."}

        a        = ap.data
        ref_id   = a["ref_id"]
        ref_type = a["ref_type"]
        now      = datetime.now(timezone.utc).isoformat()

        supabase.table("appeals").update({
            "status"     : "approved",
            "review_note": reason,
            "reviewed_at": now,
        }).eq("id", appeal_id).execute()

        if ref_type == "question":
            q = supabase.table("questions")\
                .select("user_id,points_cost")\
                .eq("id", ref_id).single().execute()
            supabase.table("questions").update({
                "status"        : "open",
                "removed_by_ai" : False,
                "removed_reason": None,
            }).eq("id", ref_id).execute()
            if q.data and q.data.get("points_cost"):
                _refund_points(q.data["user_id"],
                               q.data["points_cost"], ref_id)
        else:
            supabase.table("answers").update({
                "moderation_status": "approved",
                "removed_by_ai"    : False,
                "removed_reason"   : None,
            }).eq("id", ref_id).execute()

        send_notification(
            user_id   = a["user_id"],
            ntype     = "appeal_approved",
            title     = "✅ Kháng cáo thành công! (Admin duyệt)",
            message   = f'Admin đã chấp nhận kháng cáo của bạn. '
                       f'Nội dung đã được khôi phục. Lý do: {reason}',
            ref_id    = ref_id,
            ref_type  = ref_type,
            appeal_id = appeal_id,
        )

        return {"result": f"✅ Đã chấp nhận kháng cáo `{appeal_id[:8]}`. Nội dung khôi phục và thông báo đã gửi."}

    # ── reject_appeal ─────────────────────────────────────────────────────────
    if tool == "reject_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin từ chối kháng cáo")

        ap = supabase.table("appeals")\
            .select("*").eq("id", appeal_id).single().execute()
        if not ap.data:
            return {"result": "Không tìm thấy kháng cáo."}

        supabase.table("appeals").update({
            "status"     : "rejected",
            "review_note": reason,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", appeal_id).execute()

        send_notification(
            user_id   = ap.data["user_id"],
            ntype     = "appeal_rejected",
            title     = "❌ Kháng cáo không thành công (Admin duyệt)",
            message   = f'Admin đã xem xét kháng cáo của bạn nhưng không chấp nhận. '
                       f'Lý do: {reason}',
            ref_id    = ap.data["ref_id"],
            ref_type  = ap.data["ref_type"],
            appeal_id = appeal_id,
        )

        return {"result": f"❌ Đã từ chối kháng cáo `{appeal_id[:8]}`. Thông báo đã gửi."}

    # ── resolve_report ────────────────────────────────────────────────────────
    if tool == "resolve_report":
        report_id    = inp.get("report_id","")
        action_taken = inp.get("action_taken", False)
        reason       = inp.get("reason","")

        rep = supabase.table("reports")\
            .select("*,profiles(username)")\
            .eq("id", report_id).single().execute()
        if not rep.data:
            return {"result": "Không tìm thấy báo cáo."}

        r           = rep.data
        reporter_id = r.get("reporter_id")

        supabase.table("reports")\
            .update({"status":"resolved"})\
            .eq("id", report_id).execute()

        if reporter_id:
            if action_taken:
                send_notification(
                    user_id  = reporter_id,
                    ntype    = "report_resolved",
                    title    = "✅ Báo cáo của bạn đã được xử lý",
                    message  = f'Cảm ơn bạn đã báo cáo! Admin đã xem xét và xử lý nội dung vi phạm. '
                               f'Lý do: {reason}',
                    ref_id   = r["ref_id"],
                    ref_type = r["ref_type"],
                )
            else:
                send_notification(
                    user_id  = reporter_id,
                    ntype    = "report_resolved",
                    title    = "ℹ️ Báo cáo đã được xem xét",
                    message  = f'Admin đã xem xét nội dung bị báo cáo nhưng không phát hiện vi phạm. '
                               f'Lý do: {reason}. Cảm ơn bạn đã đóng góp cho cộng đồng!',
                    ref_id   = r["ref_id"],
                    ref_type = r["ref_type"],
                )

        return {"result": f"✅ Đã đánh dấu report `{report_id[:8]}` là resolved. Thông báo đã gửi cho reporter."}

    # ── get_stats ─────────────────────────────────────────────────────────────
    if tool == "get_stats":
        logs  = supabase.table("moderation_logs").select("label,ref_type").execute()
        rpts  = supabase.table("reports").select("status").execute()
        apps  = supabase.table("appeals").select("status").execute()

        # Đếm nội dung đang chờ duyệt
        q_pending = supabase.table("questions")\
            .select("id", count="exact")\
            .eq("status","pending")\
            .not_.is_("removed_reason","null").execute()
        a_pending = supabase.table("answers")\
            .select("id", count="exact")\
            .eq("moderation_status","pending")\
            .not_.is_("removed_reason","null").execute()

        r_counts = Counter(r["status"] for r in (rpts.data or []))
        a_counts = Counter(a["status"] for a in (apps.data or []))
        l_counts = Counter(l["label"]  for l in (logs.data or []))

        result = (
            f"📊 **THỐNG KÊ HỆ THỐNG**\n\n"
            f"⏳ **Chờ admin duyệt:**\n"
            f"  - Câu hỏi bị gắn cờ: {q_pending.count or 0}\n"
            f"  - Câu trả lời bị gắn cờ: {a_pending.count or 0}\n"
            f"  - Báo cáo pending: {r_counts.get('pending',0)}\n"
            f"  - Kháng cáo pending: {a_counts.get('pending',0)}\n\n"
            f"🚫 **Vi phạm đã xử lý:** {len(logs.data or [])}\n"
            + "\n".join(f"  - {k}: {v}" for k,v in l_counts.items()) +
            f"\n\n🚩 **Báo cáo:**\n"
            + "\n".join(f"  - {k}: {v}" for k,v in r_counts.items()) +
            f"\n\n⚖️  **Kháng cáo:**\n"
            + "\n".join(f"  - {k}: {v}" for k,v in a_counts.items())
        )
        return {"result": result}

    return {"result": f"Tool '{tool}' không tồn tại."}

# ── Health & Root ─────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    counts = {}
    if supabase:
        try:
            q = supabase.table("questions").select("id",count="exact")\
                .eq("status","pending").not_.is_("removed_reason","null").execute()
            a = supabase.table("answers").select("id",count="exact")\
                .eq("moderation_status","pending").not_.is_("removed_reason","null").execute()
            r = supabase.table("reports").select("id",count="exact")\
                .eq("status","pending").execute()
            ap = supabase.table("appeals").select("id",count="exact")\
                .eq("status","pending").execute()
            counts = {
                "questions_flagged": q.count or 0,
                "answers_flagged"  : a.count or 0,
                "reports_pending"  : r.count or 0,
                "appeals_pending"  : ap.count or 0,
            }
        except: pass
    return {
        "status" : "ok",
        "mode"   : "manual_review (MCP)",
        "scanner": "running" if (supabase and scan_task
                    and not scan_task.done()) else "disabled",
        "pending": counts,
        "version": "5.0.0",
    }

@app.get("/")
async def root():
    return {
        "service": "HoiBai Moderator",
        "version": "5.0.0",
        "mode"   : "manual_review via MCP",
    }
