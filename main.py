import os, re, asyncio, hashlib, time, base64, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import Counter

import httpx
from fastapi import FastAPI, Header, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL  = os.getenv("SUPABASE_URL",         "")
SUPABASE_KEY  = os.getenv("SUPABASE_SERVICE_KEY", "")
ADMIN_TOKEN   = os.getenv("ADMIN_TOKEN",          "hoibai-admin-secret")
BASE_URL      = os.getenv("BASE_URL",             "https://api-production-8d4b7.up.railway.app")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL",    "30"))
BATCH_SIZE    = int(os.getenv("BATCH_SIZE",       "5"))

supabase    = None
scan_task   = None
_auth_codes: dict = {}

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

# ── OAuth 2.0 ─────────────────────────────────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer"                                : BASE_URL,
        "authorization_endpoint"               : f"{BASE_URL}/oauth/authorize",
        "token_endpoint"                        : f"{BASE_URL}/oauth/token",
        "response_types_supported"             : ["code"],
        "grant_types_supported"                : ["authorization_code"],
        "code_challenge_methods_supported"     : ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }

@app.get("/oauth/authorize")
async def oauth_authorize(
    response_type        : str = "",
    client_id            : str = "",
    redirect_uri         : str = "",
    state                : str = "",
    code_challenge       : str = "",
    code_challenge_method: str = "",
):
    code = hashlib.sha256(f"{ADMIN_TOKEN}{time.time()}".encode()).hexdigest()[:32]
    _auth_codes[code] = {
        "code_challenge": code_challenge,
        "expires"       : time.time() + 300,
    }
    url = f"{redirect_uri}?code={code}"
    if state:
        url += f"&state={state}"
    return RedirectResponse(url, status_code=302)

@app.post("/oauth/token")
async def oauth_token(
    grant_type   : str = Form(""),
    code         : str = Form(""),
    redirect_uri : str = Form(""),
    code_verifier: str = Form(""),
    client_id    : str = Form(""),
):
    expired = [k for k, v in _auth_codes.items() if v["expires"] < time.time()]
    for k in expired:
        del _auth_codes[k]

    if code not in _auth_codes:
        raise HTTPException(400, "invalid_grant")

    stored = _auth_codes.pop(code)

    if stored.get("code_challenge") and code_verifier:
        verifier_hash = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if verifier_hash != stored["code_challenge"]:
            raise HTTPException(400, "invalid_grant: PKCE mismatch")

    return {
        "access_token": ADMIN_TOKEN,
        "token_type"  : "bearer",
        "expires_in"  : 86400,
    }

# ── MCP Tools definition ──────────────────────────────────────────────────────
MCP_TOOLS = [
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
        "description": "Xem chi tiết nội dung câu hỏi hoặc câu trả lời",
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
        "name"       : "get_image",
        "description": "Tải ảnh từ URL và trả về dạng image block để admin xem nội dung ảnh đính kèm, phát hiện vi phạm trong ảnh",
        "inputSchema": {
            "type"      : "object",
            "properties": {
                "image_url": {"type":"string","description":"URL của ảnh cần xem"},
            },
            "required": ["image_url"],
        },
    },
    {
        "name"       : "get_question_by_answer_id",
        "description": "Lấy thông tin câu hỏi cha từ ID của một câu trả lời — dùng khi cần xem ngữ cảnh hoặc xóa câu hỏi liên quan",
        "inputSchema": {
            "type"      : "object",
            "properties": {
                "answer_id": {"type":"string","description":"ID của câu trả lời"},
            },
            "required": ["answer_id"],
        },
    },
    {
        "name"       : "approve_content",
        "description": "Duyệt nội dung — cho phép hiển thị",
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
        "description": "Đánh dấu báo cáo đã xử lý",
        "inputSchema": {
            "type"      : "object",
            "properties": {
                "report_id"   : {"type":"string","description":"ID báo cáo"},
                "action_taken": {"type":"boolean","description":"true nếu đã xóa, false nếu không vi phạm"},
                "reason"      : {"type":"string","description":"Lý do quyết định"},
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

# ── MCP Tool executor ─────────────────────────────────────────────────────────
# Trả về str hoặc list[dict] (content blocks cho image)
def execute_tool(tool: str, inp: dict):
    if tool == "list_flagged":
        content_type = inp.get("type", "all")
        lines = []
        if content_type in ("question", "all"):
            r = supabase.table("questions")\
                .select("id,title,user_id,removed_reason,created_at,profiles(username)")\
                .eq("status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at", desc=False).limit(20).execute()
            if r.data:
                lines.append(f"📚 **{len(r.data)} CÂU HỎI bị gắn cờ:**\n")
                for q in r.data:
                    lines.append(
                        f"🆔 `{q['id']}`\n"
                        f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"
                        f"📋 {q.get('title','')[:100]}\n"
                        f"🚩 {q.get('removed_reason','')}\n"
                        f"🕐 {q.get('created_at','')[:16]}\n---"
                    )
        if content_type in ("answer", "all"):
            r = supabase.table("answers")\
                .select("id,body,user_id,removed_reason,created_at,profiles(username)")\
                .eq("moderation_status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at", desc=False).limit(20).execute()
            if r.data:
                lines.append(f"\n💬 **{len(r.data)} CÂU TRẢ LỜI bị gắn cờ:**\n")
                for a in r.data:
                    lines.append(
                        f"🆔 `{a['id']}`\n"
                        f"👤 {a['profiles']['username'] if a.get('profiles') else '?'}\n"
                        f"📄 {a.get('body','')[:100]}\n"
                        f"🚩 {a.get('removed_reason','')}\n"
                        f"🕐 {a.get('created_at','')[:16]}\n---"
                    )
        return "\n".join(lines) if lines else "✅ Không có nội dung nào bị gắn cờ."

    if tool == "list_pending_reports":
        r = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,detail,created_at,profiles(username)")\
            .eq("status","pending").order("created_at", desc=False).limit(20).execute()
        if not r.data:
            return "✅ Không có báo cáo nào đang chờ xử lý."
        lines = [f"🚩 **{len(r.data)} báo cáo đang chờ admin:**\n"]
        for rep in r.data:
            lines.append(
                f"🆔 `{rep['id']}`\n"
                f"👤 {rep['profiles']['username'] if rep.get('profiles') else '?'}\n"
                f"📌 {rep['ref_type']} | `{rep['ref_id']}`\n"
                f"⚠️  {rep['reason']}\n"
                f"📝 {rep.get('detail') or '(không có)'}\n"
                f"🕐 {rep['created_at'][:16]}\n---"
            )
        return "\n".join(lines)

    if tool == "list_pending_appeals":
        r = supabase.table("appeals")\
            .select("id,user_id,ref_id,ref_type,content,created_at,profiles(username)")\
            .eq("status","pending").order("created_at", desc=False).limit(20).execute()
        if not r.data:
            return "✅ Không có kháng cáo nào đang chờ duyệt."
        lines = [f"⚖️  **{len(r.data)} kháng cáo đang chờ admin:**\n"]
        for a in r.data:
            lines.append(
                f"🆔 `{a['id']}`\n"
                f"👤 {a['profiles']['username'] if a.get('profiles') else a['user_id'][:8]}\n"
                f"📌 {a['ref_type']} | `{a['ref_id']}`\n"
                f"💬 {a['content'][:300]}\n"
                f"🕐 {a['created_at'][:16]}\n---"
            )
        return "\n".join(lines)

    if tool == "get_content_detail":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        if ref_type == "question":
            r = supabase.table("questions")\
                .select("*,profiles(username)").eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu hỏi."
            q = r.data
            return (
                f"📚 **CÂU HỎI**\n🆔 `{q['id']}`\n"
                f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"
                f"📌 {q.get('grade_group','')} | {q.get('subject','')}\n"
                f"📋 {q.get('title','')}\n"
                f"📄 {q.get('body','') or '(không có)'}\n"
                f"🖼️  {q.get('image_url') or '(không có ảnh)'}\n"
                f"📊 {q.get('status','')} | 🚩 {q.get('removed_reason') or '(chưa gắn cờ)'}\n"
                f"👁️  {q.get('views',0)} lượt | ⭐ {q.get('points_cost',0)} điểm\n"
                f"🕐 {q.get('created_at','')[:16]}"
            )
        else:
            r = supabase.table("answers")\
                .select("*,profiles(username),questions(title)")\
                .eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu trả lời."
            a = r.data
            return (
                f"💬 **CÂU TRẢ LỜI**\n🆔 `{a['id']}`\n"
                f"👤 {a['profiles']['username'] if a.get('profiles') else '?'}\n"
                f"❓ {a['questions']['title'] if a.get('questions') else a.get('question_id','')}\n"
                f"📄 {a.get('body','')}\n"
                f"🖼️  {a.get('image_url') or '(không có ảnh)'}\n"
                f"📊 {a.get('moderation_status','')} | 🚩 {a.get('removed_reason') or '(chưa gắn cờ)'}\n"
                f"🕐 {a.get('created_at','')[:16]}"
            )

    # ── get_image (BUG FIX) ─────────────────────────────────────────────────────
    if tool == "get_image":
        image_url = inp.get("image_url", "").strip()
        if not image_url:
            return "❌ Thiếu image_url."
        try:
            # Thêm timeout và retries để tránh lỗi network
            resp = httpx.get(
                image_url, 
                timeout=15, 
                follow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            if resp.status_code != 200:
                return f"❌ Không tải được ảnh (HTTP {resp.status_code})."
            
            # FIX: Kiểm tra content-type chính xác hơn
            content_type = resp.headers.get("content-type", "image/jpeg")
            if ";" in content_type:
                content_type = content_type.split(";")[0].strip()
            
            # Nếu không phải image, try guess từ URL hoặc use default
            if not content_type.startswith("image/"):
                # Guess từ URL
                if ".png" in image_url.lower():
                    content_type = "image/png"
                elif ".gif" in image_url.lower():
                    content_type = "image/gif"
                elif ".webp" in image_url.lower():
                    content_type = "image/webp"
                else:
                    content_type = "image/jpeg"
            
            # FIX: Kiểm tra kích thước để tránh ảnh quá lớn
            if len(resp.content) > 5 * 1024 * 1024:  # 5MB limit
                return f"❌ Ảnh quá lớn ({len(resp.content) // 1024 // 1024}MB > 5MB)."
            
            b64      = base64.b64encode(resp.content).decode()
            size_kb  = len(resp.content) // 1024
            
            # FIX: Trả về đúng format content blocks
            return [
                {
                    "type": "text",
                    "text": f"🖼️ Ảnh ({size_kb} KB | {content_type})\nURL: {image_url}",
                },
                {
                    "type"  : "image",
                    "source": {
                        "type"      : "base64",
                        "media_type": content_type,
                        "data"      : b64,
                    },
                },
            ]
        except httpx.TimeoutException:
            return "❌ Timeout khi tải ảnh (quá 15 giây)."
        except httpx.ConnectError:
            return "❌ Không thể kết nối đến URL ảnh."
        except Exception as e:
            return f"❌ Lỗi tải ảnh: {str(e)[:100]}"

    # ── get_question_by_answer_id ─────────────────────────────────────────────
    if tool == "get_question_by_answer_id":
        answer_id = inp.get("answer_id", "").strip()
        if not answer_id:
            return "❌ Thiếu answer_id."
        a = supabase.table("answers")\
            .select("id,question_id,body,user_id,moderation_status,removed_reason,profiles(username)")\
            .eq("id", answer_id).single().execute()
        if not a.data:
            return "Không tìm thấy câu trả lời."
        question_id = a.data.get("question_id")
        if not question_id:
            return "❌ Câu trả lời này không có question_id."
        q = supabase.table("questions")\
            .select("*,profiles(username)")\
            .eq("id", question_id).single().execute()
        if not q.data:
            return f"❌ Không tìm thấy câu hỏi cha (question_id: {question_id})."
        qd = q.data
        ad = a.data
        return (
            f"🔗 **NGỮ CẢNH: Answer → Question**\n\n"
            f"💬 **CÂU TRẢ LỜI** `{ad['id']}`\n"
            f"👤 {ad['profiles']['username'] if ad.get('profiles') else '?'}\n"
            f"📄 {ad.get('body','')[:200]}\n"
            f"📊 {ad.get('moderation_status','')} | 🚩 {ad.get('removed_reason') or '(chưa gắn cờ)'}\n\n"
            f"📚 **CÂU HỎI CHA** `{qd['id']}`\n"
            f"👤 {qd['profiles']['username'] if qd.get('profiles') else '?'}\n"
            f"📌 {qd.get('grade_group','')} | {qd.get('subject','')}\n"
            f"📋 {qd.get('title','')}\n"
            f"📄 {qd.get('body','') or '(không có)'}\n"
            f"🖼️  {qd.get('image_url') or '(không có ảnh)'}\n"
            f"📊 {qd.get('status','')} | 👁️  {qd.get('views',0)} lượt\n"
            f"🕐 {qd.get('created_at','')[:16]}\n\n"
            f"💡 Dùng remove_content với ref_id=`{qd['id']}` ref_type='question' nếu muốn xóa câu hỏi cha."
        )

    if tool == "approve_content":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        reason   = inp.get("reason","Admin duyệt hợp lệ")
        if ref_type == "question":
            r = supabase.table("questions").select("user_id,title")\
                .eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu hỏi."
            supabase.table("questions").update({
                "status":"open","removed_by_ai":False,"removed_reason":None,
            }).eq("id", ref_id).execute()
            send_notification(r.data["user_id"],"appeal_approved",
                "✅ Câu hỏi được duyệt",
                f'Câu hỏi "{r.data.get("title","")[:50]}" đã được admin duyệt. Lý do: {reason}',
                ref_id,"question")
        else:
            r = supabase.table("answers").select("user_id,question_id")\
                .eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu trả lời."
            supabase.table("answers").update({
                "moderation_status":"approved","removed_by_ai":False,"removed_reason":None,
            }).eq("id", ref_id).execute()
            _notify_new_answer({"id":ref_id,"user_id":r.data["user_id"],
                                "question_id":r.data["question_id"]})
            send_notification(r.data["user_id"],"appeal_approved",
                "✅ Câu trả lời được duyệt",
                f'Câu trả lời của bạn đã được admin duyệt. Lý do: {reason}',
                ref_id,"answer")
        return f"✅ Đã duyệt {ref_type} `{ref_id[:8]}`."

    if tool == "remove_content":
        ref_id    = inp.get("ref_id","")
        ref_type  = inp.get("ref_type","")
        reason    = inp.get("reason","Admin xóa nội dung vi phạm")
        report_id = inp.get("report_id","")
        if ref_type == "question":
            r = supabase.table("questions").select("user_id,points_cost,title")\
                .eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu hỏi."
            supabase.table("questions").update({
                "status":"removed","removed_by_ai":True,
                "removed_reason":f"Admin: {reason}",
            }).eq("id", ref_id).execute()
            _refund_points(r.data["user_id"], r.data.get("points_cost",0), ref_id)
            _log_violation(r.data["user_id"], ref_id, "question", "REMOVED", f"Admin: {reason}")
            send_notification(r.data["user_id"],"content_removed",
                "⚠️ Câu hỏi bị xóa bởi Admin",
                f'Câu hỏi "{r.data.get("title","")[:50]}" bị Admin xóa. '
                f'Lý do: {reason}. Bạn có thể kháng cáo.',
                ref_id,"question")
        else:
            r = supabase.table("answers").select("user_id,body")\
                .eq("id", ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu trả lời."
            supabase.table("answers").update({
                "moderation_status":"removed","removed_by_ai":True,
                "removed_reason":f"Admin: {reason}",
                "removed_content":r.data.get("body","")[:1000],
            }).eq("id", ref_id).execute()
            _log_violation(r.data["user_id"], ref_id, "answer", "REMOVED", f"Admin: {reason}")
            send_notification(r.data["user_id"],"content_removed",
                "⚠️ Câu trả lời bị xóa bởi Admin",
                f'Câu trả lời của bạn bị Admin xóa. Lý do: {reason}. Bạn có thể kháng cáo.',
                ref_id,"answer")
        if report_id:
            supabase.table("reports").update({"status":"resolved"})\
                .eq("id", report_id).execute()
        return f"🚫 Đã xóa {ref_type} `{ref_id[:8]}`."

    if tool == "approve_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin chấp nhận kháng cáo")
        ap = supabase.table("appeals").select("*").eq("id", appeal_id).single().execute()
        if not ap.data: return "Không tìm thấy kháng cáo."
        a = ap.data
        supabase.table("appeals").update({
            "status":"approved","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id", appeal_id).execute()
        if a["ref_type"] == "question":
            q = supabase.table("questions").select("user_id,points_cost")\
                .eq("id", a["ref_id"]).single().execute()
            supabase.table("questions").update({
                "status":"open","removed_by_ai":False,"removed_reason":None,
            }).eq("id", a["ref_id"]).execute()
            if q.data and q.data.get("points_cost"):
                _refund_points(q.data["user_id"], q.data["points_cost"], a["ref_id"])
        else:
            supabase.table("answers").update({
                "moderation_status":"approved","removed_by_ai":False,"removed_reason":None,
            }).eq("id", a["ref_id"]).execute()
        send_notification(a["user_id"],"appeal_approved",
            "✅ Kháng cáo thành công! (Admin duyệt)",
            f'Admin chấp nhận kháng cáo. Nội dung đã được khôi phục. Lý do: {reason}',
            a["ref_id"],a["ref_type"],appeal_id)
        return f"✅ Đã chấp nhận kháng cáo `{appeal_id[:8]}`."

    if tool == "reject_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin từ chối kháng cáo")
        ap = supabase.table("appeals").select("*").eq("id", appeal_id).single().execute()
        if not ap.data: return "Không tìm thấy kháng cáo."
        supabase.table("appeals").update({
            "status":"rejected","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id", appeal_id).execute()
        send_notification(ap.data["user_id"],"appeal_rejected",
            "❌ Kháng cáo không thành công (Admin duyệt)",
            f'Admin không chấp nhận kháng cáo. Lý do: {reason}',
            ap.data["ref_id"],ap.data["ref_type"],appeal_id)
        return f"❌ Đã từ chối kháng cáo `{appeal_id[:8]}`."

    if tool == "resolve_report":
        report_id    = inp.get("report_id","")
        action_taken = inp.get("action_taken", False)
        reason       = inp.get("reason","")
        rep = supabase.table("reports").select("*").eq("id", report_id).single().execute()
        if not rep.data: return "Không tìm thấy báo cáo."
        r = rep.data
        supabase.table("reports").update({"status":"resolved"})\
            .eq("id", report_id).execute()
        if r.get("reporter_id"):
            if action_taken:
                send_notification(r["reporter_id"],"report_resolved",
                    "✅ Báo cáo đã được xử lý",
                    f'Admin đã xử lý nội dung vi phạm. Lý do: {reason}',
                    r["ref_id"],r["ref_type"])
            else:
                send_notification(r["reporter_id"],"report_resolved",
                    "ℹ️ Báo cáo đã được xem xét",
                    f'Admin không phát hiện vi phạm. Lý do: {reason}',
                    r["ref_id"],r["ref_type"])
        return f"✅ Đã resolve report `{report_id[:8]}`."

    if tool == "get_stats":
        logs = supabase.table("moderation_logs").select("label").execute()
        rpts = supabase.table("reports").select("status").execute()
        apps = supabase.table("appeals").select("status").execute()
        qp   = supabase.table("questions").select("id",count="exact")\
               .eq("status","pending").not_.is_("removed_reason","null").execute()
        ap   = supabase.table("answers").select("id",count="exact")\
               .eq("moderation_status","pending").not_.is_("removed_reason","null").execute()
        r_counts = Counter(r["status"] for r in (rpts.data or []))
        a_counts = Counter(a["status"] for a in (apps.data or []))
        l_counts = Counter(l["label"]  for l in (logs.data or []))
        return (
            f"📊 THỐNG KÊ\n\n"
            f"⏳ Chờ admin duyệt:\n"
            f"  Câu hỏi gắn cờ: {qp.count or 0}\n"
            f"  Câu trả lời gắn cờ: {ap.count or 0}\n"
            f"  Báo cáo pending: {r_counts.get('pending',0)}\n"
            f"  Kháng cáo pending: {a_counts.get('pending',0)}\n\n"
            f"🚫 Vi phạm đã xử lý: {len(logs.data or [])}\n"
            + "\n".join(f"  {k}: {v}" for k,v in l_counts.items()) +
            f"\n\n🚩 Báo cáo:\n"
            + "\n".join(f"  {k}: {v}" for k,v in r_counts.items()) +
            f"\n\n⚖️ Kháng cáo:\n"
            + "\n".join(f"  {k}: {v}" for k,v in a_counts.items())
        )

    return f"Tool '{tool}' không tồn tại."

# ── Hard Rules ────────────────────────────────────────────────────────────────
def hard_rules(text: str) -> tuple:
    t = text.strip()
    if len(t) < 2:               return "MEANINGLESS", "Quá ngắn"
    if re.match(r'^(.)\1+$', t): return "MEANINGLESS", "Ký tự lặp"
    if re.match(r'^\d+$', t):    return "MEANINGLESS", "Toàn số"
    if not re.search(
        r'[a-zA-Zàáảãạăắặẳẵậâấầẩẫèéẻẽẹêếềểễệ'
        r'ìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]',
        t, re.IGNORECASE
    ): return "MEANINGLESS", "Không có chữ cái"
    SUSPICIOUS_PATTERNS = [
        r'(?i)(sex|porn|18\+|địt|lồn|cặc|đụ|fuck|shit)',
        r'(?i)(quảng cáo|mua ngay|liên hệ zalo|telegram|t\.me/)',
        r'https?://\S+',
        r'\b0\d{9,10}\b',
    ]
    for p in SUSPICIOUS_PATTERNS:
        if re.search(p, t):
            return "SUSPICIOUS", f"Khớp pattern: {p}"
    return None, ""

# ── Helpers ───────────────────────────────────────────────────────────────────
def send_notification(user_id, ntype, title, message,
                      ref_id=None, ref_type=None, appeal_id=None):
    try:
        supabase.table("notifications").insert({
            "user_id":user_id,"type":ntype,"title":title,"message":message,
            "ref_id":ref_id,"ref_type":ref_type,"appeal_id":appeal_id,
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Notification error: {e}")

def _refund_points(user_id, amount, ref_id):
    if not amount: return
    try:
        p = supabase.table("profiles").select("points")\
            .eq("id", user_id).single().execute()
        if p.data:
            supabase.table("profiles")\
                .update({"points": p.data["points"] + amount})\
                .eq("id", user_id).execute()
            supabase.table("point_transactions").insert({
                "user_id":user_id,"amount":amount,
                "reason":"refund_violation","ref_id":ref_id,
            }).execute()
    except Exception as e:
        print(f"  ⚠️  Refund error: {e}")

def _log_violation(user_id, ref_id, ref_type, label, reason):
    try:
        supabase.table("moderation_logs").insert({
            "user_id":user_id,"ref_id":ref_id,"ref_type":ref_type,
            "label":label,"reason":reason,"action":"flagged",
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Log error: {e}")

def _notify_new_answer(answer):
    try:
        q = supabase.table("questions").select("id,title,user_id")\
            .eq("id", answer["question_id"]).single().execute()
        if q.data and q.data["user_id"] != answer["user_id"]:
            send_notification(q.data["user_id"],"answer_posted",
                "💬 Có câu trả lời mới!",
                f'Câu hỏi "{q.data["title"][:50]}..." vừa nhận được câu trả lời mới.',
                q.data["id"],"question")
    except Exception as e:
        print(f"  ⚠️  Notify answer error: {e}")

# ── Background Scanner ────────────────────────────────────────────────────────
async def scanner_loop():
    print(f"🔍 Scanner started!")
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
        qs  = supabase.table("questions").select("id,title,body,user_id,points_cost")\
              .eq("status","pending").limit(BATCH_SIZE).execute()
        ans = supabase.table("answers").select("id,body,user_id,question_id")\
              .eq("moderation_status","pending").limit(BATCH_SIZE).execute()
        rps = supabase.table("reports").select("id,ref_id,ref_type,reason,reporter_id")\
              .eq("status","pending").limit(BATCH_SIZE).execute()

        items = []
        for q in (qs.data  or []): items.append(("question", q))
        for a in (ans.data or []): items.append(("answer",   a))
        for r in (rps.data or []): items.append(("report",   r))

        if items:
            loop = asyncio.get_event_loop()
            for itype, data in items:
                await loop.run_in_executor(
                    None, lambda i=itype, d=data: process_item(i, d))
    except Exception as e:
        print(f"❌ scan_batch: {e}")

def process_item(itype, data):
    try:
        if itype == "report":
            reporter_id = data.get("reporter_id")
            if reporter_id:
                send_notification(reporter_id,"report_resolved",
                    "📨 Báo cáo đã được tiếp nhận",
                    "Báo cáo của bạn đã được ghi nhận và sẽ được admin xem xét sớm.",
                    data["ref_id"],data["ref_type"])
            print(f"  🚩 Report {data['id'][:8]} → chờ admin")
            return

        text  = f"{data['title']} {data.get('body','') or ''}" \
                if itype == "question" else data["body"]
        label, reason = hard_rules(text)

        if label in ("MEANINGLESS", "SUSPICIOUS"):
            if itype == "question":
                supabase.table("questions").update({
                    "status":"pending",
                    "removed_reason":f"[Chờ admin] {label}: {reason}",
                }).eq("id", data["id"]).execute()
            else:
                supabase.table("answers").update({
                    "moderation_status":"pending",
                    "removed_reason":f"[Chờ admin] {label}: {reason}",
                }).eq("id", data["id"]).execute()
            _log_violation(data["user_id"], data["id"], itype, label, reason)
            print(f"  🚩 [{itype}] {data['id'][:8]} → flagged")
        else:
            if itype == "question":
                supabase.table("questions")\
                    .update({"status":"open","removed_by_ai":False})\
                    .eq("id", data["id"]).execute()
            else:
                supabase.table("answers")\
                    .update({"moderation_status":"approved","removed_by_ai":False})\
                    .eq("id", data["id"]).execute()
                _notify_new_answer(data)
            print(f"  ✅ [{itype}] {data['id'][:8]} → approved")
    except Exception as e:
        print(f"  ❌ process error: {e}")

# ── JSON-RPC handler dùng chung ───────────────────────────────────────────────
async def handle_jsonrpc(request: Request) -> dict:
    body   = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id"     : req_id,
            "result" : {
                "protocolVersion": "2024-11-05",
                "capabilities"   : {"tools": {}},
                "serverInfo"     : {"name":"hoibai-panel","version":"5.0.0"},
            }
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id"     : req_id,
            "result" : {"tools": MCP_TOOLS},
        }

    if method == "tools/call":
        params    = body.get("params", {})
        tool_name = params.get("name", "")
        tool_inp  = params.get("arguments", {})

        if not supabase:
            return {
                "jsonrpc": "2.0",
                "id"     : req_id,
                "result" : {
                    "content": [{"type":"text","text":"⚠️ Supabase chưa kết nối."}],
                    "isError": True,
                }
            }

        try:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: execute_tool(tool_name, tool_inp)
            )
            # FIX: Kiểm tra type của result đúng cách
            # result có thể là str (text) hoặc list (image blocks)
            if isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict):
                # Đây là content blocks (từ get_image)
                content = result
            else:
                # Đây là string
                content = [{"type":"text","text": str(result)}]
            
            return {
                "jsonrpc": "2.0",
                "id"     : req_id,
                "result" : {"content": content, "isError": False},
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id"     : req_id,
                "result" : {
                    "content": [{"type":"text","text":f"❌ Lỗi: {str(e)[:200]}"}],
                    "isError": True,
                }
            }

    if method == "ping":
        return {"jsonrpc":"2.0","id":req_id,"result":{}}

    return {
        "jsonrpc": "2.0",
        "id"     : req_id,
        "error"  : {"code":-32601,"message":f"Method '{method}' not found"},
    }

# ── MCP endpoints ─────────────────────────────────────────────────────────────
@app.get("/mcp")
async def mcp_info():
    return {
        "jsonrpc": "2.0",
        "result" : {
            "protocolVersion": "2024-11-05",
            "capabilities"   : {"tools": {}},
            "serverInfo"     : {"name":"hoibai-panel","version":"5.0.0"},
        }
    }

@app.post("/mcp")
async def mcp_endpoint(request: Request,
                       authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Unauthorized")
    return await handle_jsonrpc(request)

@app.post("/messages")
async def messages_endpoint(request: Request,
                            authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Unauthorized")
    return await handle_jsonrpc(request)

@app.get("/sse")
async def sse_endpoint(request: Request,
                       authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Unauthorized")

    async def event_stream():
        init = {
            "jsonrpc": "2.0",
            "method" : "notifications/initialized",
            "params" : {
                "protocolVersion": "2024-11-05",
                "capabilities"   : {"tools": {}},
                "serverInfo"     : {"name":"hoibai-panel","version":"5.0.0"},
            }
        }
        yield f"data: {json.dumps(init, ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'jsonrpc':'2.0','method':'notifications/tools/list_changed','params':{}}, ensure_ascii=False)}\n\n"
        while True:
            if await request.is_disconnected():
                break
            yield f": ping\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control"              : "no-cache",
            "X-Accel-Buffering"          : "no",
            "Access-Control-Allow-Origin": "*",
        }
    )

# ── REST endpoints ────────────────────────────────────────────────────────────
class ModerateRequest(BaseModel):
    text   : str
    context: str = "question"

class ModerateResponse(BaseModel):
    label  : str
    allowed: bool
    reason : str

@app.post("/moderate", response_model=ModerateResponse)
async def moderate(req: ModerateRequest):
    label, reason = hard_rules(req.text.strip())
    if label in ("MEANINGLESS", "SUSPICIOUS"):
        return ModerateResponse(label=label, allowed=False, reason=reason)
    return ModerateResponse(label="CLEAN", allowed=True, reason="Passed rules")

@app.get("/health")
async def health():
    counts = {}
    if supabase:
        try:
            qp = supabase.table("questions").select("id",count="exact")\
                .eq("status","pending").not_.is_("removed_reason","null").execute()
            ap = supabase.table("answers").select("id",count="exact")\
                .eq("moderation_status","pending").not_.is_("removed_reason","null").execute()
            rp = supabase.table("reports").select("id",count="exact")\
                .eq("status","pending").execute()
            pp = supabase.table("appeals").select("id",count="exact")\
                .eq("status","pending").execute()
            counts = {
                "questions_flagged": qp.count or 0,
                "answers_flagged"  : ap.count or 0,
                "reports_pending"  : rp.count or 0,
                "appeals_pending"  : pp.count or 0,
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
        "mcp_url": f"{BASE_URL}/mcp",
    }
