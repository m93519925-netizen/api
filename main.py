import os, re, asyncio, hashlib, time, base64, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import Counter

from fastapi import FastAPI, Header, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL  = os.getenv("SUPABASE_URL",         "")
SUPABASE_KEY  = os.getenv("SUPABASE_SERVICE_KEY", "")
ADMIN_TOKEN   = os.getenv("ADMIN_TOKEN",          "hoibai-admin-secret")
BASE_URL      = os.getenv("BASE_URL",             "https://api-production-a365.up.railway.app")
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

app = FastAPI(title="HoiBai Moderator (MCP)", version="5.1.0", lifespan=lifespan)
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
    client_id             : str = "",
    redirect_uri          : str = "",
    state                 : str = "",
    code_challenge        : str = "",
    code_challenge_method : str = "",
):
    code = hashlib.sha256(f"{ADMIN_TOKEN}{time.time()}".encode()).hexdigest()[:32]
    _auth_codes[code] = {
        "code_challenge": code_challenge,
        "expires"       : time.time() + 300,
    }
    url = f"{redirect_uri}?code={code}"
    if state: url += f"&state={state}"
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
    for k in expired: del _auth_codes[k]
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

# ── MCP Tools ─────────────────────────────────────────────────────────────────
MCP_TOOLS = [
    {
        "name"       : "list_flagged",
        "description": "Liệt kê câu hỏi/câu trả lời bị gắn cờ chờ admin duyệt",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type":"string","description":"'question','answer','all'"}
            }
        },
    },
    {
        "name"       : "list_pending_reports",
        "description": "Liệt kê báo cáo vi phạm đang chờ admin xử lý",
        "inputSchema": {"type":"object","properties":{}},
    },
    {
        "name"       : "list_pending_appeals",
        "description": "Liệt kê kháng cáo nội dung (câu hỏi/câu trả lời) đang chờ admin duyệt",
        "inputSchema": {"type":"object","properties":{}},
    },
    {
        "name"       : "list_ban_appeals",
        "description": "Liệt kê kháng cáo xóa/khóa tài khoản đang chờ xét duyệt",
        "inputSchema": {"type":"object","properties":{}},
    },
    {
        "name"       : "get_content_detail",
        "description": "Xem chi tiết câu hỏi hoặc câu trả lời kèm ảnh",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref_id"  : {"type":"string","description":"ID nội dung"},
                "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
            },
            "required": ["ref_id","ref_type"],
        },
    },
    {
        "name"       : "get_question_by_answer_id",
        "description": "Lấy câu hỏi cha từ ID câu trả lời",
        "inputSchema": {
            "type": "object",
            "properties": {
                "answer_id": {"type":"string","description":"ID câu trả lời"},
            },
            "required": ["answer_id"],
        },
    },
    {
        "name"       : "get_user_history",
        "description": "Xem toàn bộ lịch sử vi phạm, câu hỏi/trả lời bị xóa của user — dùng để xét kháng cáo ban",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type":"string","description":"ID người dùng"},
            },
            "required": ["user_id"],
        },
    },
    {
        "name"       : "approve_content",
        "description": "Duyệt nội dung — cho hiển thị",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref_id"  : {"type":"string"},
                "ref_type": {"type":"string"},
                "reason"  : {"type":"string"},
            },
            "required": ["ref_id","ref_type"],
        },
    },
    {
        "name"       : "remove_content",
        "description": "Xóa nội dung vi phạm",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref_id"   : {"type":"string"},
                "ref_type" : {"type":"string"},
                "reason"   : {"type":"string"},
                "report_id": {"type":"string","description":"ID report liên quan (nếu có)"},
            },
            "required": ["ref_id","ref_type","reason"],
        },
    },
    {
        "name"       : "approve_appeal",
        "description": "Chấp nhận kháng cáo nội dung (câu hỏi/câu trả lời) — khôi phục",
        "inputSchema": {
            "type": "object",
            "properties": {
                "appeal_id": {"type":"string"},
                "reason"   : {"type":"string"},
            },
            "required": ["appeal_id","reason"],
        },
    },
    {
        "name"       : "reject_appeal",
        "description": "Từ chối kháng cáo nội dung (câu hỏi/câu trả lời)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "appeal_id": {"type":"string"},
                "reason"   : {"type":"string"},
            },
            "required": ["appeal_id","reason"],
        },
    },
    {
        "name"       : "approve_ban_appeal",
        "description": "Chấp nhận kháng cáo xóa/khóa tài khoản — mở khóa",
        "inputSchema": {
            "type": "object",
            "properties": {
                "appeal_id": {"type":"string"},
                "reason"   : {"type":"string"},
            },
            "required": ["appeal_id","reason"],
        },
    },
    {
        "name"       : "reject_ban_appeal",
        "description": "Từ chối kháng cáo xóa/khóa tài khoản — giữ khóa",
        "inputSchema": {
            "type": "object",
            "properties": {
                "appeal_id": {"type":"string"},
                "reason"   : {"type":"string"},
            },
            "required": ["appeal_id","reason"],
        },
    },
    {
        "name"       : "resolve_report",
        "description": "Đánh dấu báo cáo đã xử lý và thông báo người báo cáo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_id"   : {"type":"string"},
                "action_taken": {"type":"boolean","description":"true=đã xóa, false=không vi phạm"},
                "reason"      : {"type":"string"},
            },
            "required": ["report_id","action_taken","reason"],
        },
    },
    {
        "name"       : "ban_user",
        "description": "Cảnh báo hoặc khóa tài khoản người dùng",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type":"string"},
                "reason" : {"type":"string"},
                "level"  : {"type":"integer","description":"1=cảnh báo vàng, 2=nghiêm trọng đỏ, 3=khóa"},
            },
            "required": ["user_id","reason","level"],
        },
    },
    {
        "name"       : "unban_user",
        "description": "Mở khóa tài khoản bị khóa",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type":"string"},
                "reason" : {"type":"string"},
            },
            "required": ["user_id","reason"],
        },
    },
    {
        "name"       : "get_stats",
        "description": "Thống kê tổng quan hệ thống",
        "inputSchema": {"type":"object","properties":{}},
    },
]

# ── Tool Executor ─────────────────────────────────────────────────────────────
def execute_tool(tool: str, inp: dict) -> str:

    # ── list_flagged ──────────────────────────────────────────────────────────
    if tool == "list_flagged":
        ctype = inp.get("type","all")
        lines = []
        if ctype in ("question","all"):
            r = supabase.table("questions")\
                .select("id,title,user_id,removed_reason,created_at,profiles(username)")\
                .eq("status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at",desc=False).limit(20).execute()
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
        if ctype in ("answer","all"):
            r = supabase.table("answers")\
                .select("id,body,user_id,removed_reason,created_at,profiles(username)")\
                .eq("moderation_status","pending")\
                .not_.is_("removed_reason","null")\
                .order("created_at",desc=False).limit(20).execute()
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
        return "\n".join(lines) if lines else "✅ Không có nội dung bị gắn cờ."

    # ── list_pending_reports ──────────────────────────────────────────────────
    if tool == "list_pending_reports":
        r = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,detail,created_at,profiles(username)")\
            .eq("status","processing")\
            .order("created_at",desc=False).limit(20).execute()
        if not r.data:
            return "✅ Không có báo cáo nào đang chờ xử lý."
        lines = [f"🚩 **{len(r.data)} báo cáo đang chờ:**\n"]
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

    # ── list_pending_appeals ──────────────────────────────────────────────────
    # Đồng bộ với appeal.php: bảng 'appeals' chứa CẢ kháng cáo nội dung
    # (ref_type='question'/'answer') LẪN kháng cáo tài khoản (ref_type='account').
    # Tool này chỉ lấy kháng cáo nội dung; kháng cáo tài khoản dùng list_ban_appeals.
    if tool == "list_pending_appeals":
        r = supabase.table("appeals")\
            .select("id,user_id,ref_id,ref_type,content,created_at,profiles(username)")\
            .eq("status","pending")\
            .in_("ref_type",["question","answer"])\
            .order("created_at",desc=False).limit(20).execute()
        if not r.data:
            return "✅ Không có kháng cáo nội dung nào đang chờ."
        lines = [f"⚖️  **{len(r.data)} kháng cáo nội dung đang chờ:**\n"]
        for a in r.data:
            lines.append(
                f"🆔 `{a['id']}`\n"
                f"👤 {a['profiles']['username'] if a.get('profiles') else a['user_id'][:8]}\n"
                f"📌 {a['ref_type']} | `{a['ref_id']}`\n"
                f"💬 {a['content'][:300]}\n"
                f"🕐 {a['created_at'][:16]}\n---"
            )
        return "\n".join(lines)

    # ── list_ban_appeals ──────────────────────────────────────────────────────
    # appeal.php (type=account, gọi từ banned.php) insert vào CÙNG bảng 'appeals'
    # với ref_type='account' — không có bảng 'ban_appeals' riêng trong hệ PHP.
    if tool == "list_ban_appeals":
        r = supabase.table("appeals")\
            .select("id,user_id,content,created_at,profiles(username,violation_level)")\
            .eq("status","pending")\
            .eq("ref_type","account")\
            .order("created_at",desc=False).limit(20).execute()
        if not r.data:
            return "✅ Không có kháng cáo ban nào đang chờ."
        lines = [f"🔒 **{len(r.data)} kháng cáo ban đang chờ:**\n"]
        for a in r.data:
            lines.append(
                f"🆔 `{a['id']}`\n"
                f"👤 {a['profiles']['username'] if a.get('profiles') else a['user_id'][:8]}\n"
                f"📊 Mức vi phạm: {a['profiles']['violation_level'] if a.get('profiles') else '?'}\n"
                f"💬 {a['content'][:300]}\n"
                f"🕐 {a['created_at'][:16]}\n---"
            )
        return "\n".join(lines)

    # ── get_content_detail ────────────────────────────────────────────────────
    if tool == "get_content_detail":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        if ref_type == "question":
            r = supabase.table("questions")\
                .select("*,profiles(username)").eq("id",ref_id).single().execute()
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
                .eq("id",ref_id).single().execute()
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

    # ── get_question_by_answer_id ─────────────────────────────────────────────
    if tool == "get_question_by_answer_id":
        answer_id = inp.get("answer_id","").strip()
        a = supabase.table("answers")\
            .select("id,question_id,body,user_id,moderation_status,removed_reason,profiles(username)")\
            .eq("id",answer_id).single().execute()
        if not a.data: return "Không tìm thấy câu trả lời."
        question_id = a.data.get("question_id")
        if not question_id: return "Câu trả lời này không có question_id."
        q = supabase.table("questions")\
            .select("*,profiles(username)").eq("id",question_id).single().execute()
        if not q.data: return f"Không tìm thấy câu hỏi cha."
        qd, ad = q.data, a.data
        return (
            f"🔗 **Answer → Question**\n\n"
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
            f"💡 remove_content ref_id=`{qd['id']}` ref_type='question' để xóa câu hỏi cha."
        )

    # ── get_user_history ──────────────────────────────────────────────────────
    if tool == "get_user_history":
        user_id = inp.get("user_id","")
        profile = supabase.table("profiles")\
            .select("username,violation_level,is_banned,ban_reason,points")\
            .eq("id",user_id).single().execute()
        logs = supabase.table("moderation_logs")\
            .select("label,reason,ref_type,created_at")\
            .eq("user_id",user_id)\
            .order("created_at",desc=True).limit(30).execute()
        removed_q = supabase.table("questions")\
            .select("id,title,removed_reason,created_at")\
            .eq("user_id",user_id).eq("status","removed")\
            .limit(10).execute()
        removed_a = supabase.table("answers")\
            .select("id,body,removed_reason,created_at")\
            .eq("user_id",user_id).eq("moderation_status","removed")\
            .limit(10).execute()

        p = profile.data or {}
        vl_map = {0:"✅ Bình thường",1:"⚠️ Cảnh báo",2:"🔴 Nghiêm trọng",3:"🔒 Bị khóa"}

        result = (
            f"👤 **LỊCH SỬ USER** `{user_id[:8]}`\n"
            f"  Tên: {p.get('username','?')}\n"
            f"  Trạng thái: {vl_map.get(p.get('violation_level',0),'?')}\n"
            f"  Bị khóa: {'Có - '+p.get('ban_reason','?') if p.get('is_banned') else 'Không'}\n"
            f"  Điểm: {p.get('points',0)}\n\n"
        )
        if removed_q.data:
            result += f"📚 **{len(removed_q.data)} câu hỏi bị xóa:**\n"
            for q in removed_q.data:
                result += f"  - {q.get('title','')[:80]} | {q.get('removed_reason','')}\n"
        if removed_a.data:
            result += f"\n💬 **{len(removed_a.data)} câu trả lời bị xóa:**\n"
            for a in removed_a.data:
                result += f"  - {a.get('body','')[:80]} | {a.get('removed_reason','')}\n"
        if logs.data:
            result += f"\n📋 **Lịch sử vi phạm ({len(logs.data)}):**\n"
            for l in logs.data:
                result += f"  [{l['ref_type']}] {l['label']}: {l['reason']} ({l['created_at'][:10]})\n"
        return result

    # ── approve_content ───────────────────────────────────────────────────────
    if tool == "approve_content":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        reason   = inp.get("reason","Admin duyệt hợp lệ")
        if ref_type == "question":
            r = supabase.table("questions").select("user_id,title")\
                .eq("id",ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu hỏi."
            supabase.table("questions").update({
                "status":"open","removed_by_ai":False,"removed_reason":None,
            }).eq("id",ref_id).execute()
            send_notification(r.data["user_id"],"appeal_approved",
                "✅ Câu hỏi được duyệt",
                f'Câu hỏi "{r.data.get("title","")[:50]}" được admin duyệt. Lý do: {reason}',
                ref_id,"question")
        else:
            r = supabase.table("answers").select("user_id,question_id")\
                .eq("id",ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu trả lời."
            supabase.table("answers").update({
                "moderation_status":"approved","removed_by_ai":False,"removed_reason":None,
            }).eq("id",ref_id).execute()
            _notify_new_answer({
                "id":ref_id,
                "user_id":r.data["user_id"],
                "question_id":r.data["question_id"]
            })
            send_notification(r.data["user_id"],"appeal_approved",
                "✅ Câu trả lời được duyệt",
                f'Câu trả lời được admin duyệt. Lý do: {reason}',
                ref_id,"answer")
        return f"✅ Đã duyệt {ref_type} `{ref_id[:8]}`."

    # ── remove_content ────────────────────────────────────────────────────────
    if tool == "remove_content":
        ref_id    = inp.get("ref_id","")
        ref_type  = inp.get("ref_type","")
        reason    = inp.get("reason","Admin xóa vi phạm")
        report_id = inp.get("report_id","")
        if ref_type == "question":
            r = supabase.table("questions").select("user_id,points_cost,title")\
                .eq("id",ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu hỏi."
            supabase.table("questions").update({
                "status":"removed","removed_by_ai":True,
                "removed_reason":f"Admin: {reason}",
            }).eq("id",ref_id).execute()
            _refund_points(r.data["user_id"],r.data.get("points_cost",0),ref_id)
            _log_violation(r.data["user_id"],ref_id,"question","REMOVED",f"Admin: {reason}")
            send_notification(r.data["user_id"],"content_removed",
                "⚠️ Câu hỏi bị xóa bởi Admin",
                f'Câu hỏi "{r.data.get("title","")[:50]}" bị Admin xóa. Lý do: {reason}. Bạn có thể kháng cáo.',
                ref_id,"question")
        else:
            r = supabase.table("answers").select("user_id,body")\
                .eq("id",ref_id).single().execute()
            if not r.data: return "Không tìm thấy câu trả lời."
            supabase.table("answers").update({
                "moderation_status":"removed","removed_by_ai":True,
                "removed_reason":f"Admin: {reason}",
                "removed_content":r.data.get("body","")[:1000],
            }).eq("id",ref_id).execute()
            _log_violation(r.data["user_id"],ref_id,"answer","REMOVED",f"Admin: {reason}")
            send_notification(r.data["user_id"],"content_removed",
                "⚠️ Câu trả lời bị xóa bởi Admin",
                f'Câu trả lời bị Admin xóa. Lý do: {reason}. Bạn có thể kháng cáo.',
                ref_id,"answer")
        if report_id:
            supabase.table("reports").update({"status":"resolved"})\
                .eq("id",report_id).execute()
        return f"🚫 Đã xóa {ref_type} `{ref_id[:8]}`."

    # ── approve_appeal (chỉ kháng cáo nội dung: question/answer) ────────────────
    if tool == "approve_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin chấp nhận kháng cáo")
        ap = supabase.table("appeals").select("*")\
            .eq("id",appeal_id).in_("ref_type",["question","answer"]).single().execute()
        if not ap.data:
            return "Không tìm thấy kháng cáo nội dung (nếu là kháng cáo tài khoản, dùng approve_ban_appeal)."
        a = ap.data
        supabase.table("appeals").update({
            "status":"approved","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id",appeal_id).execute()
        if a["ref_type"] == "question":
            q = supabase.table("questions").select("user_id,points_cost")\
                .eq("id",a["ref_id"]).single().execute()
            supabase.table("questions").update({
                "status":"open","removed_by_ai":False,"removed_reason":None,
            }).eq("id",a["ref_id"]).execute()
            if q.data and q.data.get("points_cost"):
                _refund_points(q.data["user_id"],q.data["points_cost"],a["ref_id"])
        else:
            supabase.table("answers").update({
                "moderation_status":"approved","removed_by_ai":False,"removed_reason":None,
            }).eq("id",a["ref_id"]).execute()
        send_notification(a["user_id"],"appeal_approved",
            "✅ Kháng cáo thành công! (Admin duyệt)",
            f'Admin chấp nhận kháng cáo. Nội dung khôi phục. Lý do: {reason}',
            a["ref_id"],a["ref_type"],appeal_id)
        return f"✅ Đã chấp nhận kháng cáo `{appeal_id[:8]}`."

    # ── reject_appeal (chỉ kháng cáo nội dung: question/answer) ─────────────────
    if tool == "reject_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin từ chối")
        ap = supabase.table("appeals").select("*")\
            .eq("id",appeal_id).in_("ref_type",["question","answer"]).single().execute()
        if not ap.data:
            return "Không tìm thấy kháng cáo nội dung (nếu là kháng cáo tài khoản, dùng reject_ban_appeal)."
        supabase.table("appeals").update({
            "status":"rejected","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id",appeal_id).execute()
        send_notification(ap.data["user_id"],"appeal_rejected",
            "❌ Kháng cáo không thành công (Admin duyệt)",
            f'Admin không chấp nhận kháng cáo. Lý do: {reason}',
            ap.data["ref_id"],ap.data["ref_type"],appeal_id)
        return f"❌ Đã từ chối kháng cáo `{appeal_id[:8]}`."

    # ── approve_ban_appeal (chỉ kháng cáo tài khoản: ref_type='account') ────────
    if tool == "approve_ban_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin chấp nhận kháng cáo ban")
        ap = supabase.table("appeals").select("*")\
            .eq("id",appeal_id).eq("ref_type","account").single().execute()
        if not ap.data:
            return "Không tìm thấy kháng cáo ban (kiểm tra lại appeal_id, hoặc đây là kháng cáo nội dung — dùng approve_appeal)."
        supabase.table("appeals").update({
            "status":"approved","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id",appeal_id).execute()
        supabase.table("profiles").update({
            "violation_level"   : 0,
            "is_banned"         : False,
            "ban_reason"        : None,
            "redemption_points" : 0,
        }).eq("id",ap.data["user_id"]).execute()
        send_notification(ap.data["user_id"],"appeal_approved",
            "✅ Tài khoản đã được mở khóa!",
            f'Kháng cáo của bạn được chấp nhận. Tài khoản đã mở khóa. Lý do: {reason}',
            None,None,appeal_id)
        return f"✅ Đã mở khóa tài khoản user `{ap.data['user_id'][:8]}`."

    # ── reject_ban_appeal (chỉ kháng cáo tài khoản: ref_type='account') ─────────
    if tool == "reject_ban_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin từ chối kháng cáo ban")
        ap = supabase.table("appeals").select("*")\
            .eq("id",appeal_id).eq("ref_type","account").single().execute()
        if not ap.data:
            return "Không tìm thấy kháng cáo ban (kiểm tra lại appeal_id, hoặc đây là kháng cáo nội dung — dùng reject_appeal)."
        supabase.table("appeals").update({
            "status":"rejected","review_note":reason,
            "reviewed_at":datetime.now(timezone.utc).isoformat(),
        }).eq("id",appeal_id).execute()
        send_notification(ap.data["user_id"],"appeal_rejected",
            "❌ Kháng cáo tài khoản không thành công",
            f'Kháng cáo bị từ chối. Tài khoản vẫn bị khóa. Lý do: {reason}',
            None,None,appeal_id)
        return f"❌ Đã từ chối kháng cáo ban `{appeal_id[:8]}`."

    # ── resolve_report ────────────────────────────────────────────────────────
    if tool == "resolve_report":
        report_id    = inp.get("report_id","")
        action_taken = inp.get("action_taken",False)
        reason       = inp.get("reason","")
        rep = supabase.table("reports").select("*")\
            .eq("id",report_id).single().execute()
        if not rep.data: return "Không tìm thấy báo cáo."
        r = rep.data
        supabase.table("reports").update({"status":"resolved"})\
            .eq("id",report_id).execute()
        # Mở tạm khóa nội dung nếu không vi phạm
        if not action_taken:
            if r["ref_type"] == "question":
                supabase.table("questions")\
                    .update({"is_under_review":False})\
                    .eq("id",r["ref_id"]).execute()
            else:
                supabase.table("answers")\
                    .update({"is_under_review":False})\
                    .eq("id",r["ref_id"]).execute()
        if r.get("reporter_id"):
            msg = f'Admin đã xử lý nội dung vi phạm. Lý do: {reason}' if action_taken \
                  else f'Admin không phát hiện vi phạm. Lý do: {reason}'
            send_notification(r["reporter_id"],"report_resolved",
                "✅ Báo cáo đã được xử lý" if action_taken else "ℹ️ Báo cáo đã được xem xét",
                msg, r["ref_id"],r["ref_type"])
        return f"✅ Đã resolve report `{report_id[:8]}`."

    # ── ban_user ──────────────────────────────────────────────────────────────
    if tool == "ban_user":
        user_id = inp.get("user_id","")
        reason  = inp.get("reason","")
        level   = int(inp.get("level",1))
        is_ban  = level >= 3
        supabase.table("profiles").update({
            "violation_level": level,
            "is_banned"      : is_ban,
            "ban_reason"     : reason,
        }).eq("id",user_id).execute()
        level_vi = {1:"Cảnh báo",2:"Nghiêm trọng",3:"Khóa tài khoản"}
        send_notification(user_id,"content_removed",
            f"⚠️ Tài khoản bị {'khóa' if is_ban else 'cảnh báo'}",
            f'Tài khoản ở mức {level_vi.get(level,"?")}. Lý do: {reason}. '
            f'{"Bạn có thể kháng cáo." if is_ban else "Hãy tuân thủ quy tắc cộng đồng."}',
            None,None)
        return f"✅ Đã {'khóa' if is_ban else 'cảnh báo'} user `{user_id[:8]}` mức {level}."

    # ── unban_user ────────────────────────────────────────────────────────────
    if tool == "unban_user":
        user_id = inp.get("user_id","")
        reason  = inp.get("reason","Admin mở khóa")
        supabase.table("profiles").update({
            "violation_level"   : 0,
            "is_banned"         : False,
            "ban_reason"        : None,
            "redemption_points" : 0,
        }).eq("id",user_id).execute()
        send_notification(user_id,"appeal_approved",
            "✅ Tài khoản đã được mở khóa",
            f'Tài khoản đã mở khóa. Lý do: {reason}. Vui lòng tuân thủ quy tắc.',
            None,None)
        return f"✅ Đã mở khóa user `{user_id[:8]}`."

    # ── get_stats ─────────────────────────────────────────────────────────────
    if tool == "get_stats":
        logs = supabase.table("moderation_logs").select("label").execute()
        rpts = supabase.table("reports").select("status").execute()
        apps = supabase.table("appeals").select("status")\
            .in_("ref_type",["question","answer"]).execute()
        bans = supabase.table("appeals").select("status")\
            .eq("ref_type","account").execute()
        qp   = supabase.table("questions").select("id",count="exact")\
               .eq("status","pending").not_.is_("removed_reason","null").execute()
        ap   = supabase.table("answers").select("id",count="exact")\
               .eq("moderation_status","pending").not_.is_("removed_reason","null").execute()
        r_counts  = Counter(r["status"] for r in (rpts.data or []))
        a_counts  = Counter(a["status"] for a in (apps.data or []))
        b_counts  = Counter(b["status"] for b in (bans.data or []))
        l_counts  = Counter(l["label"]  for l in (logs.data or []))
        return (
            f"📊 THỐNG KÊ HỆ THỐNG\n\n"
            f"⏳ Chờ admin duyệt:\n"
            f"  Câu hỏi gắn cờ     : {qp.count or 0}\n"
            f"  Câu trả lời gắn cờ : {ap.count or 0}\n"
            f"  Báo cáo processing  : {r_counts.get('processing',0)}\n"
            f"  Kháng cáo nội dung  : {a_counts.get('pending',0)}\n"
            f"  Kháng cáo ban       : {b_counts.get('pending',0)}\n\n"
            f"🚫 Vi phạm đã xử lý: {len(logs.data or [])}\n"
            + "\n".join(f"  {k}: {v}" for k,v in l_counts.items()) +
            f"\n\n🚩 Báo cáo:\n"
            + "\n".join(f"  {k}: {v}" for k,v in r_counts.items()) +
            f"\n\n⚖️  Kháng cáo nội dung:\n"
            + "\n".join(f"  {k}: {v}" for k,v in a_counts.items()) +
            f"\n\n🔒 Kháng cáo ban:\n"
            + "\n".join(f"  {k}: {v}" for k,v in b_counts.items())
        )

    return f"Tool '{tool}' không tồn tại."

# ── Helpers ───────────────────────────────────────────────────────────────────
def send_notification(user_id, ntype, title, message,
                      ref_id=None, ref_type=None, appeal_id=None):
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

def _refund_points(user_id, amount, ref_id):
    if not amount: return
    try:
        p = supabase.table("profiles").select("points")\
            .eq("id",user_id).single().execute()
        if p.data:
            supabase.table("profiles")\
                .update({"points": p.data["points"] + amount})\
                .eq("id",user_id).execute()
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
            .eq("id",answer["question_id"]).single().execute()
        if q.data and q.data["user_id"] != answer["user_id"]:
            send_notification(q.data["user_id"],"answer_posted",
                "💬 Có câu trả lời mới!",
                f'Câu hỏi "{q.data["title"][:50]}..." vừa nhận được câu trả lời mới.',
                q.data["id"],"question")
    except Exception as e:
        print(f"  ⚠️  Notify answer error: {e}")

def _check_and_award_badges(user_id: str):
    """Kiểm tra và trao huy hiệu"""
    try:
        # Đếm câu trả lời
        a_count = supabase.table("answers")\
            .select("id",count="exact")\
            .eq("user_id",user_id)\
            .eq("moderation_status","approved").execute()
        a_total = a_count.count or 0

        # Đếm câu trả lời được chấp nhận
        acc_count = supabase.table("answers")\
            .select("id",count="exact")\
            .eq("user_id",user_id)\
            .eq("is_accepted",True).execute()
        acc_total = acc_count.count or 0

        # Điểm hiện tại
        p = supabase.table("profiles").select("points")\
            .eq("id",user_id).single().execute()
        points = p.data["points"] if p.data else 0

        # Lấy badges đã có
        existing = supabase.table("user_badges")\
            .select("badge_code").eq("user_id",user_id).execute()
        existing_codes = {b["badge_code"] for b in (existing.data or [])}

        badges_to_award = []
        if a_total >= 1  and "first_answer" not in existing_codes: badges_to_award.append("first_answer")
        if a_total >= 5  and "helper_5"     not in existing_codes: badges_to_award.append("helper_5")
        if a_total >= 20 and "helper_20"    not in existing_codes: badges_to_award.append("helper_20")
        if a_total >= 50 and "helper_50"    not in existing_codes: badges_to_award.append("helper_50")
        if acc_total >= 1  and "accepted_1"  not in existing_codes: badges_to_award.append("accepted_1")
        if acc_total >= 10 and "accepted_10" not in existing_codes: badges_to_award.append("accepted_10")
        if points >= 100 and "points_100" not in existing_codes: badges_to_award.append("points_100")
        if points >= 500 and "points_500" not in existing_codes: badges_to_award.append("points_500")

        for code in badges_to_award:
            try:
                supabase.table("user_badges").insert({
                    "user_id"   : user_id,
                    "badge_code": code,
                }).execute()
                # Lấy thông tin badge
                b = supabase.table("badges").select("name,icon")\
                    .eq("code",code).single().execute()
                if b.data:
                    send_notification(user_id,"appeal_approved",
                        f"🏅 Huy hiệu mới: {b.data['icon']} {b.data['name']}",
                        f'Chúc mừng! Bạn vừa nhận được huy hiệu "{b.data["name"]}"!',
                        None,None)
                print(f"  🏅 Awarded badge '{code}' to {user_id[:8]}")
            except Exception as e:
                print(f"  ⚠️  Award badge '{code}' error: {e}")
    except Exception as e:
        print(f"  ⚠️  Badge error: {e}")

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
    PATTERNS = [
        (r'(?i)(sex|porn|18\+|địt|lồn|cặc|đụ|fuck|shit)', "Nội dung 18+"),
        (r'(?i)(mua ngay|liên hệ zalo|telegram|t\.me/|click here)', "Spam quảng cáo"),
        (r'https?://\S+', "Chứa URL"),
        (r'\b0\d{9,10}\b', "Số điện thoại"),
    ]
    for pattern, reason in PATTERNS:
        if re.search(pattern, t):
            return "SUSPICIOUS", reason
    return None, ""

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
        # Câu hỏi pending chưa gắn cờ
        qs = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","pending")\
            .is_("removed_reason","null")\
            .limit(BATCH_SIZE).execute()

        # Câu trả lời pending chưa gắn cờ
        ans = supabase.table("answers")\
            .select("id,body,user_id,question_id")\
            .eq("moderation_status","pending")\
            .is_("removed_reason","null")\
            .limit(BATCH_SIZE).execute()

        # Reports mới pending → đổi thành processing (chỉ 1 lần)
        rps = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,reporter_id")\
            .eq("status","pending")\
            .limit(BATCH_SIZE).execute()

        items = []
        for q in (qs.data  or []): items.append(("question", q))
        for a in (ans.data or []): items.append(("answer",   a))
        for r in (rps.data or []): items.append(("report",   r))

        if items:
            loop = asyncio.get_event_loop()
            for itype, data in items:
                await loop.run_in_executor(
                    None, lambda i=itype, d=data: process_item(i, d)
                )
    except Exception as e:
        print(f"❌ scan_batch: {e}")

def process_item(itype, data):
    try:
        # ── Report: tiếp nhận 1 lần duy nhất ────────────────────────────────
        if itype == "report":
            # Đổi status → processing để không xử lý lại
            supabase.table("reports")\
                .update({"status":"processing"})\
                .eq("id",data["id"]).execute()

            # Tạm khóa nội dung bị báo cáo
            if data["ref_type"] == "question":
                supabase.table("questions")\
                    .update({"is_under_review":True})\
                    .eq("id",data["ref_id"]).execute()
            else:
                supabase.table("answers")\
                    .update({"is_under_review":True})\
                    .eq("id",data["ref_id"]).execute()

            # Thông báo người bị báo cáo
            reported_user = None
            if data["ref_type"] == "question":
                q = supabase.table("questions").select("user_id")\
                    .eq("id",data["ref_id"]).single().execute()
                reported_user = q.data["user_id"] if q.data else None
            else:
                a = supabase.table("answers").select("user_id")\
                    .eq("id",data["ref_id"]).single().execute()
                reported_user = a.data["user_id"] if a.data else None

            if reported_user:
                send_notification(reported_user,"content_removed",
                    "⚠️ Nội dung của bạn đang bị xem xét",
                    f'Một người dùng đã báo cáo nội dung của bạn ({data["reason"]}). '
                    f'Nội dung tạm thời bị hạn chế cho đến khi admin xem xét xong.',
                    data["ref_id"],data["ref_type"])

            # Thông báo người báo cáo (CHỈ 1 LẦN)
            if data.get("reporter_id"):
                send_notification(data["reporter_id"],"report_resolved",
                    "📨 Báo cáo đã được tiếp nhận",
                    "Báo cáo của bạn đã được ghi nhận và sẽ được admin xem xét sớm.",
                    data["ref_id"],data["ref_type"])

            print(f"  🚩 Report {data['id'][:8]} → processing, content under review")
            return

        # ── Question/Answer: hard rules ───────────────────────────────────────
        text = f"{data['title']} {data.get('body','') or ''}" \
               if itype == "question" else data["body"]
        label, reason = hard_rules(text)

        if label in ("MEANINGLESS","SUSPICIOUS"):
            flag_reason = f"[Chờ admin] {label}: {reason}"
            if itype == "question":
                supabase.table("questions").update({
                    "status"        : "pending",
                    "removed_reason": flag_reason,
                }).eq("id",data["id"]).execute()
            else:
                supabase.table("answers").update({
                    "moderation_status": "pending",
                    "removed_reason"   : flag_reason,
                }).eq("id",data["id"]).execute()
            _log_violation(data["user_id"],data["id"],itype,label,reason)
            print(f"  🚩 [{itype}] {data['id'][:8]} → flagged ({label})")
        else:
            # Clean → approve
            if itype == "question":
                supabase.table("questions").update({
                    "status"        : "open",
                    "removed_by_ai" : False,
                }).eq("id",data["id"]).execute()
            else:
                supabase.table("answers").update({
                    "moderation_status": "approved",
                    "removed_by_ai"    : False,
                }).eq("id",data["id"]).execute()
                _notify_new_answer(data)
                # Kiểm tra huy hiệu
                _check_and_award_badges(data["user_id"])
            print(f"  ✅ [{itype}] {data['id'][:8]} → approved")

    except Exception as e:
        print(f"  ❌ process error [{itype}]: {e}")

# ── JSON-RPC handler ──────────────────────────────────────────────────────────
async def handle_jsonrpc(request: Request) -> dict:
    body   = await request.json()
    method = body.get("method","")
    req_id = body.get("id")

    if method == "initialize":
        return {
            "jsonrpc":"2.0","id":req_id,
            "result":{
                "protocolVersion":"2024-11-05",
                "capabilities"   :{"tools":{}},
                "serverInfo"     :{"name":"hoibai-panel","version":"5.1.0"},
            }
        }
    if method == "tools/list":
        return {"jsonrpc":"2.0","id":req_id,"result":{"tools":MCP_TOOLS}}

    if method == "tools/call":
        params    = body.get("params",{})
        tool_name = params.get("name","")
        tool_inp  = params.get("arguments",{})
        if not supabase:
            return {"jsonrpc":"2.0","id":req_id,
                    "result":{"content":[{"type":"text","text":"⚠️ Supabase chưa kết nối."}],"isError":True}}
        try:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: execute_tool(tool_name, tool_inp)
            )
            return {"jsonrpc":"2.0","id":req_id,
                    "result":{"content":[{"type":"text","text":result}],"isError":False}}
        except Exception as e:
            return {"jsonrpc":"2.0","id":req_id,
                    "result":{"content":[{"type":"text","text":f"❌ Lỗi: {e}"}],"isError":True}}

    if method == "ping":
        return {"jsonrpc":"2.0","id":req_id,"result":{}}

    return {"jsonrpc":"2.0","id":req_id,
            "error":{"code":-32601,"message":f"Method '{method}' not found"}}

# ── MCP Endpoints ─────────────────────────────────────────────────────────────
@app.get("/mcp")
async def mcp_info():
    return {"jsonrpc":"2.0","result":{
        "protocolVersion":"2024-11-05",
        "capabilities"   :{"tools":{}},
        "serverInfo"     :{"name":"hoibai-panel","version":"5.1.0"},
    }}

@app.post("/mcp")
async def mcp_endpoint(request: Request, authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401,"Unauthorized")
    return await handle_jsonrpc(request)

@app.post("/messages")
async def messages_endpoint(request: Request, authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401,"Unauthorized")
    return await handle_jsonrpc(request)

@app.get("/sse")
async def sse_endpoint(request: Request, authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401,"Unauthorized")

    async def event_stream():
        init = {
            "jsonrpc":"2.0","method":"notifications/initialized",
            "params":{
                "protocolVersion":"2024-11-05",
                "capabilities"   :{"tools":{}},
                "serverInfo"     :{"name":"hoibai-panel","version":"5.1.0"},
            }
        }
        yield f"data: {json.dumps(init,ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'jsonrpc':'2.0','method':'notifications/tools/list_changed','params':{}},ensure_ascii=False)}\n\n"
        while True:
            if await request.is_disconnected(): break
            yield f": ping\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Access-Control-Allow-Origin":"*"})

# ── REST ──────────────────────────────────────────────────────────────────────
class ModerateRequest(BaseModel):
    text   : str
    context: str = "question"

@app.post("/moderate")
async def moderate(req: ModerateRequest):
    label, reason = hard_rules(req.text.strip())
    if label in ("MEANINGLESS","SUSPICIOUS"):
        return {"label":label,"allowed":False,"reason":reason}
    return {"label":"CLEAN","allowed":True,"reason":"Passed rules"}

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
                .eq("status","processing").execute()
            pp = supabase.table("appeals").select("id",count="exact")\
                .eq("status","pending").in_("ref_type",["question","answer"]).execute()
            bp = supabase.table("appeals").select("id",count="exact")\
                .eq("status","pending").eq("ref_type","account").execute()
            counts = {
                "questions_flagged": qp.count or 0,
                "answers_flagged"  : ap.count or 0,
                "reports_processing": rp.count or 0,
                "appeals_pending"  : pp.count or 0,
                "ban_appeals_pending": bp.count or 0,
            }
        except: pass
    return {
        "status" : "ok",
        "mode"   : "manual_review (MCP)",
        "scanner": "running" if (supabase and scan_task
                    and not scan_task.done()) else "disabled",
        "pending": counts,
        "version": "5.1.0",
    }

@app.get("/")
async def root():
    return {
        "service": "HoiBai Moderator",
        "version": "5.1.0",
        "mode"   : "manual_review via MCP",
        "mcp_url": f"{BASE_URL}/mcp",
    }
