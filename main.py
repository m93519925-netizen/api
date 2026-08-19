import os, re, asyncio, hashlib, time, base64, json, secrets
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
# Lưu tạm các yêu cầu bulk action đang chờ xác nhận (confirm step).
# key = confirm_token, value = {"action":..., "payload":..., "expires": ts}
_pending_confirms: dict = {}
CONFIRM_TTL_SECONDS = 300  # token xác nhận hết hạn sau 5 phút

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

app = FastAPI(title="HoiBai Moderator (MCP)", version="6.0.0", lifespan=lifespan)
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
        "name"       : "get_user_id_by_username",
        "description": "Tra UUID của user từ username (hỗ trợ tìm gần đúng nếu không khớp chính xác) — dùng trước khi gọi ban_user/get_user_history",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type":"string","description":"Username cần tra, ví dụ 'tuibigay'"},
            },
            "required": ["username"],
        },
    },
    {
        "name"       : "search_users",
        "description": "Tìm/lọc user theo tên (gần đúng), mức vi phạm, trạng thái khóa — dùng để rà soát tài khoản vi phạm lặp lại",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username_like": {"type":"string","description":"Tìm username chứa chuỗi này (không bắt buộc)"},
                "min_violation_level": {"type":"integer","description":"Lọc từ mức vi phạm này trở lên: 0-3 (không bắt buộc)"},
                "is_banned": {"type":"boolean","description":"Lọc theo trạng thái bị khóa (không bắt buộc)"},
                "limit": {"type":"integer","description":"Số kết quả tối đa, mặc định 30"},
            },
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
        "name"       : "get_user_warning_history",
        "description": "Xem lịch sử CẢNH BÁO/leo thang mức vi phạm của 1 user (level 1→2→3 qua thời gian), tách riêng khỏi lịch sử nội dung bị xóa — dùng để đánh giá mức độ tái phạm trước khi quyết định ban/unban",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type":"string","description":"ID người dùng"},
            },
            "required": ["user_id"],
        },
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
        "description": "Xóa mềm (soft delete) 1 nội dung vi phạm — có thể khôi phục trong 30 ngày qua restore_content",
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
        "name"       : "restore_content",
        "description": "Khôi phục 1 nội dung đã bị xóa mềm trong vòng 30 ngày qua remove_content/bulk_remove_content",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref_id"  : {"type":"string"},
                "ref_type": {"type":"string"},
                "reason"  : {"type":"string","description":"Lý do khôi phục"},
            },
            "required": ["ref_id","ref_type"],
        },
    },
    {
        "name"       : "list_deleted_content",
        "description": "Liệt kê nội dung đang ở trạng thái xóa mềm (còn trong 30 ngày, có thể restore) — dùng để rà soát trước khi phục hồi hoặc xóa vĩnh viễn",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type":"string","description":"'question','answer','all' (mặc định 'all')"},
            },
        },
    },
    {
        "name"       : "bulk_remove_content",
        "description": "Xóa mềm NHIỀU nội dung cùng lúc, MỖI nội dung có lý do (reason) RIÊNG — không dùng chung 1 lý do cho tất cả. BẮT BUỘC phải gọi với confirm_token hợp lệ lấy từ request_bulk_action trước, trừ khi dry_run=true để xem trước danh sách sẽ bị ảnh hưởng.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "description": "Danh sách nội dung cần xóa, MỖI item có reason riêng",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ref_id"  : {"type":"string"},
                            "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
                            "reason"  : {"type":"string","description":"Lý do XÓA RIÊNG cho nội dung này"},
                        },
                        "required": ["ref_id","ref_type","reason"],
                    },
                },
                "confirm_token": {"type":"string","description":"Token xác nhận lấy từ request_bulk_action — bắt buộc trừ khi dry_run=true"},
                "dry_run": {"type":"boolean","description":"true = chỉ xem trước sẽ xóa gì, KHÔNG thực thi, KHÔNG cần confirm_token"},
            },
            "required": ["items"],
        },
    },
    {
        "name"       : "bulk_ban_users",
        "description": "Cảnh báo hoặc khóa NHIỀU user cùng lúc. Hỗ trợ 2 chế độ: (1) 'reason' + 'level' chung cho tất cả, HOẶC (2) 'items' để mỗi user có reason/level RIÊNG (ưu tiên 'items' nếu có cả hai). BẮT BUỘC phải gọi với confirm_token hợp lệ lấy từ request_bulk_action trước, trừ khi dry_run=true để xem trước danh sách.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_ids": {"type":"array","items":{"type":"string"},"description":"Danh sách UUID user — dùng khi muốn 1 reason/level CHUNG cho tất cả (bỏ qua nếu dùng 'items')"},
                "reason"  : {"type":"string","description":"Lý do CHUNG — chỉ dùng khi không truyền 'items'"},
                "level"   : {"type":"integer","description":"Mức CHUNG (1/2/3) — chỉ dùng khi không truyền 'items'"},
                "items": {
                    "type": "array",
                    "description": "Danh sách user MỖI user có reason/level RIÊNG — nếu truyền, bỏ qua 'user_ids'/'reason'/'level' ở trên",
                    "items": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type":"string"},
                            "reason" : {"type":"string","description":"Lý do RIÊNG cho user này"},
                            "level"  : {"type":"integer","description":"Mức RIÊNG cho user này (1/2/3)"},
                        },
                        "required": ["user_id","reason","level"],
                    },
                },
                "confirm_token": {"type":"string","description":"Token xác nhận lấy từ request_bulk_action — bắt buộc trừ khi dry_run=true"},
                "dry_run": {"type":"boolean","description":"true = chỉ xem trước sẽ ảnh hưởng ai, KHÔNG thực thi, KHÔNG cần confirm_token"},
            },
        },
    },
    {
        "name"       : "bulk_unban_users",
        "description": "Mở khóa NHIỀU user cùng lúc. Hỗ trợ 2 chế độ: (1) 'reason' chung cho tất cả, HOẶC (2) 'items' để mỗi user có reason RIÊNG (ví dụ: người thì appeal được duyệt, người thì hết thời gian cảnh báo — lý do khác nhau). BẮT BUỘC confirm_token trước, trừ khi dry_run=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_ids": {"type":"array","items":{"type":"string"},"description":"Danh sách UUID user — dùng khi muốn 1 reason CHUNG (bỏ qua nếu dùng 'items')"},
                "reason"  : {"type":"string","description":"Lý do CHUNG — chỉ dùng khi không truyền 'items'"},
                "items": {
                    "type": "array",
                    "description": "Danh sách user MỖI user có reason RIÊNG — nếu truyền, bỏ qua 'user_ids'/'reason' ở trên",
                    "items": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type":"string"},
                            "reason" : {"type":"string","description":"Lý do mở khóa RIÊNG cho user này"},
                        },
                        "required": ["user_id","reason"],
                    },
                },
                "confirm_token": {"type":"string","description":"Token xác nhận lấy từ request_bulk_action — bắt buộc trừ khi dry_run=true"},
                "dry_run": {"type":"boolean","description":"true = chỉ xem trước sẽ ảnh hưởng ai, KHÔNG thực thi, KHÔNG cần confirm_token"},
            },
        },
    },
    {
        "name"       : "bulk_remove_user_content",
        "description": "Xóa mềm TOÀN BỘ câu hỏi + câu trả lời của 1 user (dùng khi ban user vi phạm nặng, muốn dọn sạch nội dung họ từng đăng cùng lúc thay vì xóa từng cái). Tất cả nội dung dùng CHUNG 1 reason vì cùng 1 quyết định xử lý user đó. BẮT BUỘC confirm_token trước, trừ khi dry_run=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type":"string","description":"UUID user cần xóa toàn bộ nội dung"},
                "reason" : {"type":"string","description":"Lý do chung cho việc xóa toàn bộ nội dung của user này"},
                "confirm_token": {"type":"string","description":"Token xác nhận lấy từ request_bulk_action — bắt buộc trừ khi dry_run=true"},
                "dry_run": {"type":"boolean","description":"true = chỉ xem trước sẽ xóa bao nhiêu nội dung, KHÔNG thực thi, KHÔNG cần confirm_token"},
            },
            "required": ["user_id","reason"],
        },
    },
    {
        "name"       : "request_bulk_action",
        "description": "BƯỚC XÁC NHẬN bắt buộc trước khi chạy bulk_remove_content, bulk_ban_users, bulk_unban_users, hoặc bulk_remove_user_content thật sự. Trả về confirm_token (hết hạn sau 5 phút) và bản tóm tắt số lượng/đối tượng sẽ bị ảnh hưởng để xác nhận lại trước khi thực thi.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type":"string","description":"'bulk_remove_content', 'bulk_ban_users', 'bulk_unban_users', hoặc 'bulk_remove_user_content'"},
                "payload": {"type":"object","description":"Tham số sẽ dùng khi thực thi thật (items hoặc user_ids+reason+level)"},
            },
            "required": ["action","payload"],
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
        "name"       : "get_appeal_detail",
        "description": "Xem đầy đủ nội dung 1 kháng cáo (nội dung hoặc tài khoản), không bị cắt ngắn, kèm bối cảnh liên quan — dùng trước khi approve/reject",
        "inputSchema": {
            "type": "object",
            "properties": {
                "appeal_id": {"type":"string"},
            },
            "required": ["appeal_id"],
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
        "name"       : "list_pending_reports",
        "description": "Liệt kê báo cáo vi phạm đang chờ admin xử lý",
        "inputSchema": {"type":"object","properties":{}},
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
        "name"       : "get_audit_log",
        "description": "Xem lịch sử audit log — mọi hành động moderation đã thực hiện (xóa, ban, duyệt kháng cáo...), ai làm, khi nào, lý do gì. Dùng để truy vết/kiểm tra lại quyết định trước đó.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action"      : {"type":"string","description":"Lọc theo loại hành động, ví dụ 'remove_content','ban_user' (không bắt buộc)"},
                "target_id"   : {"type":"string","description":"Lọc theo ID đối tượng cụ thể (không bắt buộc)"},
                "days"        : {"type":"integer","description":"Số ngày gần nhất (mặc định 30)"},
                "limit"       : {"type":"integer","description":"Số kết quả tối đa (mặc định 50)"},
            },
        },
    },
    {
        "name"       : "get_stats",
        "description": "Thống kê tổng quan hệ thống",
        "inputSchema": {"type":"object","properties":{}},
    },
    {
        "name"       : "get_violation_analytics",
        "description": "Thống kê vi phạm: top user vi phạm nhiều nhất, số nội dung bị xóa theo loại, timeline vi phạm theo ngày",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type":"integer","description":"Số ngày gần nhất để thống kê, mặc định 30"},
            },
        },
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

    # ── get_user_id_by_username ──────────────────────────────────────────────
    if tool == "get_user_id_by_username":
        username = inp.get("username","").strip()
        if not username:
            return "⚠️ Thiếu username."
        exact = supabase.table("profiles")\
            .select("id,username,violation_level,is_banned,points")\
            .eq("username",username).limit(5).execute()
        if exact.data:
            lines = [f"✅ **{len(exact.data)} kết quả khớp chính xác '{username}':**\n"]
            for p in exact.data:
                lines.append(
                    f"🆔 `{p['id']}`\n"
                    f"👤 {p['username']}\n"
                    f"📊 Mức vi phạm: {p.get('violation_level',0)} | "
                    f"{'🔒 Đã khóa' if p.get('is_banned') else '✅ Bình thường'}\n"
                    f"⭐ {p.get('points',0)} điểm\n---"
                )
            return "\n".join(lines)
        fuzzy = supabase.table("profiles")\
            .select("id,username,violation_level,is_banned")\
            .ilike("username",f"%{username}%").limit(10).execute()
        if not fuzzy.data:
            return f"❌ Không tìm thấy user nào có username giống '{username}'."
        lines = [f"⚠️ Không khớp chính xác. **{len(fuzzy.data)} kết quả gần đúng:**\n"]
        for p in fuzzy.data:
            lines.append(
                f"🆔 `{p['id']}`\n"
                f"👤 {p['username']}\n"
                f"📊 Mức vi phạm: {p.get('violation_level',0)} | "
                f"{'🔒 Đã khóa' if p.get('is_banned') else '✅ Bình thường'}\n---"
            )
        return "\n".join(lines)

    # ── search_users ──────────────────────────────────────────────────────────
    if tool == "search_users":
        username_like = inp.get("username_like","").strip()
        min_vl        = inp.get("min_violation_level")
        is_banned     = inp.get("is_banned")
        limit         = int(inp.get("limit",30))

        q = supabase.table("profiles")\
            .select("id,username,violation_level,is_banned,ban_reason,points")
        if username_like:
            q = q.ilike("username",f"%{username_like}%")
        if min_vl is not None:
            q = q.gte("violation_level",int(min_vl))
        if is_banned is not None:
            q = q.eq("is_banned",bool(is_banned))
        r = q.order("violation_level",desc=True).limit(limit).execute()

        if not r.data:
            return "❌ Không tìm thấy user nào khớp bộ lọc."
        lines = [f"👥 **{len(r.data)} user khớp bộ lọc:**\n"]
        vl_map = {0:"✅ Bình thường",1:"⚠️ Cảnh báo",2:"🔴 Nghiêm trọng",3:"🔒 Bị khóa"}
        for p in r.data:
            lines.append(
                f"🆔 `{p['id']}`\n"
                f"👤 {p['username']}\n"
                f"📊 {vl_map.get(p.get('violation_level',0),'?')}"
                + (f" - {p.get('ban_reason')}" if p.get('is_banned') and p.get('ban_reason') else "") + "\n"
                f"⭐ {p.get('points',0)} điểm\n---"
            )
        return "\n".join(lines)

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

    # ── get_user_warning_history ─────────────────────────────────────────────
    # Khác get_user_history: tập trung riêng vào việc LEO THANG mức vi phạm
    # (level 1→2→3) qua các lần ban_user, lấy từ audit_logs thay vì moderation_logs
    # vì moderation_logs chỉ ghi vi phạm nội dung tự động, không ghi quyết định ban của admin.
    if tool == "get_user_warning_history":
        user_id = inp.get("user_id","")
        profile = supabase.table("profiles")\
            .select("username,violation_level,is_banned,ban_reason")\
            .eq("id",user_id).single().execute()
        p = profile.data or {}

        audits = supabase.table("audit_logs")\
            .select("action,reason,metadata,created_at")\
            .eq("target_type","user").eq("target_id",user_id)\
            .in_("action",["ban_user","unban_user"])\
            .order("created_at",desc=False).limit(50).execute()

        result = (
            f"📖 **LỊCH SỬ CẢNH BÁO** — {p.get('username','?')} (`{user_id[:8]}`)\n"
            f"Mức hiện tại: {p.get('violation_level',0)} | "
            f"{'🔒 Đang bị khóa' if p.get('is_banned') else '✅ Bình thường'}\n\n"
        )
        if not audits.data:
            result += "Chưa có lịch sử cảnh báo/ban nào được ghi nhận qua audit log."
            return result

        result += "**Diễn biến theo thời gian:**\n"
        for a in audits.data:
            meta = a.get("metadata") or {}
            if a["action"] == "ban_user":
                lvl = meta.get("level","?")
                result += f"  🔺 [{a['created_at'][:16]}] Nâng lên MỨC {lvl} — Lý do: {a.get('reason','')}\n"
            else:
                result += f"  🔻 [{a['created_at'][:16]}] MỞ KHÓA (reset về mức 0) — Lý do: {a.get('reason','')}\n"
        return result

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
                f"🗑️  Xóa mềm: {'Có, lúc ' + q['deleted_at'][:16] if q.get('deleted_at') else 'Không'}\n"
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
                f"🗑️  Xóa mềm: {'Có, lúc ' + a['deleted_at'][:16] if a.get('deleted_at') else 'Không'}\n"
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
        _audit("approve_content", "question" if ref_type=="question" else "answer", ref_id, reason)
        return f"✅ Đã duyệt {ref_type} `{ref_id[:8]}`."

    # ── remove_content (SOFT DELETE) ─────────────────────────────────────────
    if tool == "remove_content":
        ref_id    = inp.get("ref_id","")
        ref_type  = inp.get("ref_type","")
        reason    = inp.get("reason","Admin xóa vi phạm")
        report_id = inp.get("report_id","")
        result = _soft_delete_one(ref_id, ref_type, reason)
        if report_id:
            supabase.table("reports").update({"status":"resolved"})\
                .eq("id",report_id).execute()
        return result

    # ── restore_content ───────────────────────────────────────────────────────
    if tool == "restore_content":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        reason   = inp.get("reason","Admin khôi phục")
        return _restore_one(ref_id, ref_type, reason)

    # ── list_deleted_content ──────────────────────────────────────────────────
    if tool == "list_deleted_content":
        ctype = inp.get("type","all")
        lines = []
        if ctype in ("question","all"):
            r = supabase.table("questions")\
                .select("id,title,user_id,deleted_at,deleted_by,removed_reason,profiles(username)")\
                .not_.is_("deleted_at","null")\
                .order("deleted_at",desc=True).limit(30).execute()
            if r.data:
                lines.append(f"📚 **{len(r.data)} CÂU HỎI đã xóa mềm (còn khôi phục được):**\n")
                for q in r.data:
                    lines.append(
                        f"🆔 `{q['id']}`\n"
                        f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"
                        f"📋 {q.get('title','')[:100]}\n"
                        f"🚩 {q.get('removed_reason','')}\n"
                        f"🗑️  Xóa lúc {q.get('deleted_at','')[:16]} bởi {q.get('deleted_by','?')}\n---"
                    )
        if ctype in ("answer","all"):
            r = supabase.table("answers")\
                .select("id,body,user_id,deleted_at,deleted_by,removed_reason,profiles(username)")\
                .not_.is_("deleted_at","null")\
                .order("deleted_at",desc=True).limit(30).execute()
            if r.data:
                lines.append(f"\n💬 **{len(r.data)} CÂU TRẢ LỜI đã xóa mềm:**\n")
                for a in r.data:
                    lines.append(
                        f"🆔 `{a['id']}`\n"
                        f"👤 {a['profiles']['username'] if a.get('profiles') else '?'}\n"
                        f"📄 {a.get('body','')[:100]}\n"
                        f"🚩 {a.get('removed_reason','')}\n"
                        f"🗑️  Xóa lúc {a.get('deleted_at','')[:16]} bởi {a.get('deleted_by','?')}\n---"
                    )
        return "\n".join(lines) if lines else "✅ Không có nội dung nào đang ở trạng thái xóa mềm."

    # ── request_bulk_action (CONFIRM STEP) ───────────────────────────────────
    if tool == "request_bulk_action":
        action  = inp.get("action","")
        payload = inp.get("payload",{})
        valid_actions = ("bulk_remove_content","bulk_ban_users","bulk_unban_users","bulk_remove_user_content")
        if action not in valid_actions:
            return f"⚠️ action không hợp lệ. Chỉ hỗ trợ: {', '.join(valid_actions)}."

        token = secrets.token_urlsafe(16)
        _pending_confirms[token] = {
            "action": action,
            "payload": payload,
            "expires": time.time() + CONFIRM_TTL_SECONDS,
        }
        for k in [k for k,v in _pending_confirms.items() if v["expires"] < time.time()]:
            del _pending_confirms[k]

        if action == "bulk_remove_content":
            items = payload.get("items",[])
            summary = f"Sẽ XÓA MỀM {len(items)} nội dung:\n"
            for it in items[:20]:
                summary += f"  • {it.get('ref_type')} `{it.get('ref_id','')[:8]}` — lý do: {it.get('reason','(chưa có)')}\n"
            if len(items) > 20:
                summary += f"  ... và {len(items)-20} nội dung khác\n"

        elif action == "bulk_ban_users":
            ban_items = payload.get("items")
            if ban_items:
                summary = f"Sẽ BAN {len(ban_items)} user, MỖI user reason/level RIÊNG:\n"
                for it in ban_items[:20]:
                    summary += f"  • `{it.get('user_id','')[:8]}` mức {it.get('level','?')} — {it.get('reason','(chưa có)')}\n"
                if len(ban_items) > 20:
                    summary += f"  ... và {len(ban_items)-20} user khác\n"
            else:
                user_ids = payload.get("user_ids",[])
                level = payload.get("level","?")
                reason = payload.get("reason","")
                summary = f"Sẽ áp dụng MỨC {level} cho {len(user_ids)} user, lý do chung: {reason}\n"
                for uid in user_ids[:20]:
                    summary += f"  • `{uid[:8]}`\n"
                if len(user_ids) > 20:
                    summary += f"  ... và {len(user_ids)-20} user khác\n"

        elif action == "bulk_unban_users":
            unban_items = payload.get("items")
            if unban_items:
                summary = f"Sẽ MỞ KHÓA {len(unban_items)} user, MỖI user reason RIÊNG:\n"
                for it in unban_items[:20]:
                    summary += f"  • `{it.get('user_id','')[:8]}` — {it.get('reason','(chưa có)')}\n"
                if len(unban_items) > 20:
                    summary += f"  ... và {len(unban_items)-20} user khác\n"
            else:
                user_ids = payload.get("user_ids",[])
                reason = payload.get("reason","")
                summary = f"Sẽ MỞ KHÓA {len(user_ids)} user, lý do chung: {reason}\n"
                for uid in user_ids[:20]:
                    summary += f"  • `{uid[:8]}`\n"
                if len(user_ids) > 20:
                    summary += f"  ... và {len(user_ids)-20} user khác\n"

        else:  # bulk_remove_user_content
            uid = payload.get("user_id","")
            reason = payload.get("reason","")
            cnt_q = supabase.table("questions").select("id",count="exact")\
                .eq("user_id",uid).is_("deleted_at","null").execute()
            cnt_a = supabase.table("answers").select("id",count="exact")\
                .eq("user_id",uid).is_("deleted_at","null").execute()
            total = (cnt_q.count or 0) + (cnt_a.count or 0)
            summary = (f"Sẽ XÓA MỀM TOÀN BỘ nội dung của user `{uid[:8]}`: "
                       f"{cnt_q.count or 0} câu hỏi + {cnt_a.count or 0} câu trả lời "
                       f"= {total} nội dung. Lý do chung: {reason}\n")

        return (
            f"📋 **XÁC NHẬN TRƯỚC KHI THỰC THI**\n\n{summary}\n"
            f"🔑 confirm_token: `{token}` (hết hạn sau {CONFIRM_TTL_SECONDS//60} phút)\n\n"
            f"Để thực thi thật, gọi lại `{action}` với đúng payload này VÀ kèm confirm_token ở trên.\n"
            f"Hoặc gọi với dry_run=true bất cứ lúc nào để xem trước mà không cần token."
        )

    # ── bulk_remove_content (reason riêng + confirm step) ────────────────────
    if tool == "bulk_remove_content":
        items         = inp.get("items",[])
        confirm_token = inp.get("confirm_token","")
        dry_run       = bool(inp.get("dry_run",False))
        if not items:
            return "⚠️ Danh sách items rỗng."
        missing_reason = [it for it in items if not it.get("reason","").strip()]
        if missing_reason:
            return (f"⚠️ {len(missing_reason)} item thiếu 'reason' riêng. "
                     f"Mỗi nội dung xóa hàng loạt PHẢI có lý do riêng, không dùng chung 1 lý do.")

        if dry_run:
            lines = [f"👁️ **DRY RUN — sẽ xóa {len(items)} nội dung (chưa thực thi):**\n"]
            for it in items:
                lines.append(f"  • {it['ref_type']} `{it['ref_id'][:8]}` — {it['reason']}")
            return "\n".join(lines)

        if not _check_confirm_token(confirm_token, "bulk_remove_content", {"items": items}):
            return ("⛔ Thiếu hoặc sai confirm_token. Gọi request_bulk_action với "
                     "action='bulk_remove_content' và payload={'items': [...]} giống hệt lần này trước, "
                     "rồi dùng confirm_token trả về để thực thi. Hoặc dùng dry_run=true để xem trước.")

        results = []
        for item in items:
            r = _soft_delete_one(item.get("ref_id",""), item.get("ref_type",""), item.get("reason",""))
            results.append(f"  • {item.get('ref_type')} `{item.get('ref_id','')[:8]}` → {r}")
        _audit("bulk_remove_content", "batch", None, f"{len(items)} nội dung", {"count": len(items)})
        return f"🚫 **Đã xử lý {len(items)} nội dung:**\n" + "\n".join(results)

    # ── bulk_ban_users (2 chế độ: reason chung HOẶC items reason riêng) ─────
    if tool == "bulk_ban_users":
        ban_items     = inp.get("items")
        user_ids      = inp.get("user_ids",[])
        reason        = inp.get("reason","")
        level         = int(inp.get("level",1)) if inp.get("level") is not None else 1
        confirm_token = inp.get("confirm_token","")
        dry_run       = bool(inp.get("dry_run",False))

        # Chuẩn hoá về 1 danh sách [{user_id, reason, level}] dù dùng chế độ nào
        if ban_items:
            missing = [it for it in ban_items if not it.get("reason","").strip()]
            if missing:
                return f"⚠️ {len(missing)} user trong 'items' thiếu 'reason' riêng."
            normalized = [{"user_id": it["user_id"], "reason": it["reason"], "level": int(it.get("level",1))} for it in ban_items]
            payload_for_token = {"items": ban_items}
        else:
            if not user_ids:
                return "⚠️ Cần truyền 'user_ids' (+reason/level chung) hoặc 'items' (reason/level riêng)."
            normalized = [{"user_id": uid, "reason": reason, "level": level} for uid in user_ids]
            payload_for_token = {"user_ids": user_ids, "reason": reason, "level": level}

        if dry_run:
            lines = [f"👁️ **DRY RUN — sẽ xử lý {len(normalized)} user (chưa thực thi):**\n"]
            for it in normalized:
                lines.append(f"  • `{it['user_id'][:8]}` mức {it['level']} — {it['reason']}")
            return "\n".join(lines)

        if not _check_confirm_token(confirm_token, "bulk_ban_users", payload_for_token):
            return ("⛔ Thiếu hoặc sai confirm_token. Gọi request_bulk_action với "
                     "action='bulk_ban_users' và payload giống hệt lần này trước, "
                     "rồi dùng confirm_token trả về để thực thi. Hoặc dùng dry_run=true để xem trước.")

        results = []
        for it in normalized:
            r = _ban_user_internal(it["user_id"], it["reason"], it["level"])
            results.append(f"  • `{it['user_id'][:8]}` → {r}")
        _audit("bulk_ban_users", "batch", None,
               reason if not ban_items else "(mỗi user 1 lý do riêng, xem chi tiết từng dòng ban_user)",
               {"count": len(normalized), "per_user_reason": bool(ban_items)})
        return f"⚖️ **Đã xử lý {len(normalized)} user:**\n" + "\n".join(results)

    # ── bulk_unban_users (2 chế độ: reason chung HOẶC items reason riêng) ────
    if tool == "bulk_unban_users":
        unban_items   = inp.get("items")
        user_ids      = inp.get("user_ids",[])
        reason        = inp.get("reason","Admin mở khóa")
        confirm_token = inp.get("confirm_token","")
        dry_run       = bool(inp.get("dry_run",False))

        if unban_items:
            missing = [it for it in unban_items if not it.get("reason","").strip()]
            if missing:
                return f"⚠️ {len(missing)} user trong 'items' thiếu 'reason' riêng."
            normalized = [{"user_id": it["user_id"], "reason": it["reason"]} for it in unban_items]
            payload_for_token = {"items": unban_items}
        else:
            if not user_ids:
                return "⚠️ Cần truyền 'user_ids' (+reason chung) hoặc 'items' (reason riêng)."
            normalized = [{"user_id": uid, "reason": reason} for uid in user_ids]
            payload_for_token = {"user_ids": user_ids, "reason": reason}

        if dry_run:
            lines = [f"👁️ **DRY RUN — sẽ mở khóa {len(normalized)} user (chưa thực thi):**\n"]
            for it in normalized:
                lines.append(f"  • `{it['user_id'][:8]}` — {it['reason']}")
            return "\n".join(lines)

        if not _check_confirm_token(confirm_token, "bulk_unban_users", payload_for_token):
            return ("⛔ Thiếu hoặc sai confirm_token. Gọi request_bulk_action với "
                     "action='bulk_unban_users' và payload giống hệt lần này trước, "
                     "rồi dùng confirm_token trả về để thực thi. Hoặc dùng dry_run=true để xem trước.")

        results = []
        for it in normalized:
            r = _unban_user_internal(it["user_id"], it["reason"])
            results.append(f"  • `{it['user_id'][:8]}` → {r}")
        _audit("bulk_unban_users", "batch", None,
               reason if not unban_items else "(mỗi user 1 lý do riêng, xem chi tiết từng dòng unban_user)",
               {"count": len(normalized), "per_user_reason": bool(unban_items)})
        return f"✅ **Đã mở khóa {len(normalized)} user:**\n" + "\n".join(results)

    # ── bulk_remove_user_content ─────────────────────────────────────────────
    if tool == "bulk_remove_user_content":
        user_id       = inp.get("user_id","")
        reason        = inp.get("reason","")
        confirm_token = inp.get("confirm_token","")
        dry_run       = bool(inp.get("dry_run",False))
        if not user_id or not reason.strip():
            return "⚠️ Cần cả 'user_id' và 'reason'."

        qs = supabase.table("questions").select("id,title")\
            .eq("user_id",user_id).is_("deleted_at","null").execute()
        ans = supabase.table("answers").select("id,body")\
            .eq("user_id",user_id).is_("deleted_at","null").execute()
        q_list = qs.data or []
        a_list = ans.data or []
        total = len(q_list) + len(a_list)

        if dry_run:
            lines = [f"👁️ **DRY RUN — sẽ xóa mềm {total} nội dung của user `{user_id[:8]}` (chưa thực thi):**\n"]
            for q in q_list[:15]:
                lines.append(f"  • question `{q['id'][:8]}` — {q.get('title','')[:60]}")
            for a in a_list[:15]:
                lines.append(f"  • answer `{a['id'][:8]}` — {a.get('body','')[:60]}")
            if total > 30:
                lines.append(f"  ... và {total-30} nội dung khác")
            return "\n".join(lines)

        payload_for_token = {"user_id": user_id, "reason": reason}
        if not _check_confirm_token(confirm_token, "bulk_remove_user_content", payload_for_token):
            return ("⛔ Thiếu hoặc sai confirm_token. Gọi request_bulk_action với "
                     "action='bulk_remove_user_content' và payload={'user_id':..., 'reason':...} giống hệt lần này trước, "
                     "rồi dùng confirm_token trả về để thực thi. Hoặc dùng dry_run=true để xem trước.")

        if total == 0:
            return f"✅ User `{user_id[:8]}` không có nội dung nào cần xóa."

        results = []
        for q in q_list:
            r = _soft_delete_one(q["id"], "question", reason)
            results.append(f"  • question `{q['id'][:8]}` → {r}")
        for a in a_list:
            r = _soft_delete_one(a["id"], "answer", reason)
            results.append(f"  • answer `{a['id'][:8]}` → {r}")
        _audit("bulk_remove_user_content", "user", user_id, reason, {"items_count": total})
        return f"🚫 **Đã xóa mềm {total} nội dung của user `{user_id[:8]}`:**\n" + "\n".join(results)

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
            _restore_one(a["ref_id"], "question", reason)
        else:
            _restore_one(a["ref_id"], "answer", reason)
        send_notification(a["user_id"],"appeal_approved",
            "✅ Kháng cáo thành công! (Admin duyệt)",
            f'Admin chấp nhận kháng cáo. Nội dung khôi phục. Lý do: {reason}',
            a["ref_id"],a["ref_type"],appeal_id)
        _audit("approve_appeal", "appeal", appeal_id, reason)
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
        _audit("reject_appeal", "appeal", appeal_id, reason)
        return f"❌ Đã từ chối kháng cáo `{appeal_id[:8]}`."

    # ── list_pending_appeals ──────────────────────────────────────────────────
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
        }).eq("id",ap.data["user_id"]).execute()
        send_notification(ap.data["user_id"],"appeal_approved",
            "✅ Tài khoản đã được mở khóa!",
            f'Kháng cáo của bạn được chấp nhận. Tài khoản đã mở khóa. Lý do: {reason}',
            None,None,appeal_id)
        _audit("approve_ban_appeal", "appeal", appeal_id, reason, {"user_id": ap.data["user_id"]})
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
        _audit("reject_ban_appeal", "appeal", appeal_id, reason, {"user_id": ap.data["user_id"]})
        return f"❌ Đã từ chối kháng cáo ban `{appeal_id[:8]}`."

    # ── get_appeal_detail ─────────────────────────────────────────────────────
    if tool == "get_appeal_detail":
        appeal_id = inp.get("appeal_id","")
        ap = supabase.table("appeals").select("*,profiles(username,violation_level,is_banned)")\
            .eq("id",appeal_id).single().execute()
        if not ap.data:
            return "❌ Không tìm thấy kháng cáo."
        a = ap.data
        result = (
            f"⚖️ **CHI TIẾT KHÁNG CÁO** `{a['id']}`\n"
            f"👤 {a['profiles']['username'] if a.get('profiles') else a.get('user_id','?')[:8]}\n"
            f"📌 Loại: {a.get('ref_type','?')}\n"
            f"📊 Trạng thái: {a.get('status','?')}\n"
            f"🕐 {a.get('created_at','')[:16]}\n\n"
            f"📝 **Nội dung kháng cáo đầy đủ:**\n{a.get('content','(trống)')}\n"
        )
        if a.get('review_note'):
            result += f"\n📋 Ghi chú admin trước đó: {a['review_note']}\n"
        if a.get('ref_type') in ('question','answer') and a.get('ref_id'):
            detail = execute_tool("get_content_detail", {
                "ref_id": a['ref_id'], "ref_type": a['ref_type'],
            })
            result += f"\n──── Nội dung liên quan ────\n{detail}"
        elif a.get('ref_type') == 'account':
            history = execute_tool("get_user_history", {"user_id": a.get('user_id','')})
            result += f"\n──── Lịch sử tài khoản ────\n{history}"
        return result

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
        _audit("resolve_report", r["ref_type"], r["ref_id"], reason, {"action_taken": action_taken})
        return f"✅ Đã resolve report `{report_id[:8]}`."

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

    # ── ban_user ──────────────────────────────────────────────────────────────
    if tool == "ban_user":
        user_id = inp.get("user_id","")
        reason  = inp.get("reason","")
        level   = int(inp.get("level",1))
        return _ban_user_internal(user_id, reason, level)

    # ── unban_user ────────────────────────────────────────────────────────────
    if tool == "unban_user":
        user_id = inp.get("user_id","")
        reason  = inp.get("reason","Admin mở khóa")
        return _unban_user_internal(user_id, reason)

    # ── get_audit_log ─────────────────────────────────────────────────────────
    if tool == "get_audit_log":
        action_filter = inp.get("action","")
        target_id     = inp.get("target_id","")
        days          = int(inp.get("days",30))
        limit         = int(inp.get("limit",50))
        since_iso = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - days*86400, tz=timezone.utc
        ).isoformat()

        q = supabase.table("audit_logs").select("*").gte("created_at", since_iso)
        if action_filter:
            q = q.eq("action", action_filter)
        if target_id:
            q = q.eq("target_id", target_id)
        r = q.order("created_at",desc=True).limit(limit).execute()

        if not r.data:
            return f"✅ Không có audit log nào trong {days} ngày qua khớp bộ lọc."
        lines = [f"📝 **{len(r.data)} bản ghi audit log ({days} ngày qua):**\n"]
        for l in r.data:
            lines.append(
                f"🕐 {l['created_at'][:16]} | 👤 actor: {l.get('actor','ai')}\n"
                f"⚡ {l['action']} → {l.get('target_type','?')} `{(l.get('target_id') or '')[:8]}`\n"
                f"💬 {l.get('reason','(không có)')}\n---"
            )
        return "\n".join(lines)

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
        dq   = supabase.table("questions").select("id",count="exact")\
               .not_.is_("deleted_at","null").execute()
        da   = supabase.table("answers").select("id",count="exact")\
               .not_.is_("deleted_at","null").execute()
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
            f"♻️  Đang xóa mềm (khôi phục được):\n"
            f"  Câu hỏi   : {dq.count or 0}\n"
            f"  Câu trả lời: {da.count or 0}\n\n"
            f"🚫 Vi phạm đã xử lý: {len(logs.data or [])}\n"
            + "\n".join(f"  {k}: {v}" for k,v in l_counts.items()) +
            f"\n\n🚩 Báo cáo:\n"
            + "\n".join(f"  {k}: {v}" for k,v in r_counts.items()) +
            f"\n\n⚖️  Kháng cáo nội dung:\n"
            + "\n".join(f"  {k}: {v}" for k,v in a_counts.items()) +
            f"\n\n🔒 Kháng cáo ban:\n"
            + "\n".join(f"  {k}: {v}" for k,v in b_counts.items())
        )

    # ── get_violation_analytics ──────────────────────────────────────────────
    if tool == "get_violation_analytics":
        days = int(inp.get("days",30))
        since_iso = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - days*86400, tz=timezone.utc
        ).isoformat()

        logs = supabase.table("moderation_logs")\
            .select("user_id,ref_type,label,created_at,profiles(username)")\
            .gte("created_at",since_iso)\
            .order("created_at",desc=False).limit(500).execute()
        ld = logs.data or []

        if not ld:
            return f"✅ Không có vi phạm nào trong {days} ngày qua."

        top_users = Counter()
        by_type   = Counter()
        by_day    = Counter()
        uname_map = {}
        for l in ld:
            uid = l.get("user_id","?")
            top_users[uid] += 1
            by_type[l.get("ref_type","?")] += 1
            by_day[l.get("created_at","")[:10]] += 1
            if l.get("profiles"):
                uname_map[uid] = l["profiles"].get("username","?")

        result = f"📊 **PHÂN TÍCH VI PHẠM ({days} ngày qua, {len(ld)} bản ghi)**\n\n"
        result += "🔝 **Top 10 user vi phạm nhiều nhất:**\n"
        for uid, cnt in top_users.most_common(10):
            uname = uname_map.get(uid, uid[:8] if uid != "?" else "?")
            result += f"  • {uname} (`{uid[:8]}`): {cnt} lần\n"

        result += "\n📂 **Theo loại nội dung:**\n"
        for t, cnt in by_type.most_common():
            result += f"  • {t}: {cnt}\n"

        result += "\n📅 **Timeline theo ngày (10 ngày gần nhất có vi phạm):**\n"
        for day, cnt in sorted(by_day.items())[-10:]:
            result += f"  • {day}: {cnt} vi phạm\n"

        return result

    return f"Tool '{tool}' không tồn tại."

# ── Internal helpers dùng chung nhiều tool ───────────────────────────────────
def _check_confirm_token(token: str, expected_action: str, expected_payload: dict) -> bool:
    """Xác nhận token hợp lệ, chưa hết hạn, và payload khớp đúng với lúc request_bulk_action."""
    if not token or token not in _pending_confirms:
        return False
    entry = _pending_confirms[token]
    if entry["expires"] < time.time():
        del _pending_confirms[token]
        return False
    if entry["action"] != expected_action:
        return False
    # So khớp payload dạng JSON để tránh dùng token của 1 lô khác cho lô này
    if json.dumps(entry["payload"], sort_keys=True) != json.dumps(expected_payload, sort_keys=True):
        return False
    del _pending_confirms[token]  # dùng 1 lần
    return True

def _soft_delete_one(ref_id: str, ref_type: str, reason: str) -> str:
    """Xóa mềm 1 nội dung — set deleted_at thay vì xóa hẳn, lưu status cũ để restore đúng."""
    if ref_type == "question":
        r = supabase.table("questions").select("user_id,points_cost,title,status")\
            .eq("id",ref_id).single().execute()
        if not r.data: return "Không tìm thấy câu hỏi."
        supabase.table("questions").update({
            "status":"removed","removed_by_ai":True,
            "removed_reason":f"Admin: {reason}",
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "deleted_by": "ai",
            "status_before_delete": r.data.get("status"),
        }).eq("id",ref_id).execute()
        _refund_points(r.data["user_id"],r.data.get("points_cost",0),ref_id)
        _log_violation(r.data["user_id"],ref_id,"question","REMOVED",f"Admin: {reason}")
        send_notification(r.data["user_id"],"content_removed",
            "⚠️ Câu hỏi bị xóa bởi Admin",
            f'Câu hỏi "{r.data.get("title","")[:50]}" bị Admin xóa. Lý do: {reason}. '
            f'Nội dung có thể được khôi phục trong 30 ngày nếu kháng cáo thành công.',
            ref_id,"question")
    else:
        r = supabase.table("answers").select("user_id,body,moderation_status")\
            .eq("id",ref_id).single().execute()
        if not r.data: return "Không tìm thấy câu trả lời."
        supabase.table("answers").update({
            "moderation_status":"removed","removed_by_ai":True,
            "removed_reason":f"Admin: {reason}",
            "removed_content":r.data.get("body","")[:1000],
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "deleted_by": "ai",
            "moderation_status_before_delete": r.data.get("moderation_status"),
        }).eq("id",ref_id).execute()
        _log_violation(r.data["user_id"],ref_id,"answer","REMOVED",f"Admin: {reason}")
        send_notification(r.data["user_id"],"content_removed",
            "⚠️ Câu trả lời bị xóa bởi Admin",
            f'Câu trả lời bị Admin xóa. Lý do: {reason}. Có thể khôi phục trong 30 ngày nếu kháng cáo thành công.',
            ref_id,"answer")
    _audit("remove_content", ref_type, ref_id, reason)
    return f"🚫 Đã xóa mềm {ref_type} `{ref_id[:8]}` (khôi phục được trong 30 ngày)."

def _restore_one(ref_id: str, ref_type: str, reason: str) -> str:
    """Khôi phục nội dung đã xóa mềm — trả về đúng status trước khi xóa."""
    if ref_type == "question":
        r = supabase.table("questions").select("status_before_delete,deleted_at")\
            .eq("id",ref_id).single().execute()
        if not r.data: return "Không tìm thấy câu hỏi."
        if not r.data.get("deleted_at"):
            return "Câu hỏi này không ở trạng thái xóa mềm (có thể đã bị xóa vĩnh viễn hoặc chưa từng bị xóa)."
        restore_status = r.data.get("status_before_delete") or "open"
        supabase.table("questions").update({
            "status": restore_status,
            "removed_by_ai": False,
            "removed_reason": None,
            "deleted_at": None,
            "deleted_by": None,
            "status_before_delete": None,
        }).eq("id",ref_id).execute()
    else:
        r = supabase.table("answers").select("moderation_status_before_delete,deleted_at,user_id")\
            .eq("id",ref_id).single().execute()
        if not r.data: return "Không tìm thấy câu trả lời."
        if not r.data.get("deleted_at"):
            return "Câu trả lời này không ở trạng thái xóa mềm (có thể đã bị xóa vĩnh viễn hoặc chưa từng bị xóa)."
        restore_status = r.data.get("moderation_status_before_delete") or "approved"
        supabase.table("answers").update({
            "moderation_status": restore_status,
            "removed_by_ai": False,
            "removed_reason": None,
            "removed_content": None,
            "deleted_at": None,
            "deleted_by": None,
            "moderation_status_before_delete": None,
        }).eq("id",ref_id).execute()
    _audit("restore_content", ref_type, ref_id, reason)
    return f"♻️ Đã khôi phục {ref_type} `{ref_id[:8]}`."

def _ban_user_internal(user_id: str, reason: str, level: int) -> str:
    """Logic ban dùng chung cho ban_user đơn lẻ và bulk_ban_users."""
    is_ban = level >= 3
    p = supabase.table("profiles").select("ban_reason")\
        .eq("id",user_id).single().execute()
    old_reason = (p.data or {}).get("ban_reason") or ""
    today = datetime.now(timezone.utc).strftime("%d/%m/%Y")
    new_entry = f"[{today}] {reason}"
    combined_reason = f"{old_reason}\n{new_entry}" if old_reason else new_entry
    supabase.table("profiles").update({
        "violation_level": level,
        "is_banned"      : is_ban,
        "ban_reason"     : combined_reason,
    }).eq("id",user_id).execute()
    level_vi = {1:"Cảnh báo",2:"Nghiêm trọng",3:"Khóa tài khoản"}
    send_notification(user_id,"content_removed",
        f"⚠️ Tài khoản bị {'khóa' if is_ban else 'cảnh báo'}",
        f'Tài khoản ở mức {level_vi.get(level,"?")}. Lý do: {reason}. '
        f'{"Bạn có thể kháng cáo." if is_ban else "Hãy tuân thủ quy tắc cộng đồng."}',
        None,None)
    _audit("ban_user", "user", user_id, reason, {"level": level})
    return f"✅ Đã {'khóa' if is_ban else 'cảnh báo'} user `{user_id[:8]}` mức {level}."

def _unban_user_internal(user_id: str, reason: str) -> str:
    """Logic unban dùng chung cho unban_user đơn lẻ và bulk_unban_users."""
    supabase.table("profiles").update({
        "violation_level"   : 0,
        "is_banned"         : False,
        "ban_reason"        : None,
    }).eq("id",user_id).execute()
    send_notification(user_id,"appeal_approved",
        "✅ Tài khoản đã được mở khóa",
        f'Tài khoản đã mở khóa. Lý do: {reason}. Vui lòng tuân thủ quy tắc.',
        None,None)
    _audit("unban_user", "user", user_id, reason)
    return f"✅ Đã mở khóa user `{user_id[:8]}`."

def _audit(action: str, target_type, target_id, reason: str, metadata: dict = None):
    """Ghi 1 dòng vào audit_logs — không bao giờ raise để tránh làm hỏng hành động chính."""
    try:
        supabase.table("audit_logs").insert({
            "actor": "ai",
            "action": action,
            "target_type": target_type,
            "target_id": str(target_id) if target_id else None,
            "reason": reason,
            "metadata": metadata or {},
        }).execute()
    except Exception as e:
        print(f"  ⚠️  Audit log error: {e}")

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
    try:
        a_count = supabase.table("answers")\
            .select("id",count="exact")\
            .eq("user_id",user_id)\
            .eq("moderation_status","approved").execute()
        a_total = a_count.count or 0

        acc_count = supabase.table("answers")\
            .select("id",count="exact")\
            .eq("user_id",user_id)\
            .eq("is_accepted",True).execute()
        acc_total = acc_count.count or 0

        p = supabase.table("profiles").select("points")\
            .eq("id",user_id).single().execute()
        points = p.data["points"] if p.data else 0

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
        qs = supabase.table("questions")\
            .select("id,title,body,user_id,points_cost")\
            .eq("status","pending")\
            .is_("removed_reason","null")\
            .limit(BATCH_SIZE).execute()

        ans = supabase.table("answers")\
            .select("id,body,user_id,question_id")\
            .eq("moderation_status","pending")\
            .is_("removed_reason","null")\
            .limit(BATCH_SIZE).execute()

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
        if itype == "report":
            supabase.table("reports")\
                .update({"status":"processing"})\
                .eq("id",data["id"]).execute()

            if data["ref_type"] == "question":
                supabase.table("questions")\
                    .update({"is_under_review":True})\
                    .eq("id",data["ref_id"]).execute()
            else:
                supabase.table("answers")\
                    .update({"is_under_review":True})\
                    .eq("id",data["ref_id"]).execute()

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

            if data.get("reporter_id"):
                send_notification(data["reporter_id"],"report_resolved",
                    "📨 Báo cáo đã được tiếp nhận",
                    "Báo cáo của bạn đã được ghi nhận và sẽ được admin xem xét sớm.",
                    data["ref_id"],data["ref_type"])

            print(f"  🚩 Report {data['id'][:8]} → processing, content under review")
            return

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
                "serverInfo"     :{"name":"hoibai-panel","version":"6.0.0"},
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
        "serverInfo"     :{"name":"hoibai-panel","version":"6.0.0"},
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
                "serverInfo"     :{"name":"hoibai-panel","version":"6.0.0"},
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
        "version": "6.0.0",
    }

@app.get("/")
async def root():
    return {
        "service": "HoiBai Moderator",
        "version": "6.0.0",
        "mode"   : "manual_review via MCP",
        "mcp_url": f"{BASE_URL}/mcp",
    }
