# ── MCP Server Endpoints ──────────────────────────────────────────────────────
# Claude.ai gọi các tool này để admin duyệt

from fastapi import Header

MCP_SECRET = os.getenv("MCP_SECRET", "")  # Thêm vào Railway variables

def verify_mcp(authorization: str = Header(None)):
    """Xác thực request từ Claude MCP"""
    if MCP_SECRET and authorization != f"Bearer {MCP_SECRET}":
        from fastapi import HTTPException
        raise HTTPException(401, "Unauthorized")

# ── MCP: List tools ───────────────────────────────────────────────────────────
@app.get("/mcp")
async def mcp_info():
    """MCP Server info — Claude.ai dùng để discover tools"""
    return {
        "name"       : "HoiBai Moderation",
        "description": "Quản lý kiểm duyệt nội dung HoiBai",
        "version"    : "1.0.0",
        "tools"      : [
            {
                "name"       : "list_pending_appeals",
                "description": "Xem danh sách kháng cáo đang chờ duyệt",
                "inputSchema": {"type":"object","properties":{}},
            },
            {
                "name"       : "list_pending_reports",
                "description": "Xem danh sách báo cáo vi phạm đang chờ xử lý",
                "inputSchema": {"type":"object","properties":{}},
            },
            {
                "name"       : "get_content_detail",
                "description": "Xem chi tiết nội dung (câu hỏi/câu trả lời) kèm ảnh",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"  : {"type":"string","description":"ID của câu hỏi hoặc câu trả lời"},
                        "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
                    },
                    "required": ["ref_id","ref_type"],
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
                "name"       : "remove_content",
                "description": "Xóa nội dung vi phạm (từ report hoặc xóa thẳng)",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"   : {"type":"string","description":"ID nội dung"},
                        "ref_type" : {"type":"string","description":"'question' hoặc 'answer'"},
                        "report_id": {"type":"string","description":"ID report (nếu có)"},
                        "reason"   : {"type":"string","description":"Lý do xóa"},
                    },
                    "required": ["ref_id","ref_type","reason"],
                },
            },
            {
                "name"       : "restore_content",
                "description": "Khôi phục nội dung bị xóa nhầm",
                "inputSchema": {
                    "type"      : "object",
                    "properties": {
                        "ref_id"  : {"type":"string","description":"ID nội dung"},
                        "ref_type": {"type":"string","description":"'question' hoặc 'answer'"},
                        "reason"  : {"type":"string","description":"Lý do khôi phục"},
                    },
                    "required": ["ref_id","ref_type","reason"],
                },
            },
            {
                "name"       : "get_stats",
                "description": "Xem thống kê tổng quan: vi phạm, báo cáo, kháng cáo",
                "inputSchema": {"type":"object","properties":{}},
            },
        ]
    }

# ── MCP: Execute tool ─────────────────────────────────────────────────────────
class MCPToolCall(BaseModel):
    tool : str
    input: dict = {}

@app.post("/mcp/call")
async def mcp_call(req: MCPToolCall,
                   authorization: str = Header(None)):
    verify_mcp(authorization)

    tool  = req.tool
    inp   = req.input

    # ── list_pending_appeals ──────────────────────────────────────────────────
    if tool == "list_pending_appeals":
        r = supabase.table("appeals")\
            .select("id,user_id,ref_id,ref_type,content,created_at,profiles(username)")\
            .eq("status","pending")\
            .order("created_at", desc=False)\
            .limit(20).execute()

        if not r.data:
            return {"result": "Không có kháng cáo nào đang chờ duyệt."}

        lines = [f"📋 **{len(r.data)} kháng cáo đang chờ:**\n"]
        for a in r.data:
            lines.append(
                f"🆔 `{a['id']}`\n"
                f"👤 User: {a['profiles']['username'] if a.get('profiles') else a['user_id'][:8]}\n"
                f"📌 Loại: {a['ref_type']} | ID: `{a['ref_id']}`\n"
                f"💬 Lý do kháng cáo: {a['content'][:200]}\n"
                f"🕐 Gửi: {a['created_at'][:16]}\n"
                f"---"
            )
        return {"result": "\n".join(lines)}

    # ── list_pending_reports ──────────────────────────────────────────────────
    if tool == "list_pending_reports":
        r = supabase.table("reports")\
            .select("id,ref_id,ref_type,reason,detail,created_at,profiles(username)")\
            .eq("status","pending")\
            .order("created_at", desc=False)\
            .limit(20).execute()

        if not r.data:
            return {"result": "Không có báo cáo nào đang chờ xử lý."}

        lines = [f"🚩 **{len(r.data)} báo cáo đang chờ:**\n"]
        for rep in r.data:
            lines.append(
                f"🆔 `{rep['id']}`\n"
                f"👤 Người báo cáo: {rep['profiles']['username'] if rep.get('profiles') else '?'}\n"
                f"📌 Loại: {rep['ref_type']} | ID: `{rep['ref_id']}`\n"
                f"⚠️  Lý do: {rep['reason']}\n"
                f"📝 Chi tiết: {rep.get('detail') or '(không có)'}\n"
                f"🕐 Gửi: {rep['created_at'][:16]}\n"
                f"---"
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
                f"🖼️  Ảnh: {q.get('image_url') or '(không có ảnh)'}\n"
                f"📊 Status: {q.get('status','')}\n"
                f"🤖 Bị AI xóa: {'Có' if q.get('removed_by_ai') else 'Không'}\n"
                f"❓ Lý do xóa: {q.get('removed_reason') or '(chưa xóa)'}\n"
                f"👁️  Lượt xem: {q.get('views',0)}\n"
                f"⭐ Điểm thưởng: {q.get('points_cost',0)}\n"
                f"🕐 Đăng: {q.get('created_at','')[:16]}"
            )
            if q.get('image_url'):
                result += f"\n\n🖼️  **Link ảnh để xem:** {q['image_url']}"

        else:  # answer
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
                f"🖼️  Ảnh: {a.get('image_url') or '(không có ảnh)'}\n"
                f"📊 Status: {a.get('moderation_status','')}\n"
                f"🤖 Bị AI xóa: {'Có' if a.get('removed_by_ai') else 'Không'}\n"
                f"❓ Lý do xóa: {a.get('removed_reason') or '(chưa xóa)'}\n"
                f"🕐 Đăng: {a.get('created_at','')[:16]}"
            )
            if a.get('image_url'):
                result += f"\n\n🖼️  **Link ảnh để xem:** {a['image_url']}"

        return {"result": result}

    # ── approve_appeal ────────────────────────────────────────────────────────
    if tool == "approve_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin chấp nhận kháng cáo")

        # Lấy appeal
        ap = supabase.table("appeals")\
            .select("*").eq("id", appeal_id).single().execute()
        if not ap.data:
            return {"result": "Không tìm thấy kháng cáo."}

        a        = ap.data
        ref_id   = a["ref_id"]
        ref_type = a["ref_type"]

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()

        # Cập nhật appeal
        supabase.table("appeals").update({
            "status"     : "approved",
            "review_note": reason,
            "reviewed_at": now,
        }).eq("id", appeal_id).execute()

        # Khôi phục nội dung
        if ref_type == "question":
            # Lấy points_cost để hoàn điểm
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

        # Thông báo user
        send_notification(
            user_id   = a["user_id"],
            ntype     = "appeal_approved",
            title     = "✅ Kháng cáo thành công! (Admin duyệt)",
            message   = f'Admin đã xem xét và chấp nhận kháng cáo của bạn. '
                       f'Nội dung đã được khôi phục. Lý do: {reason}',
            ref_id    = ref_id,
            ref_type  = ref_type,
            appeal_id = appeal_id,
        )

        return {"result": f"✅ Đã chấp nhận kháng cáo `{appeal_id[:8]}`. Nội dung đã được khôi phục và thông báo gửi cho user."}

    # ── reject_appeal ─────────────────────────────────────────────────────────
    if tool == "reject_appeal":
        appeal_id = inp.get("appeal_id","")
        reason    = inp.get("reason","Admin từ chối kháng cáo")

        ap = supabase.table("appeals")\
            .select("*").eq("id", appeal_id).single().execute()
        if not ap.data:
            return {"result": "Không tìm thấy kháng cáo."}

        from datetime import datetime, timezone
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

        return {"result": f"❌ Đã từ chối kháng cáo `{appeal_id[:8]}`. Thông báo đã gửi cho user."}

    # ── remove_content ────────────────────────────────────────────────────────
    if tool == "remove_content":
        ref_id    = inp.get("ref_id","")
        ref_type  = inp.get("ref_type","")
        report_id = inp.get("report_id","")
        reason    = inp.get("reason","Admin xóa nội dung vi phạm")

        if ref_type == "question":
            q = supabase.table("questions")\
                .select("user_id,points_cost,title")\
                .eq("id", ref_id).single().execute()
            if not q.data:
                return {"result": "Không tìm thấy câu hỏi."}
            supabase.table("questions").update({
                "status"         : "removed",
                "removed_by_ai"  : True,
                "removed_reason" : f"Admin: {reason}",
            }).eq("id", ref_id).execute()
            _refund_points(q.data["user_id"],
                           q.data.get("points_cost",0), ref_id)
            send_notification(
                user_id  = q.data["user_id"],
                ntype    = "content_removed",
                title    = "⚠️ Câu hỏi bị xóa bởi Admin",
                message  = f'Câu hỏi "{q.data.get("title","")[:50]}" '
                          f'đã bị Admin xóa. Lý do: {reason}',
                ref_id   = ref_id,
                ref_type = "question",
            )
        else:
            supabase.table("answers").update({
                "moderation_status": "removed",
                "removed_by_ai"    : True,
                "removed_reason"   : f"Admin: {reason}",
            }).eq("id", ref_id).execute()
            a = supabase.table("answers")\
                .select("user_id").eq("id", ref_id).single().execute()
            if a.data:
                send_notification(
                    user_id  = a.data["user_id"],
                    ntype    = "content_removed",
                    title    = "⚠️ Câu trả lời bị xóa bởi Admin",
                    message  = f'Câu trả lời của bạn đã bị Admin xóa. Lý do: {reason}',
                    ref_id   = ref_id,
                    ref_type = "answer",
                )

        # Đánh dấu report resolved nếu có
        if report_id:
            supabase.table("reports")\
                .update({"status":"resolved"})\
                .eq("id", report_id).execute()

        return {"result": f"🚫 Đã xóa {ref_type} `{ref_id[:8]}`. Thông báo đã gửi cho user."}

    # ── restore_content ───────────────────────────────────────────────────────
    if tool == "restore_content":
        ref_id   = inp.get("ref_id","")
        ref_type = inp.get("ref_type","")
        reason   = inp.get("reason","Admin khôi phục nội dung")

        if ref_type == "question":
            q = supabase.table("questions")\
                .select("user_id,points_cost")\
                .eq("id", ref_id).single().execute()
            if not q.data:
                return {"result": "Không tìm thấy câu hỏi."}
            supabase.table("questions").update({
                "status"        : "open",
                "removed_by_ai" : False,
                "removed_reason": None,
            }).eq("id", ref_id).execute()
            if q.data.get("points_cost"):
                _refund_points(q.data["user_id"],
                               q.data["points_cost"], ref_id)
            send_notification(
                user_id  = q.data["user_id"],
                ntype    = "appeal_approved",
                title    = "✅ Câu hỏi được khôi phục bởi Admin",
                message  = f'Admin đã khôi phục câu hỏi của bạn. Lý do: {reason}',
                ref_id   = ref_id,
                ref_type = "question",
            )
        else:
            a = supabase.table("answers")\
                .select("user_id").eq("id", ref_id).single().execute()
            supabase.table("answers").update({
                "moderation_status": "approved",
                "removed_by_ai"    : False,
                "removed_reason"   : None,
            }).eq("id", ref_id).execute()
            if a.data:
                send_notification(
                    user_id  = a.data["user_id"],
                    ntype    = "appeal_approved",
                    title    = "✅ Câu trả lời được khôi phục bởi Admin",
                    message  = f'Admin đã khôi phục câu trả lời của bạn. Lý do: {reason}',
                    ref_id   = ref_id,
                    ref_type = "answer",
                )

        return {"result": f"✅ Đã khôi phục {ref_type} `{ref_id[:8]}`. Thông báo đã gửi cho user."}

    # ── get_stats ─────────────────────────────────────────────────────────────
    if tool == "get_stats":
        from collections import Counter
        logs  = supabase.table("moderation_logs").select("label,ref_type").execute()
        rpts  = supabase.table("reports").select("status").execute()
        apps  = supabase.table("appeals").select("status").execute()
        notifs= supabase.table("notifications").select("type,is_read").execute()

        r_counts = Counter(r["status"] for r in (rpts.data or []))
        a_counts = Counter(a["status"] for a in (apps.data or []))
        l_counts = Counter(l["label"]  for l in (logs.data or []))

        result = (
            f"📊 **THỐNG KÊ HỆ THỐNG**\n\n"
            f"🚫 **Vi phạm đã xử lý:** {len(logs.data or [])}\n"
            + "\n".join(f"  - {k}: {v}" for k,v in l_counts.items()) +
            f"\n\n🚩 **Báo cáo:**\n"
            + "\n".join(f"  - {k}: {v}" for k,v in r_counts.items()) +
            f"\n\n⚖️  **Kháng cáo:**\n"
            + "\n".join(f"  - {k}: {v}" for k,v in a_counts.items()) +
            f"\n\n🔔 **Thông báo chưa đọc:** "
            f"{sum(1 for n in (notifs.data or []) if not n['is_read'])}"
        )
        return {"result": result}

    return {"result": f"Tool '{tool}' không tồn tại."}
