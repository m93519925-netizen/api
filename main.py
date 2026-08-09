# SUGGESTED FIXES FOR HOIBAI MODERATOR API
# Apply these patches to fix HIGH & MEDIUM priority issues

# ============================================================================
# FIX #1: Add httpx import (Line 1, after other imports)
# ============================================================================
"""
BEFORE:
import httpx
from fastapi import FastAPI, Header, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
...

AFTER:
"""
import os, re, asyncio, hashlib, time, base64, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import Counter

import httpx  # ← ADD THIS LINE
from fastapi import FastAPI, Header, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel


# ============================================================================
# FIX #2: Fix Authorization - Make it REQUIRED (Line ~960-965)
# ============================================================================
"""
BEFORE:
@app.post("/mcp")
async def mcp_endpoint(request: Request,
                       authorization: str = Header(None)):
    if authorization and authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Unauthorized")
    return await handle_jsonrpc(request)

AFTER:
"""
@app.post("/mcp")
async def mcp_endpoint(request: Request,
                       authorization: str = Header(...)):  # ← REQUIRED
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Invalid or missing authorization token")
    return await handle_jsonrpc(request)

@app.post("/messages")
async def messages_endpoint(request: Request,
                            authorization: str = Header(...)):  # ← REQUIRED
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Invalid or missing authorization token")
    return await handle_jsonrpc(request)

@app.get("/sse")
async def sse_endpoint(request: Request,
                       authorization: str = Header(...)):  # ← REQUIRED
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(401, "Invalid or missing authorization token")
    # ... rest of function


# ============================================================================
# FIX #3: Unify return type for get_image tool (Line ~420-480)
# ============================================================================
"""
BEFORE: get_image returns either str (error) or list (content blocks)
AFTER: Always return list[dict] for consistency
"""
# ── get_image (FIXED) ──────────────────────────────────────────────────────
if tool == "get_image":
    image_url = inp.get("image_url", "").strip()
    if not image_url:
        return [{"type": "text", "text": "❌ Thiếu image_url."}]  # ← Wrap in list
    
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
            error_msg = f"❌ Không tải được ảnh (HTTP {resp.status_code})."
            return [{"type": "text", "text": error_msg}]  # ← Wrap in list
        
        # FIX: Kiểm tra content-type chính xác hơn
        content_type = resp.headers.get("content-type", "image/jpeg").lower()
        
        # Xử lý content-type với charset
        if ";" in content_type:
            content_type = content_type.split(";")[0].strip()
        
        # Nếu vẫn empty hoặc không phải image, guess từ URL
        if not content_type.startswith("image/"):
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
            size_mb = len(resp.content) / (1024 * 1024)
            error_msg = f"❌ Ảnh quá lớn ({size_mb:.1f}MB > 5MB)."
            return [{"type": "text", "text": error_msg}]  # ← Wrap in list
        
        b64 = base64.b64encode(resp.content).decode()
        size_kb = len(resp.content) // 1024
        
        # FIX: Luôn trả list[dict] - CONSISTENT!
        return [
            {
                "type": "text",
                "text": f"🖼️ Ảnh ({size_kb} KB | {content_type})\nURL: {image_url}",
            },
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": content_type,
                    "data": b64,
                },
            },
        ]
    
    except httpx.TimeoutException:
        return [{"type": "text", "text": "❌ Timeout khi tải ảnh (quá 15 giây)."}]
    
    except httpx.ConnectError:
        return [{"type": "text", "text": "❌ Không thể kết nối đến URL ảnh."}]
    
    except Exception as e:
        error_msg = f"❌ Lỗi tải ảnh: {str(e)[:100]}"
        return [{"type": "text", "text": error_msg}]  # ← Wrap in list


# ============================================================================
# FIX #4: Add safe access helper for nested Supabase objects
# ============================================================================
def safe_get_nested(obj, *keys, default=None):
    """
    Safely navigate nested dicts/objects
    
    Example:
        username = safe_get_nested(question, 'profiles', 'username', default='Unknown')
    """
    current = obj
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif current is None:
            return default
        else:
            return default
    
    return current if current is not None else default


# ============================================================================
# FIX #5: Apply safe access to list_flagged (Line ~180-210)
# ============================================================================
"""
BEFORE:
for q in r.data:
    lines.append(
        f"🆔 `{q['id']}`\n"
        f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"  # ← Unsafe
        ...
    )

AFTER:
"""
if content_type in ("question", "all"):
    r = supabase.table("questions")\
        .select("id,title,user_id,removed_reason,created_at,profiles(username)")\
        .eq("status","pending")\
        .neq("removed_reason","null")\
        .order("created_at", desc=False).limit(20).execute()
    
    if r.data:
        lines.append(f"📚 **{len(r.data)} CÂU HỎI bị gắn cờ:**\n")
        for q in r.data:
            username = safe_get_nested(q, 'profiles', 'username', default='Unknown')
            title = q.get('title', '')[:100]
            reason = q.get('removed_reason', 'N/A')
            created = q.get('created_at', '')[:16]
            
            lines.append(
                f"🆔 `{q['id']}`\n"
                f"👤 {username}\n"
                f"📋 {title}\n"
                f"🚩 {reason}\n"
                f"🕐 {created}\n---"
            )


# ============================================================================
# FIX #6: Apply safe access to get_content_detail (Line ~220-260)
# ============================================================================
"""
BEFORE:
return (
    f"👤 {q['profiles']['username'] if q.get('profiles') else '?'}\n"
)

AFTER:
"""
if ref_type == "question":
    r = supabase.table("questions")\
        .select("*,profiles(username)").eq("id", ref_id).single().execute()
    
    if not r.data:
        return [{"type": "text", "text": "Không tìm thấy câu hỏi."}]
    
    q = r.data
    username = safe_get_nested(q, 'profiles', 'username', default='Unknown')
    
    return (
        f"📚 **CÂU HỎI**\n🆔 `{q['id']}`\n"
        f"👤 {username}\n"  # ← SAFE
        f"📌 {q.get('grade_group','')} | {q.get('subject','')}\n"
        f"📋 {q.get('title','')}\n"
        f"📄 {q.get('body','') or '(không có)'}\n"
        f"🖼️ {q.get('image_url') or '(không có ảnh)'}\n"
        f"📊 {q.get('status','')} | 🚩 {q.get('removed_reason') or '(chưa gắn cờ)'}\n"
        f"👁️ {q.get('views',0)} lượt | ⭐ {q.get('points_cost',0)} điểm\n"
        f"🕐 {q.get('created_at','')[:16]}"
    )


# ============================================================================
# FIX #7: Fix Supabase `.not_.is_()` syntax
# ============================================================================
"""
BEFORE:
r = supabase.table("questions")\
    .select("...") \
    .not_.is_("removed_reason","null") \
    ...

AFTER: Use standard Supabase syntax
"""
# Option 1: Use .neq() for "not equals None"
r = supabase.table("questions")\
    .select("id,title,user_id,removed_reason,created_at,profiles(username)")\
    .eq("status","pending")\
    .neq("removed_reason", None)\
    .order("created_at", desc=False).limit(20).execute()

# Option 2: If above doesn't work, use filter()
# r = supabase.table("questions")\
#     .select("...")\
#     .eq("status","pending")\
#     .filter("removed_reason", "is.not", "null")\
#     .order("created_at", desc=False).limit(20).execute()


# ============================================================================
# FIX #8: Improve exception handling in helpers
# ============================================================================
"""
BEFORE:
except Exception as e:
    print(f"⚠️ Notification error: {e}")

AFTER: More specific exception handling
"""
def send_notification(user_id, ntype, title, message,
                      ref_id=None, ref_type=None, appeal_id=None):
    try:
        supabase.table("notifications").insert({
            "user_id": user_id,
            "type": ntype,
            "title": title,
            "message": message,
            "ref_id": ref_id,
            "ref_type": ref_type,
            "appeal_id": appeal_id,
        }).execute()
    except ValueError as e:
        print(f"⚠️ Invalid notification data: {e}")
    except ConnectionError as e:
        print(f"⚠️ Database connection error: {e}")
    except Exception as e:
        print(f"❌ Unexpected notification error: {str(e)[:200]}")


# ============================================================================
# FIX #9: requirements.txt updates
# ============================================================================
"""
Add or update your requirements.txt:
"""
fastapi>=0.104.0
uvicorn>=0.24.0
pydantic>=2.0.0
httpx>=0.24.0
python-multipart>=0.0.6
supabase>=2.0.0
python-dotenv>=1.0.0

# ============================================================================
# Summary of Changes
# ============================================================================
"""
✅ FIX #1: Added httpx import (or update requirements.txt)
✅ FIX #2: Made Authorization header REQUIRED (not optional)
✅ FIX #3: Unified return type for get_image - always return list[dict]
✅ FIX #4: Added safe_get_nested() helper function
✅ FIX #5: Applied safe access to list_flagged queries
✅ FIX #6: Applied safe access to get_content_detail queries
✅ FIX #7: Fixed Supabase filter syntax (.neq instead of .not_.is_)
✅ FIX #8: Improved exception handling specificity
✅ FIX #9: Updated requirements.txt with httpx

REMAINING (LOW priority):
- Issue #8: Multi-byte character truncation (safe slice)
- Issue #9: Verify count='exact' syntax with Supabase SDK
- Issue #10: Add SSE connection timeout handling
"""
