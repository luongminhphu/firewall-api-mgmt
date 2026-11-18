"""Đăng nhập (mật khẩu / Entra OIDC / header SSO) và /api/config."""
from __future__ import annotations

import hmac as _h
import urllib.parse

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..core.audit import audit
from ..core.config import settings
from ..core.db import get_session
from ..core.deps import client_ip_of
from ..core.security import issue_token
from ..integrations.sophos.policy import BLOCK_GROUP
from . import header_sso, oidc as sso
from .rbac import principal
from .users import service as um

router = APIRouter()


@router.get("/api/auth/modes")
def auth_modes():
    modes = settings.auth_modes
    ready, msg = sso.oidc_ready()
    return {
        "modes": modes,
        "local": "local" in modes,
        "oidc": "oidc" in modes,
        "oidc_ready": ready,
        "oidc_message": msg,
        "header": "header" in modes,
        "oidc_auto": settings.OIDC_AUTO_LOGIN and "oidc" in modes and ready,
    }


@router.post("/api/login")
def login(request: Request, payload: dict = Body(...), db: Session = Depends(get_session)):
    """Đăng nhập bằng mật khẩu: ưu tiên tài khoản riêng trong app; mật khẩu chung APP_PASSWORD là
    đường dự phòng (break-glass) và có thể tắt bằng SHARED_PASSWORD_LOGIN=false."""
    if "local" not in settings.auth_modes:
        raise HTTPException(403, "Đăng nhập bằng mật khẩu đã bị tắt — dùng tài khoản Microsoft")
    raw_user = (payload.get("user") or "soc").strip()[:120] or "soc"
    pw = payload.get("password") or ""
    key = raw_user.lower()
    ip = client_ip_of(request)

    def deny(msg: str, code: int = 401):
        um.login_failed(key)
        audit(db, action="login", fw=None, target="password", result="error", message=msg,
              actor=raw_user, client_ip=ip)
        db.commit()
        raise HTTPException(code, msg)

    wait = um.login_locked(key)
    if wait:
        raise HTTPException(429, f"Sai mật khẩu quá {settings.LOGIN_MAX_FAILS} lần — thử lại sau {wait // 60 + 1} phút")

    u = um.find(db, raw_user)
    if u:
        # Tài khoản đã có trong app → chỉ chấp nhận mật khẩu riêng (không dùng mật khẩu chung để mạo danh)
        if u.auth_type != "local" or not u.password_hash:
            um.burn_time(pw)
            deny("Tài khoản này đăng nhập bằng Microsoft, không dùng mật khẩu")
        if not um.verify_password(pw, u.password_hash):
            deny("Tên đăng nhập hoặc mật khẩu không đúng")
        if not u.enabled:
            deny("Tài khoản đã bị khóa — liên hệ quản trị viên", 403)
        um.login_ok(key)
        um.touch_login(db, u)
        tok = issue_token(u.username, role=u.role, method="local", name=u.display_name, src="db")
        audit(db, action="login", fw=None, target="password", result="ok",
              message=f"{u.display_name or u.username} · vai trò {u.role}", actor=u.username, client_ip=ip)
        db.commit()
        return {"token": tok, "user": u.username, "ttl_hours": settings.SESSION_TTL_HOURS}

    if not settings.SHARED_PASSWORD_LOGIN:
        um.burn_time(pw)
        deny("Tên đăng nhập hoặc mật khẩu không đúng")
    if not _h.compare_digest(pw.encode(), settings.APP_PASSWORD.encode()):
        deny("Tên đăng nhập hoặc mật khẩu không đúng")
    um.login_ok(key)
    tok = issue_token(raw_user[:60], role=settings.LOCAL_ROLE, method="shared")
    audit(db, action="login", fw=None, target="shared-password", result="ok",
          message=f"Mật khẩu chung · vai trò {settings.LOCAL_ROLE}", actor=raw_user[:60], client_ip=ip)
    db.commit()
    return {"token": tok, "user": raw_user[:60], "ttl_hours": settings.SESSION_TTL_HOURS}


def resolve_sso(db: Session, p: dict) -> dict:
    """Ghép danh tính Microsoft với danh sách người dùng của app.
    Có trong danh sách → dùng quyền của app; không có → dùng App Role/header (trừ khi USERS_STRICT)."""
    oid = p.get("oid") or ""
    u = um.find_by_oid(db, oid) if oid else None
    if u is None:
        u = um.find(db, p["user"])
        if u is not None:
            if u.auth_type != "microsoft":
                # Tài khoản mật khẩu trùng tên không được dùng cho đăng nhập Microsoft
                raise sso.AuthError("Tên này là tài khoản mật khẩu trong app, không phải tài khoản Microsoft")
            if u.entra_oid and u.entra_oid != oid:
                raise sso.AuthError("UPN này đã gắn với một tài khoản Entra khác (UPN bị tái sử dụng) — "
                                    "quản trị viên cần kiểm tra và tạo lại người dùng")
            if oid and not u.entra_oid:
                u.entra_oid = oid  # gắn oid ở lần đăng nhập đầu tiên
    elif u.auth_type != "microsoft":
        raise sso.AuthError("Liên kết Microsoft không hợp lệ cho tài khoản này")
    if u:
        if not u.enabled:
            raise sso.AuthError("Tài khoản đã bị khóa trong SOC Rapid Block — liên hệ quản trị viên")
        um.touch_login(db, u)
        return {**p, "user": u.username, "role": u.role, "name": u.display_name or p["name"], "src": "db"}
    if settings.USERS_STRICT:
        raise sso.AuthError("Tài khoản chưa có trong danh sách người dùng của SOC Rapid Block")
    if not p.get("role"):
        raise sso.AuthError(
            "Tài khoản chưa được cấp quyền: chưa có trong danh sách người dùng của app và chưa được gán App Role "
            f"({settings.ROLE_ADMIN} / {settings.ROLE_OPERATOR} / {settings.ROLE_VIEWER})"
        )
    return {**p, "src": ""}


_FLOW_COOKIE = "srb_oidc"


@router.get("/api/auth/oidc/login")
def oidc_login(hint: str = Query(default="")):
    if "oidc" not in settings.auth_modes:
        raise HTTPException(404, "Chưa bật đăng nhập Microsoft (AUTH_MODES)")
    try:
        url, cookie = sso.build_authorize_url(hint)
    except sso.AuthError as exc:
        raise HTTPException(500, str(exc)) from exc
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        _FLOW_COOKIE, cookie, max_age=600, httponly=True, samesite="lax",
        secure=settings.OIDC_REDIRECT_URI.startswith("https://"), path="/api/auth/oidc",
    )
    return resp


@router.get("/api/auth/oidc/callback")
def oidc_callback(
    request: Request,
    code: str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
    db: Session = Depends(get_session),
):
    def fail(msg: str):
        r = RedirectResponse("/#sso_error=" + urllib.parse.quote(msg[:300]), status_code=302)
        r.delete_cookie(_FLOW_COOKIE, path="/api/auth/oidc")
        audit(db, action="login", fw=None, target="entra-oidc", result="error", message=msg,
              actor="?", client_ip=client_ip_of(request))
        db.commit()
        return r

    if error:
        return fail(f"{error}: {error_description}")
    try:
        flow = sso.unpack_flow(request.cookies.get(_FLOW_COOKIE, ""))
        if not state or state != flow["s"]:
            raise sso.AuthError("Sai tham số state — yêu cầu đăng nhập không hợp lệ")
        p = resolve_sso(db, sso.exchange_code(code, flow))
    except sso.AuthError as exc:
        return fail(str(exc))
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"], src=p["src"])
    audit(db, action="login", fw=None, target="entra-oidc", result="ok",
          message=f"{p['name']} · vai trò {p['role']}", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    r = RedirectResponse("/#sso=" + urllib.parse.quote(tok), status_code=302)
    r.delete_cookie(_FLOW_COOKIE, path="/api/auth/oidc")
    return r


@router.post("/api/auth/header")
def header_login(request: Request, db: Session = Depends(get_session)):
    if "header" not in settings.auth_modes:
        raise HTTPException(404, "Chưa bật header SSO (AUTH_MODES)")
    peer = request.client.host if request.client else ""
    try:
        p = resolve_sso(db, header_sso.principal_from_headers(peer, request.headers))
    except sso.AuthError as exc:
        raise HTTPException(401, str(exc)) from exc
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"], src=p["src"])
    audit(db, action="login", fw=None, target="entra-header", result="ok",
          message=f"{p['name']} · vai trò {p['role']}", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    return {"token": tok, "user": p["user"], "name": p["name"], "role": p["role"]}


@router.get("/api/config")
def config(p: dict = Depends(principal)):
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "block_group": BLOCK_GROUP,
        "user": p["user"],
        "name": p["name"],
        "role": p["role"],
        "auth_method": p["method"],
        "managed_user": p.get("managed", False),
        "can_change_password": p.get("managed", False) and p.get("auth_type") == "local",
        "users_strict": settings.USERS_STRICT,
        "shared_password_login": settings.SHARED_PASSWORD_LOGIN,
        "host_prefix": settings.HOST_PREFIX,
        "safe_list": [s.strip() for s in settings.SAFE_LIST.split(",") if s.strip()],
        "allow_private": settings.ALLOW_PRIVATE,
        "master_key_set": bool(settings.MASTER_KEY),
    }
