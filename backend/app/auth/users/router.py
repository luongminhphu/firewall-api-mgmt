"""Quản lý người dùng của app (/api/users) và tự đổi mật khẩu (/api/me/password)."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.db import get_session
from ...core.deps import client_ip_of
from ...core.models import AppUser
from ..rbac import admin, principal
from . import service as um

router = APIRouter()


def _get_user(db: Session, uid: int) -> AppUser:
    u = db.get(AppUser, uid)
    if not u:
        raise HTTPException(404, f"Không tìm thấy người dùng id={uid}")
    return u


def _user_audit(db: Session, request: Request, actor: str, target: str, msg: str, result: str = "ok"):
    audit(db, action="user_mgmt", fw=None, target=target[:120], result=result, message=msg[:500],
          actor=actor, client_ip=client_ip_of(request))


@router.get("/api/users")
def list_users(db: Session = Depends(get_session), p: dict = Depends(admin)):
    rows = db.scalars(select(AppUser).order_by(AppUser.username)).all()
    return {"users": [u.to_dict() for u in rows], "users_strict": settings.USERS_STRICT,
            "shared_password_login": settings.SHARED_PASSWORD_LOGIN,
            "password_min_length": settings.PASSWORD_MIN_LENGTH}


@router.post("/api/users")
def create_user(request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    try:
        username = um.norm_username(payload.get("username") or "")
        if um.find(db, username):
            raise um.UserError(f"Tên đăng nhập '{username}' đã tồn tại")
        u = AppUser(username=username, created_by=p["user"])
        um.apply_fields(u, payload, creating=True)
        if u.auth_type == "local":
            pw = payload.get("password") or ""
            um.check_password_strength(pw, username)
            u.password_hash = um.hash_password(pw)
    except um.UserError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.add(u)
    db.commit()
    _user_audit(db, request, p["user"], username,
                f"Tạo người dùng · {u.auth_type} · quyền {u.permission}{' · quản trị' if u.is_admin else ''}"
                f"{'' if u.enabled else ' · đang khóa'}")
    db.commit()
    return u.to_dict()


@router.put("/api/users/{uid}")
def update_user(uid: int, request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    u = _get_user(db, uid)
    before = u.to_dict()
    is_self = u.username == p["user"]
    try:
        old_type = u.auth_type
        um.apply_fields(u, {k: v for k, v in payload.items() if k != "username"}, creating=False)
        if is_self and (not u.is_admin or not u.enabled):
            raise um.UserError("Không thể tự bỏ quyền quản trị hoặc tự khóa tài khoản của chính mình")
        if before["is_admin"] and before["enabled"] and not (u.is_admin and u.enabled) \
                and um.count_admins(db, exclude_id=u.id) == 0:
            raise um.UserError("Phải còn ít nhất một quản trị viên đang hoạt động")
        pw = payload.get("password") or ""
        if u.auth_type == "local" and (pw or (old_type != "local" and not u.password_hash)):
            if not pw:
                raise um.UserError("Chuyển sang tài khoản nội bộ cần đặt mật khẩu")
            um.check_password_strength(pw, u.username)
            u.password_hash = um.hash_password(pw)
    except um.UserError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    u.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    after = u.to_dict()
    changes = [f"{k}: {before[k]} → {after[k]}" for k in ("display_name", "auth_type", "permission", "is_admin",
                                                         "enabled", "note") if before[k] != after[k]]
    if payload.get("password"):
        changes.append("đặt lại mật khẩu")
    _user_audit(db, request, p["user"], u.username, "Sửa người dùng · " + ("; ".join(changes) or "không đổi"))
    db.commit()
    return after


@router.delete("/api/users/{uid}")
def delete_user(uid: int, request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    u = _get_user(db, uid)
    if u.username == p["user"]:
        raise HTTPException(400, "Không thể tự xóa tài khoản của chính mình")
    if u.is_admin and u.enabled and um.count_admins(db, exclude_id=u.id) == 0:
        raise HTTPException(400, "Phải còn ít nhất một quản trị viên đang hoạt động")
    name = u.username
    db.delete(u)
    db.commit()
    _user_audit(db, request, p["user"], name, "Xóa người dùng — các phiên đăng nhập của tài khoản này bị vô hiệu ngay")
    db.commit()
    return {"deleted": name}


@router.post("/api/me/password")
def change_my_password(request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                       p: dict = Depends(principal)):
    u = um.find(db, p["user"])
    if not u or u.auth_type != "local":
        raise HTTPException(400, "Chỉ tài khoản nội bộ của app mới đổi được mật khẩu tại đây")
    if not um.verify_password(payload.get("current_password") or "", u.password_hash):
        _user_audit(db, request, p["user"], u.username, "Đổi mật khẩu thất bại — sai mật khẩu hiện tại", "error")
        db.commit()
        raise HTTPException(400, "Mật khẩu hiện tại không đúng")
    try:
        um.check_password_strength(payload.get("new_password") or "", u.username)
    except um.UserError as exc:
        raise HTTPException(400, str(exc)) from exc
    u.password_hash = um.hash_password(payload["new_password"])
    u.updated_at = dt.datetime.now(dt.timezone.utc)
    _user_audit(db, request, p["user"], u.username, "Tự đổi mật khẩu")
    db.commit()
    return {"ok": True}
