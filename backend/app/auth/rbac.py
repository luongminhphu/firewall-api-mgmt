"""Vai trò và phân quyền: xếp hạng vai trò + dependency FastAPI (principal / require)."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.db import get_session
from ..core.security import verify_principal

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def csv_list(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def role_at_least(role: str, needed: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[needed]


def principal(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
    db: Session = Depends(get_session),
    request: Request = None,  # FastAPI tự truyền; gọi trực tiếp principal(token, db) vẫn được
) -> dict:
    from .users import service as um

    p = verify_principal(x_auth_token or "")
    if not p:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc session đã hết hạn")
    out = {"user": p["u"], "name": p.get("n") or p["u"], "role": p["r"], "method": p.get("m", "local"),
           "managed": False}
    # Quyền lấy lại từ DB ở MỌI request → khóa / hạ quyền / xóa user có hiệu lực ngay, không chờ token hết hạn.
    if out["method"] != "shared":
        u = um.find(db, out["user"])
        if u:
            if not u.enabled:
                raise HTTPException(401, "Tài khoản đã bị khóa — liên hệ quản trị viên")
            out.update(role=u.role, name=u.display_name or out["name"], managed=True,
                       auth_type=u.auth_type)
        elif p.get("s") == "db":
            raise HTTPException(401, "Tài khoản không còn tồn tại — liên hệ quản trị viên")
        elif settings.USERS_STRICT and out["method"].startswith("entra"):
            raise HTTPException(401, "Tài khoản chưa có trong danh sách người dùng của app")
    if request is not None:
        request.state.actor = out["user"]  # dòng log truy cập (LOG_FORMAT=json) ghi kèm người dùng
    return out


def current_user(p: dict = Depends(principal)) -> str:
    return p["user"]


def require(role: str):
    def dep(p: dict = Depends(principal)) -> dict:
        if not role_at_least(p["role"], role):
            raise HTTPException(403, f"Vai trò '{p['role']}' không đủ quyền (cần '{role}')")
        return p
    return dep


def operator(p: dict = Depends(require("operator"))) -> dict:
    return p


def admin(p: dict = Depends(require("admin"))) -> dict:
    return p
