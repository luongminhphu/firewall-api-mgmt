"""Quản lý người dùng: băm mật khẩu, kiểm tra dữ liệu, chống dò mật khẩu.

Quyền:
  readonly — xem group, lịch sử, audit (vai trò nội bộ: viewer)
  write    — thêm: chặn / bỏ chặn IP, kiểm tra kết nối, đồng bộ (operator)
  is_admin — thêm: quản lý firewall và người dùng (admin, luôn kèm write)
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import re
import secrets
import threading
import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import AppUser

PERMISSIONS = ("write", "readonly")
AUTH_TYPES = ("local", "microsoft")
_ALGO = "pbkdf2_sha256"
_ITER = 310_000
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,119}$")


class UserError(ValueError):
    pass


# ------------------------------------------------------------ mật khẩu
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _ITER)
    return f"{_ALGO}${_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != _ALGO:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:  # noqa: BLE001
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))


def burn_time(pw: str) -> None:
    """Tốn thời gian như khi kiểm mật khẩu thật — không để lộ username nào tồn tại qua thời gian phản hồi."""
    verify_password(pw, _DUMMY_HASH)


def check_password_strength(pw: str, username: str = "") -> None:
    if len(pw or "") < settings.PASSWORD_MIN_LENGTH:
        raise UserError(f"Mật khẩu tối thiểu {settings.PASSWORD_MIN_LENGTH} ký tự")
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        raise UserError("Mật khẩu phải có cả chữ và số")
    if username and username.split("@")[0].lower() in pw.lower():
        raise UserError("Mật khẩu không được chứa tên đăng nhập")


# ------------------------------------------------------------ dữ liệu
def norm_username(v: str) -> str:
    u = (v or "").strip().lower()
    if not _USERNAME_RE.match(u):
        raise UserError("Tên đăng nhập 2–120 ký tự, chỉ gồm a-z, 0-9 và . _ @ - (vd phu.luong hoặc phu.luong@hsc.com.vn)")
    return u


def find(db: Session, username: str) -> AppUser | None:
    if not username:
        return None
    return db.scalar(select(AppUser).where(AppUser.username == username.strip().lower()))


def find_by_oid(db: Session, oid: str) -> AppUser | None:
    if not oid:
        return None
    return db.scalar(select(AppUser).where(AppUser.entra_oid == oid))


def count_admins(db: Session, exclude_id: int | None = None) -> int:
    stmt = select(func.count()).select_from(AppUser).where(AppUser.is_admin.is_(True), AppUser.enabled.is_(True))
    if exclude_id is not None:
        stmt = stmt.where(AppUser.id != exclude_id)
    return int(db.scalar(stmt) or 0)


def touch_login(db: Session, u: AppUser) -> None:
    u.last_login = dt.datetime.now(dt.timezone.utc)
    db.commit()


def apply_fields(u: AppUser, payload: dict, creating: bool) -> None:
    if "display_name" in payload or creating:
        u.display_name = (payload.get("display_name") or "").strip()[:120]
    if "auth_type" in payload or creating:
        at = (payload.get("auth_type") or "local").strip().lower()
        if at not in AUTH_TYPES:
            raise UserError("Loại đăng nhập phải là local hoặc microsoft")
        if at != u.auth_type:
            u.entra_oid = None  # đổi loại đăng nhập → gỡ liên kết tài khoản Microsoft cũ
        u.auth_type = at
    if "permission" in payload or creating:
        perm = (payload.get("permission") or "readonly").strip().lower()
        if perm not in PERMISSIONS:
            raise UserError("Quyền phải là Write hoặc Readonly")
        u.permission = perm
    if "is_admin" in payload or creating:
        u.is_admin = bool(payload.get("is_admin"))
    if u.is_admin:
        u.permission = "write"  # quản trị viên luôn có quyền ghi
    if "enabled" in payload or creating:
        u.enabled = bool(payload.get("enabled", True))
    if "note" in payload or creating:
        u.note = (payload.get("note") or "").strip()[:500]
    if u.auth_type == "microsoft":
        u.password_hash = ""  # tài khoản Microsoft không có mật khẩu trong app


# ------------------------------------------------------------ chống dò mật khẩu
_fails: dict[str, list[float]] = {}
_lock = threading.Lock()


def login_locked(key: str) -> int:
    """Số giây còn bị khóa (0 = không khóa)."""
    with _lock:
        rec = _fails.get(key)
        if not rec:
            return 0
        n, until = rec
        if until and until > time.time():
            return int(until - time.time()) + 1
        if until and until <= time.time():
            _fails.pop(key, None)
        return 0


def login_failed(key: str) -> None:
    with _lock:
        n, until = _fails.get(key, [0, 0.0])
        n += 1
        if n >= settings.LOGIN_MAX_FAILS:
            until = time.time() + settings.LOGIN_LOCK_MINUTES * 60
        _fails[key] = [n, until]


def login_ok(key: str) -> None:
    with _lock:
        _fails.pop(key, None)


def reset_throttle() -> None:
    with _lock:
        _fails.clear()
