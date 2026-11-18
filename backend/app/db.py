"""Shim tương thích — dùng `app.core.db` / `app.core.models`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .core.db import Base, SessionLocal, engine, get_session, init_db  # noqa: F401
from .core.models import (  # noqa: F401
    AppSetting, AppUser, AuditLog, Firewall, GroupCache, GroupChange, GroupSnapshot, Job,
)
