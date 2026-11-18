"""Shim tương thích — dùng `app.auth.users.service`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .auth.users.service import *  # noqa: F401,F403
