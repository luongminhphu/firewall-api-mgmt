"""Shim tương thích — dùng `app.core.config`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .core.config import Settings, settings  # noqa: F401
