"""Shim tương thích — dùng `app.core.jobs`. Xóa ở bước 1.9 (docs/architecture.md)."""
import sys as _sys

from .core import jobs as _m

_sys.modules[__name__] = _m
