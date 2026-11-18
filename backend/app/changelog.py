"""Shim tương thích — dùng `app.modules.ipblock.changelog`. Xóa ở bước 1.9 (docs/architecture.md)."""
import sys as _sys

from .modules.ipblock import changelog as _m

_sys.modules[__name__] = _m
