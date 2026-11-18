"""Shim tương thích — dùng `app.modules.ipblock.parse`. Xóa ở bước 1.9 (docs/architecture.md)."""
import sys as _sys

from .modules.ipblock import parse as _m

_sys.modules[__name__] = _m
