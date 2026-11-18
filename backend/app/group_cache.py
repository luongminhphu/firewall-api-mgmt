"""Shim tương thích — dùng `app.modules.ipblock.group_cache`. Xóa ở bước 1.9 (docs/architecture.md)."""
import sys as _sys

from .modules.ipblock import group_cache as _m

_sys.modules[__name__] = _m
