"""Shim tương thích — dùng `app.modules.ipblock.service`. Xóa ở bước 1.9 (docs/architecture.md)."""
import sys as _sys

from .modules.ipblock import service as _m

_sys.modules[__name__] = _m
