"""Shim tương thích — dùng `app.core.security`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .core.security import (  # noqa: F401
    ROLES, MasterKeyMissing, decrypt, encrypt, issue_token, verify_principal, verify_token,
)
