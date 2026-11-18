"""Shim tương thích — dùng `app.integrations.sophos.policy`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .integrations.sophos.policy import (  # noqa: F401
    BLOCK_GROUP, BLOCK_GROUP_FAMILY, GroupPolicyError, enforce_group,
)
