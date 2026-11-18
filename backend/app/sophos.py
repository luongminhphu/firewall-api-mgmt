"""Shim tương thích — dùng `app.integrations.sophos`. Xóa ở bước 1.9 (docs/architecture.md)."""
from .integrations.sophos import (  # noqa: F401
    ERR_API_DISABLED, ERR_IP_NOT_ALLOWED, HOST_NAME_MAX, IP_FAMILIES, STATUS_TEXT, OpResult, SophosAuthError,
    SophosClient, SophosError, build_iphostgroup_xml, pretty_xml, validate_group_name,
)
