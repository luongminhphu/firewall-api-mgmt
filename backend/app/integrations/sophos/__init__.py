"""Sophos Firewall XML API. Mọi lệnh gửi firewall đi qua `policy.check_request` (điểm chặn duy nhất)."""
from __future__ import annotations

from .client import (  # noqa: F401
    ERR_API_DISABLED, ERR_IP_NOT_ALLOWED, STATUS_TEXT, BaseClient, OpResult, SophosAuthError, SophosError,
)
from .entities.iphost import IPHostMixin
from .entities.iphostgroup import IPHostGroupMixin
from .xmlutil import HOST_NAME_MAX, IP_FAMILIES, build_iphostgroup_xml, pretty_xml, validate_group_name  # noqa: F401


class SophosClient(IPHostMixin, IPHostGroupMixin, BaseClient):
    """Client đầy đủ: kết nối (BaseClient) + thao tác IPHost / IPHostGroup."""
