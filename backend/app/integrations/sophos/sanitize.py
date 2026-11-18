"""Lọc dữ liệu đọc từ firewall theo ALLOWLIST trường — docs/architecture.md §5.3.

Phản hồi XML của User / VPNIPSecConnection chứa Password, PasswordHash, PresharedKey, RemoteRSAKey…
Mỗi entity có một hàm trích CHỈ các trường liệt kê dưới đây; phần còn lại của phản hồi bị bỏ ngay tại tầng
integration, không bao giờ tới DB, log hay API. `assert_no_secret` là lưới an toàn thứ hai trên kết quả.
"""
from __future__ import annotations

import logging
import re

from .xmlutil import _as_list

log = logging.getLogger("sophos.sanitize")

# Tài liệu: trường nguồn (XML SFOS 22.0) được phép đọc cho từng entity
ALLOWED_FIELDS = {
    "User": ["Username", "Name", "UserType", "EmailList/EmailID", "Group", "Description", "SSLVPNPolicy",
             "ClientlessPolicy", "Status"],
    "UserGroup": ["GroupDetail/Name", "GroupDetail/GroupType", "GroupDetail/SSLVPNPolicy", "GroupMembers/UserName"],
    "SSLVPNPolicy": ["TunnelPolicy/Name", "TunnelPolicy/Description", "TunnelPolicy/PolicyMembers/Member",
                     "TunnelPolicy/PermittedNetworkResourcesIPv4/Resource"],
    "VPNIPSecConnection": ["Configuration/Name", "Configuration/Description", "Configuration/ConnectionType",
                           "Configuration/Policy", "Configuration/AllowedUser/User", "Configuration/Status"],
}

SECRET_KEY_RE = re.compile(r"pass|secret|psk|otp|token|hash|private|rsakey|presharedkey|credential", re.I)


class SecretLeak(ValueError):
    """Kết quả sau lọc vẫn còn khóa mang tên trường bí mật (lỗi lập trình)."""


def _t(v) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):  # phần tử có thuộc tính: {"@x": .., "#text": ..}
        v = v.get("#text", "")
    return str(v).strip()


def _texts(v) -> list[str]:
    return [t for t in (_t(x) for x in _as_list(v)) if t]


def _get(node: dict, path: str):
    cur = node
    for part in path.split("/"):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def assert_no_secret(obj, where: str = "") -> None:
    """Ném SecretLeak nếu còn khóa nào giống trường bí mật (đệ quy)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if SECRET_KEY_RE.search(str(k)):
                raise SecretLeak(f"Trường '{k}' giống dữ liệu bí mật xuất hiện sau khi lọc ({where})")
            assert_no_secret(v, where)
    elif isinstance(obj, list):
        for x in obj:
            assert_no_secret(x, where)


def user(n: dict) -> dict:
    out = {
        "username": _t(n.get("Username")),
        "display_name": _t(n.get("Name")),
        "user_type": _t(n.get("UserType")),
        "emails": _texts(_get(n, "EmailList/EmailID")),
        "group": _t(n.get("Group")),
        "description": _t(n.get("Description"))[:500],
        "sslvpn_policy": _t(n.get("SSLVPNPolicy")),
        "clientless_policy": _t(n.get("ClientlessPolicy")),
        "status": _t(n.get("Status")),
    }
    assert_no_secret(out, "User")
    return out


def user_group(n: dict) -> dict:
    out = {
        "name": _t(_get(n, "GroupDetail/Name")),
        "group_type": _t(_get(n, "GroupDetail/GroupType")),
        "sslvpn_policy": _t(_get(n, "GroupDetail/SSLVPNPolicy")),
        "members": _texts(_get(n, "GroupMembers/UserName")),
    }
    assert_no_secret(out, "UserGroup")
    return out


def sslvpn_policy(n: dict) -> dict:
    out = {
        "name": _t(_get(n, "TunnelPolicy/Name")),
        "description": _t(_get(n, "TunnelPolicy/Description"))[:500],
        "members": _texts(_get(n, "TunnelPolicy/PolicyMembers/Member")),
        "resources_ipv4": _texts(_get(n, "TunnelPolicy/PermittedNetworkResourcesIPv4/Resource")),
    }
    assert_no_secret(out, "SSLVPNPolicy")
    return out


def ipsec_connection(n: dict) -> dict:
    out = {
        "name": _t(_get(n, "Configuration/Name")),
        "description": _t(_get(n, "Configuration/Description"))[:500],
        "connection_type": _t(_get(n, "Configuration/ConnectionType")),
        "policy": _t(_get(n, "Configuration/Policy")),
        "allowed_users": _texts(_get(n, "Configuration/AllowedUser/User")),
        "status": _t(_get(n, "Configuration/Status")),
    }
    assert_no_secret(out, "VPNIPSecConnection")
    return out
