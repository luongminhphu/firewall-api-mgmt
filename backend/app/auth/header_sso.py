"""Header-based SSO qua Entra Application Proxy: chỉ tin header khi TCP đến từ IP connector đã khai báo."""
from __future__ import annotations

import ipaddress

from ..core.config import settings
from .errors import AuthError
from .rbac import ROLE_RANK, csv_list as _csv


def _trusted_networks() -> list:
    nets = []
    for c in _csv(settings.TRUSTED_PROXY_CIDRS):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def _utf8_header(v: str) -> str:
    """HTTP header được đọc theo latin-1; tên tiếng Việt từ App Proxy thực chất là byte UTF-8."""
    v = (v or "").strip()
    try:
        return v.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v


def principal_from_headers(peer_ip: str, headers) -> dict:
    """Header-based SSO: chỉ chấp nhận khi kết nối TCP đến từ IP connector đã khai báo.

    Không dùng X-Forwarded-For để quyết định tin cậy (client có thể tự đặt header đó).
    """
    nets = _trusted_networks()
    if not nets:
        raise AuthError("Chưa khai báo TRUSTED_PROXY_CIDRS — từ chối header SSO")
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError as exc:
        raise AuthError("Không xác định được IP nguồn") from exc
    if not any(ip in n for n in nets):
        raise AuthError(f"IP nguồn {peer_ip} không phải Private Network Connector tin cậy")
    upn = (headers.get(settings.HEADER_USER) or "").strip().lower()
    if not upn:
        raise AuthError(f"Thiếu header {settings.HEADER_USER} từ Application Proxy")
    name = _utf8_header(headers.get(settings.HEADER_NAME) or "") or upn
    if upn in [u.lower() for u in _csv(settings.HEADER_ADMINS)]:
        role = "admin"
    elif upn in [u.lower() for u in _csv(settings.HEADER_OPERATORS)]:
        role = "operator"
    else:
        role = settings.HEADER_DEFAULT_ROLE if settings.HEADER_DEFAULT_ROLE in ROLE_RANK else "viewer"
    return {"user": upn, "name": name, "role": role, "method": "entra-header"}
