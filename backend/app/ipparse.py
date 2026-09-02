"""Bóc tách và kiểm tra IP từ text thô (chat Teams, log, CSV)."""
from __future__ import annotations

import ipaddress
import re

from .config import settings

# IPv4 và IPv4/CIDR, kèm dạng bị làm mờ "1.2.3[.]4" hay "1.2.3(.)4" thường thấy trong chat SOC.
_IP_RE = re.compile(
    r"\b(\d{1,3})(?:\.|\[\.\]|\(\.\)|\s*\[dot\]\s*)"
    r"(\d{1,3})(?:\.|\[\.\]|\(\.\)|\s*\[dot\]\s*)"
    r"(\d{1,3})(?:\.|\[\.\]|\(\.\)|\s*\[dot\]\s*)"
    r"(\d{1,3})(/\d{1,2})?\b",
    re.IGNORECASE,
)


def safe_networks() -> list[ipaddress.IPv4Network]:
    nets = []
    for item in settings.SAFE_LIST.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def classify(entry: str, extra_safe: list[str] | None = None) -> dict:
    """Trả về thông tin phân loại một IP/CIDR: hợp lệ, loại, có bị loại trừ không."""
    entry = entry.strip()
    out = {"value": entry, "valid": False, "kind": "", "excluded": False, "reason": ""}
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            if net.version != 4:
                out["reason"] = "Chỉ hỗ trợ IPv4"
                return out
            out.update(valid=True, kind="Network" if net.prefixlen < 32 else "IP")
            out["value"] = str(net) if net.prefixlen < 32 else str(net.network_address)
            probe = net
        else:
            addr = ipaddress.ip_address(entry)
            if addr.version != 4:
                out["reason"] = "Chỉ hỗ trợ IPv4"
                return out
            out.update(valid=True, kind="IP")
            probe = ipaddress.ip_network(f"{addr}/32")
    except ValueError:
        out["reason"] = "Không phải IPv4 hợp lệ"
        return out

    safe = safe_networks()
    for item in extra_safe or []:
        try:
            safe.append(ipaddress.ip_network(item.strip(), strict=False))
        except ValueError:
            continue

    for net in safe:
        if probe.subnet_of(net) or probe.overlaps(net):
            out.update(excluded=True, reason=f"Nằm trong safe-list ({net})")
            return out

    addr0 = probe.network_address
    if not settings.ALLOW_PRIVATE and (
        addr0.is_private or addr0.is_loopback or addr0.is_link_local or addr0.is_multicast
    ):
        out.update(excluded=True, reason="IP nội bộ/đặc biệt — bị chặn bởi cấu hình")
    return out


def extract(text: str, extra_safe: list[str] | None = None) -> dict:
    """Bóc IP từ text thô. Trả về danh sách hợp lệ (đã loại trùng) và danh sách bị loại."""
    accepted: list[dict] = []
    rejected: list[dict] = []
    seen: set[str] = set()

    for m in _IP_RE.finditer(text or ""):
        octets = [m.group(i) for i in range(1, 5)]
        if any(int(o) > 255 for o in octets):
            continue
        raw = ".".join(octets) + (m.group(5) or "")
        info = classify(raw, extra_safe)
        key = info["value"]
        if key in seen:
            continue
        seen.add(key)
        (accepted if info["valid"] and not info["excluded"] else rejected).append(info)

    return {
        "accepted": accepted,
        "rejected": rejected,
        "count": len(accepted),
        "rejected_count": len(rejected),
    }


def host_object_name(value: str, prefix: str | None = None) -> str:
    """Sinh tên IP Host trên firewall — không dấu phẩy, tối đa 60 ký tự."""
    p = prefix if prefix is not None else settings.HOST_PREFIX
    clean = value.replace(".", "_").replace("/", "-")
    name = f"{p}{clean}"
    return name[:60]
