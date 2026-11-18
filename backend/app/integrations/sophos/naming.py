"""Quy ước đặt tên IP Host do app tạo trên firewall (tên = chính IP/CIDR; kiểu cũ có HOST_PREFIX)."""
from __future__ import annotations

from ...core.config import settings


def host_object_name(value: str, prefix: str | None = None) -> str:
    """Tên IP Host trên firewall = chính địa chỉ IP/CIDR (vd `45.138.12.16`, `185.220.101.0/24`).

    Sophos chỉ cấm dấu phẩy, ký tự đầu `#`, tối đa 60 ký tự — IP/CIDR luôn hợp lệ.
    `prefix` chỉ dùng để sinh tên kiểu cũ (v1.x ≤ 1.3) khi cần nhận diện object đã tạo trước đây.
    """
    import ipaddress

    if prefix is not None:
        return legacy_object_name(value, prefix)
    v = value.strip()
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v[:60]


def legacy_object_name(value: str, prefix: str | None = None) -> str:
    """Tên kiểu cũ: SOC_BLOCK_45_138_12_16 / SOC_BLOCK_185_220_101_0-24."""
    p = prefix if prefix is not None else settings.HOST_PREFIX
    clean = value.replace(".", "_").replace("/", "-")
    return f"{p}{clean}"[:60]


def is_app_owned(name: str, actual_value: str | None) -> bool:
    """Object do app tạo: tên kiểu cũ (tiền tố HOST_PREFIX) hoặc tên đúng bằng địa chỉ thực của object."""
    if settings.HOST_PREFIX and name.startswith(settings.HOST_PREFIX):
        return True
    if not actual_value:
        return False
    return host_object_name(name) == name and host_object_name(actual_value) == name
