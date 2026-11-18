"""Dựng / định dạng XML cho Sophos Firewall XML API (không gọi mạng)."""
from __future__ import annotations

import html
from typing import Any

def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


IP_FAMILIES = ("IPv4", "IPv6")
HOST_NAME_MAX = 60  # Sophos: <Host> tối đa 60 ký tự, không có dấu phẩy


def validate_group_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("Tên IP Host Group không được để trống")
    if "," in name:
        raise ValueError(f"Tên IP Host Group không được chứa dấu phẩy: {name}")
    return name


def build_iphostgroup_xml(
    name: str, hosts: list[str], description: str = "", ip_family: str = "IPv4"
) -> str:
    """Dựng entity IPHostGroup theo đúng mẫu của Sophos Firewall XML API:

        <IPHostGroup>
          <Name>name</Name>
          <IPFamily>IPv4/IPv6</IPFamily>
          <Description>Text</Description>
          <HostList><Host>Hostname</Host>...</HostList>
        </IPHostGroup>

    <Host> là TÊN của IP Host đã tồn tại trên firewall (không phải địa chỉ IP).
    """
    name = validate_group_name(name)
    fam = ip_family or "IPv4"
    if fam not in IP_FAMILIES:
        raise ValueError(f"IPFamily chỉ nhận IPv4 hoặc IPv6, nhận được: {fam}")
    seen: set[str] = set()
    clean: list[str] = []
    for h in hosts:
        h = (h or "").strip()
        if not h or h in seen:
            continue
        if "," in h or len(h) > HOST_NAME_MAX:
            raise ValueError(f"Tên IP Host không hợp lệ (tối đa {HOST_NAME_MAX} ký tự, không dấu phẩy): {h}")
        seen.add(h)
        clean.append(h)
    host_xml = "".join(f"<Host>{_esc(h)}</Host>" for h in clean)
    return (
        "<IPHostGroup>"
        f"<Name>{_esc(name)}</Name>"
        f"<IPFamily>{fam}</IPFamily>"
        f"<Description>{_esc(description or '')}</Description>"
        f"<HostList>{host_xml}</HostList>"
        "</IPHostGroup>"
    )


def pretty_xml(xml: str) -> str:
    """Định dạng XML nhiều dòng để hiển thị cho người dùng (không chứa thông tin đăng nhập)."""
    import xml.dom.minidom as minidom

    try:
        out = minidom.parseString(xml.encode("utf-8")).toprettyxml(indent="  ")
        return "\n".join(line for line in out.splitlines()[1:] if line.strip())
    except Exception:  # noqa: BLE001
        return xml
