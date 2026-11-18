"""Chính sách hardening — NƠI DUY NHẤT quyết định app được gửi lệnh gì lên firewall.

1. Chỉ thao tác trên một IP Host Group cố định (BLOCK_GROUP).
2. `check_request()` được `BaseClient._post` gọi cho MỌI lệnh trước khi mở kết nối: đọc lại chính XML sắp gửi,
   xác định (thao tác, entity, tên) và đối chiếu ALLOWLIST. Ngoài allowlist → PolicyViolation + audit
   `policy_violation`. Nhờ kiểm tra payload thật, cả lỗi lập trình (dựng nhầm XML) cũng bị chặn.

Tên group được gắn cứng trong mã nguồn (không đọc từ biến môi trường, không nhận từ API/UI)
để không ai có thể dùng app chỉnh sửa group/rule khác trên firewall, kể cả khi lộ token
hoặc sửa ConfigMap. Muốn đổi group phải sửa mã, review và build lại image.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Callable, Final

log = logging.getLogger("policy")

BLOCK_GROUP: Final[str] = "SCANPORT GROUP"
BLOCK_GROUP_FAMILY: Final[str] = "IPv4"


class GroupPolicyError(ValueError):
    """Yêu cầu thao tác trên group khác BLOCK_GROUP."""


def enforce_group(requested: str | None = None) -> str:
    """Trả về BLOCK_GROUP. Từ chối mọi tên group khác (so khớp chính xác, kể cả hoa/thường)."""
    if requested is None:
        return BLOCK_GROUP
    value = str(requested).strip()
    if value == "" or value == BLOCK_GROUP:
        return BLOCK_GROUP
    raise GroupPolicyError(
        f"Bị từ chối theo chính sách bảo mật: ứng dụng chỉ được thao tác trên IP Host Group "
        f"'{BLOCK_GROUP}', không chấp nhận group '{value[:80]}'."
    )


class PolicyViolation(GroupPolicyError):
    """Lệnh gửi firewall nằm ngoài allowlist (bị chặn trước khi gửi)."""


def _only_block_group(name: str | None) -> bool:
    return name == BLOCK_GROUP


# (thao tác, entity) → điều kiện trên <Name> (None = không ràng buộc tên).
# Thao tác: get | add | update | remove. Mọi cặp KHÔNG có ở đây đều bị chặn.
ALLOWLIST: Final[dict[tuple[str, str], Callable[[str | None], bool] | None]] = {
    ("get", "IPHost"): None,
    ("get", "IPHostGroup"): None,
    ("add", "IPHost"): None,                       # tạo object chặn (tên = IP/CIDR)
    ("remove", "IPHost"): None,                    # + kiểm tra object do app tạo: check_remove_iphost()
    ("update", "IPHostGroup"): _only_block_group,  # chỉ ghi HostList của SCANPORT GROUP
}

_OPS = {"Get": "get", "Remove": "remove"}


def _deny(op: str, entity: str, name: str | None, why: str = "") -> None:
    msg = (f"Bị từ chối theo chính sách bảo mật: ứng dụng không được phép {op} '{entity}'"
           + (f" '{name[:80]}'" if name else "") + " trên firewall" + (f" ({why})" if why else "") + ".")
    _report(op, entity, name, msg)
    raise PolicyViolation(msg)


def check_request(inner_xml: str) -> list[tuple[str, str, str | None]]:
    """Kiểm tra nội dung <Request> (không gồm <Login>). Trả danh sách (thao tác, entity, tên) đã cho phép."""
    try:
        root = ET.fromstring(f"<Request>{inner_xml}</Request>")
    except ET.ParseError as exc:
        _deny("gửi", "XML không hợp lệ", None, str(exc)[:120])
    allowed: list[tuple[str, str, str | None]] = []
    if len(root) == 0:
        _deny("gửi", "lệnh rỗng", None)
    for op_el in root:
        if op_el.tag == "Set":
            op = (op_el.get("operation") or "add").strip().lower()
        else:
            op = _OPS.get(op_el.tag, "")
        if not op or op_el.tag == "Login":
            _deny(op_el.tag, "lệnh", None)
        if len(op_el) == 0:
            _deny(op, "entity rỗng", None)
        for ent in op_el:
            name = ent.findtext("Name")
            name = name.strip() if isinstance(name, str) else None
            key = (op, ent.tag)
            if key not in ALLOWLIST:
                _deny(op, ent.tag, name)
            cond = ALLOWLIST[key]
            if cond is not None and not cond(name):
                _deny(op, ent.tag, name, f"chỉ được thao tác '{BLOCK_GROUP}'")
            allowed.append((op, ent.tag, name))
    return allowed


def check_remove_iphost(name: str, actual_value: str | None) -> None:
    """Chỉ được xóa IP Host do app tạo: tên = chính địa chỉ của object, hoặc tên kiểu cũ có HOST_PREFIX."""
    from ...core.config import settings
    from .naming import is_app_owned

    if not is_app_owned(name, actual_value):
        raise GroupPolicyError(
            f"Không được xóa IP Host '{name}' — chỉ xóa object do app tạo "
            f"(tên trùng địa chỉ IP/CIDR của object, hoặc tiền tố {settings.HOST_PREFIX})"
        )


def _report(op: str, entity: str, name: str | None, msg: str) -> None:
    """Ghi audit policy_violation bằng phiên DB riêng — không phụ thuộc người gọi, không được làm hỏng luồng chặn."""
    log.warning("policy_violation op=%s entity=%s name=%s", op, entity, name)
    try:
        from ...core.audit import audit
        from ...core.db import SessionLocal

        with SessionLocal() as db:
            audit(db, action="policy_violation", fw=None, target=f"{op} {entity}"[:255], result="denied",
                  message=msg, group=(name or "")[:120], actor="he-thong")
            db.commit()
    except Exception:  # noqa: BLE001
        log.exception("Không ghi được audit policy_violation")
