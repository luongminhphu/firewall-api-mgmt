"""Chính sách hardening: ứng dụng CHỈ được thao tác trên một IP Host Group cố định.

Tên group được gắn cứng trong mã nguồn (không đọc từ biến môi trường, không nhận từ API/UI)
để không ai có thể dùng app chỉnh sửa group/rule khác trên firewall, kể cả khi lộ token
hoặc sửa ConfigMap. Muốn đổi group phải sửa mã, review và build lại image.
"""
from __future__ import annotations

from typing import Final

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
