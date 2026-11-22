"""Schema vào của các API chặn/bỏ chặn — chỉ nhận trường khai báo; kiểu khoan dung như bản cũ."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ParseIn(_In):
    text: str | None = None
    extra_safe: list[str] | None = None
    allow_whitelist: list[str] | None = None  # IP thuộc whitelist người dùng chủ động ghi đè


class BlockIn(_In):
    firewall_ids: list[int] | None = None
    values: list[Any] | None = None       # IP/CIDR (chuỗi hoặc số) — chuẩn hóa ở service
    text: str | None = None               # hoặc dán nguyên văn, server tự bóc IP
    extra_safe: list[str] | None = None
    group: Any = None                     # chỉ chấp nhận SCANPORT GROUP — kiểm ở policy (vi phạm → 403 + audit)
    reason: str | None = None
    source: str | None = None
    dry_run: Any = None
    allow_whitelist: list[str] | None = None  # ghi đè whitelist có chủ đích (ghi vào lý do để audit)


class UnblockIn(_In):
    firewall_ids: list[int] | None = None
    targets: list[Any] | None = None
    group: Any = None
    delete_object: Any = None
    reason: str | None = None


class SyncIn(_In):
    firewall_ids: list[int] | None = None
    group: Any = None
