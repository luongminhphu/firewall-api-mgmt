"""Schema vào/ra của /api/firewalls — chỉ nhận đúng các trường khai báo (không mass-assignment)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class FirewallCreateIn(_In):
    name: str | None = None
    site: str | None = None
    host: str | None = None
    port: int | str | None = None
    username: str | None = None
    password: str | None = None
    default_group: str | None = None
    verify_ssl: bool | None = None
    enabled: bool | None = None
    note: str | None = None


class FirewallUpdateIn(FirewallCreateIn):
    """Mọi trường tùy chọn; trường None = giữ nguyên."""


class TestAllIn(_In):
    firewall_ids: list[int] | None = None


class FirewallOut(BaseModel):
    id: int
    name: str
    site: str
    host: str
    port: int
    username: str
    default_group: str
    verify_ssl: bool
    enabled: bool
    note: str
    last_status: str
    last_message: str
    last_checked: str | None


class TestResultOut(BaseModel):
    model_config = ConfigDict(extra="allow")
    firewall_id: int
    firewall: str
    ok: bool
    message: str
    code: str
