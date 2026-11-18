"""Tiện ích tầng HTTP dùng chung giữa các router (không chứa nghiệp vụ)."""
from __future__ import annotations

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Firewall


def client_ip_of(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def get_fw(db: Session, fw_id: int) -> Firewall:
    fw = db.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, f"Không tìm thấy firewall id={fw_id}")
    return fw


def selected_firewalls(db: Session, ids: list[int] | None) -> list[Firewall]:
    stmt = select(Firewall).where(Firewall.enabled.is_(True))
    if ids:
        stmt = select(Firewall).where(Firewall.id.in_(ids))
    fws = list(db.scalars(stmt).all())
    if not fws:
        raise HTTPException(400, "Chưa chọn firewall nào (hoặc firewall đang bị tắt)")
    return fws
