"""Truy cập bảng firewalls."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.models import AuditLog, Firewall


def list_all(db: Session) -> list[Firewall]:
    return list(db.scalars(select(Firewall).order_by(Firewall.name)).all())


def get(db: Session, fw_id: int) -> Firewall | None:
    return db.get(Firewall, fw_id)


def get_by_name(db: Session, name: str) -> Firewall | None:
    return db.scalar(select(Firewall).where(Firewall.name == name))


def save(db: Session, fw: Firewall) -> Firewall:
    db.add(fw)
    db.commit()
    return fw


def delete(db: Session, fw: Firewall) -> None:
    # Giữ audit log của firewall đã xóa (bỏ liên kết khóa ngoại)
    db.query(AuditLog).filter(AuditLog.firewall_id == fw.id).update({"firewall_id": None})
    db.delete(fw)
