"""Kết nối DB và định nghĩa bảng (SQLAlchemy 2.x)."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL, pool_pre_ping=True, future=True, connect_args=connect_args
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


class Firewall(Base):
    __tablename__ = "firewalls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    site: Mapped[str] = mapped_column(String(120), default="")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=4444)
    username: Mapped[str] = mapped_column(String(120))
    password_enc: Mapped[str] = mapped_column(Text)
    default_group: Mapped[str] = mapped_column(String(120), default="SOC_BLOCKED_IPS")
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    last_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_message: Mapped[str] = mapped_column(Text, default="")
    last_checked: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    audits: Mapped[list["AuditLog"]] = relationship(back_populates="firewall")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "site": self.site,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "default_group": self.default_group,
            "verify_ssl": self.verify_ssl,
            "enabled": self.enabled,
            "note": self.note,
            "last_status": self.last_status,
            "last_message": self.last_message,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(120), default="soc")
    action: Mapped[str] = mapped_column(String(32))  # block | unblock | test | firewall_cud
    firewall_id: Mapped[int | None] = mapped_column(ForeignKey("firewalls.id"), nullable=True)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    group_name: Mapped[str] = mapped_column(String(120), default="")
    target: Mapped[str] = mapped_column(String(255), default="")  # IP / object
    result: Mapped[str] = mapped_column(String(32), default="")  # ok | skipped | error
    status_code: Mapped[str] = mapped_column(String(16), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="")  # teams-paste | manual | csv
    client_ip: Mapped[str] = mapped_column(String(64), default="")

    firewall: Mapped[Firewall | None] = relationship(back_populates="audits")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts.isoformat() if self.ts else None,
            "actor": self.actor,
            "action": self.action,
            "firewall_name": self.firewall_name,
            "group_name": self.group_name,
            "target": self.target,
            "result": self.result,
            "status_code": self.status_code,
            "message": self.message,
            "reason": self.reason,
            "source": self.source,
            "client_ip": self.client_ip,
        }


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
