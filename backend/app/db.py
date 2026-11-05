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
from .policy import BLOCK_GROUP

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
    default_group: Mapped[str] = mapped_column(String(120), default=BLOCK_GROUP)
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
            "default_group": BLOCK_GROUP,  # cố định — xem policy.py
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


class GroupChange(Base):
    """Nhật ký thay đổi thành viên Object Group — mỗi dòng là một IP được thêm/bớt.

    `batch_id` gom các dòng của cùng một thao tác trên cùng firewall/group.
    `prev_hash`/`row_hash` tạo chuỗi băm (hash-chain) để phát hiện sửa/xóa log trái phép.
    """

    __tablename__ = "group_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    batch_id: Mapped[str] = mapped_column(String(40), index=True)
    actor: Mapped[str] = mapped_column(String(160), default="")
    actor_name: Mapped[str] = mapped_column(String(160), default="")
    auth_method: Mapped[str] = mapped_column(String(32), default="")
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    group_name: Mapped[str] = mapped_column(String(120), default="", index=True)
    # add | remove | drift_add | drift_remove | baseline | create_group
    change_type: Mapped[str] = mapped_column(String(20))
    object_name: Mapped[str] = mapped_column(String(160), default="")
    value: Mapped[str] = mapped_column(String(80), default="", index=True)
    count_before: Mapped[int] = mapped_column(Integer, default=0)
    count_after: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        ts = self.ts
        if ts is not None:
            # SQLite trả datetime "naive" (đã là UTC); PostgreSQL trả có múi giờ.
            ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
        parts = [
            ts.isoformat() if ts else "",
            self.batch_id, self.actor, self.firewall_name, self.group_name, self.change_type,
            self.object_name, self.value, str(self.count_before), str(self.count_after),
            self.reason or "", self.source or "", self.prev_hash or "",
        ]
        return "\x1f".join(parts)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": (self.ts.replace(tzinfo=dt.timezone.utc) if self.ts and self.ts.tzinfo is None
                   else self.ts).isoformat() if self.ts else None,
            "batch_id": self.batch_id,
            "actor": self.actor,
            "actor_name": self.actor_name,
            "auth_method": self.auth_method,
            "firewall_id": self.firewall_id,
            "firewall_name": self.firewall_name,
            "group_name": self.group_name,
            "change_type": self.change_type,
            "object_name": self.object_name,
            "value": self.value,
            "count_before": self.count_before,
            "count_after": self.count_after,
            "reason": self.reason,
            "source": self.source,
            "client_ip": self.client_ip,
            "row_hash": self.row_hash,
        }


class GroupSnapshot(Base):
    """Ảnh chụp thành viên group lần gần nhất app nhìn thấy — dùng để phát hiện thay đổi ngoài app."""

    __tablename__ = "group_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    group_name: Mapped[str] = mapped_column(String(120))
    members_json: Mapped[str] = mapped_column(Text, default="{}")  # {object_name: value}
    taken_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class AppUser(Base):
    """Người dùng của app. Quyền: write (chặn/bỏ chặn) | readonly (chỉ xem); is_admin = quản trị user & firewall."""

    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)  # luôn lowercase
    display_name: Mapped[str] = mapped_column(String(120), default="")
    auth_type: Mapped[str] = mapped_column(String(16), default="local")  # local | microsoft
    password_hash: Mapped[str] = mapped_column(Text, default="")
    permission: Mapped[str] = mapped_column(String(16), default="readonly")  # write | readonly
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Object ID bất biến của tài khoản Entra, gắn ở lần đăng nhập Microsoft đầu tiên (UPN có thể đổi/tái sử dụng)
    entra_oid: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    @property
    def role(self) -> str:
        if self.is_admin:
            return "admin"
        return "operator" if self.permission == "write" else "viewer"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "auth_type": self.auth_type,
            "has_password": bool(self.password_hash),
            "permission": "write" if self.is_admin else self.permission,
            "is_admin": self.is_admin,
            "role": self.role,
            "enabled": self.enabled,
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "entra_linked": bool(self.entra_oid),
        }


def init_db() -> None:
    Base.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Bổ sung cột mới cho DB đã có (create_all không ALTER bảng cũ)."""
    from sqlalchemy import inspect, text

    cols = {c["name"] for c in inspect(engine).get_columns("app_users")}
    if "entra_oid" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE app_users ADD COLUMN entra_oid VARCHAR(64)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_users_entra_oid ON app_users (entra_oid)"))


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
