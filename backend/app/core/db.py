"""Kết nối DB: engine, session, khởi tạo bảng + bổ sung cột (SQLAlchemy 2.x)."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    # timeout: v1.7 ghi DB từ nhiều luồng song song (mỗi firewall một luồng) — chờ khóa thay vì lỗi ngay
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    settings.DATABASE_URL, pool_pre_ping=True, future=True, connect_args=connect_args
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401 — đăng ký bảng vào Base.metadata

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
