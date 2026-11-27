"""Kết nối DB: engine, session, khởi tạo bảng + bổ sung cột (SQLAlchemy 2.x)."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

import logging

from .config import settings

log = logging.getLogger(__name__)

connect_args, pool_args = {}, {"pool_size": settings.DB_POOL_SIZE, "max_overflow": settings.DB_MAX_OVERFLOW}
if settings.DATABASE_URL.startswith("sqlite"):
    pool_args = {}
    # timeout: v1.7 ghi DB từ nhiều luồng song song (mỗi firewall một luồng) — chờ khóa thay vì lỗi ngay
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    settings.DATABASE_URL, pool_pre_ping=True, future=True, connect_args=connect_args, **pool_args
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401 — đăng ký bảng vào Base.metadata

    Base.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Bổ sung cột mới cho bảng đã có — create_all chỉ tạo bảng CHƯA có, không ALTER bảng cũ.

    So từng bảng trong models với DB: cột nào thiếu thì ADD COLUMN (cho phép NULL, kèm DEFAULT của model để các dòng
    cũ có giá trị), tạo index nếu cột có index. Chạy mỗi lần khởi động, idempotent; nâng cấp phiên bản không cần
    migrate tay. Không xóa / đổi kiểu cột.
    """
    from sqlalchemy import inspect, literal, text

    insp = inspect(engine)
    existing = set(insp.get_table_names())
    pg = engine.dialect.name == "postgresql"
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            ddl = f'ALTER TABLE {table.name} ADD COLUMN {"IF NOT EXISTS " if pg else ""}{col.name} ' \
                  f"{col.type.compile(dialect=engine.dialect)}"
            default = col.default.arg if col.default is not None and col.default.is_scalar else None
            if default is not None:
                ddl += " DEFAULT " + str(literal(default, type_=col.type).compile(
                    dialect=engine.dialect, compile_kwargs={"literal_binds": True}))
            with engine.begin() as conn:
                conn.execute(text(ddl))
                if col.index:
                    conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table.name}_{col.name} "
                                      f"ON {table.name} ({col.name})"))
            log.warning("Nâng cấp DB: thêm cột %s.%s", table.name, col.name)
    if "audit_logs" in existing:  # DB cũ: create_all không thêm index cho bảng đã có
        with engine.begin() as conn:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action)"))


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
