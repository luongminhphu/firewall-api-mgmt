"""Chuỗi băm SHA-256 chống sửa/xóa log, dùng chung cho mọi bảng nhật ký (group_changes, sau này VPN).

Bảng tham gia chuỗi cần cột `id` (tăng dần), `prev_hash`, `row_hash` và phương thức `hash_payload()`
trả chuỗi ổn định của nội dung dòng (bao gồm prev_hash). Mỗi bảng là một chuỗi độc lập.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Iterable

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

_locks: dict[str, threading.Lock] = {}
_guard = threading.Lock()


def _lock(model) -> threading.Lock:
    with _guard:
        return _locks.setdefault(model.__tablename__, threading.Lock())


def digest(row) -> str:
    return hashlib.sha256(row.hash_payload().encode()).hexdigest()


def last_hash(db: Session, model) -> str:
    row = db.scalars(select(model).order_by(desc(model.id)).limit(1)).first()
    return row.row_hash if row else ""


def append(db: Session, model, rows: Iterable) -> None:
    """Nối các dòng (chưa lưu) vào cuối chuỗi của `model` rồi COMMIT ngay trong khóa.

    Commit trong khóa là bắt buộc: có luồng nền (quét cache, công việc chặn song song) ghi cùng lúc;
    nếu nhả khóa trước khi commit, hai phiên có thể đọc cùng prev_hash → đứt chuỗi.
    """
    with _lock(model):
        prev = last_hash(db, model)
        for row in rows:
            row.prev_hash = prev
            row.row_hash = digest(row)
            prev = row.row_hash
            db.add(row)
        db.commit()


def verify(db: Session, model) -> dict:
    prev = ""
    count = 0
    for row in db.scalars(select(model).order_by(model.id)).yield_per(500):
        count += 1
        if row.prev_hash != prev:
            return {"ok": False, "checked": count, "broken_at": row.id,
                    "message": f"Chuỗi băm đứt tại bản ghi #{row.id}: có bản ghi trước đó bị xóa hoặc chèn"}
        if digest(row) != row.row_hash:
            return {"ok": False, "checked": count, "broken_at": row.id,
                    "message": f"Bản ghi #{row.id} đã bị sửa sau khi ghi"}
        prev = row.row_hash
    return {"ok": True, "checked": count, "broken_at": None,
            "message": f"Toàn vẹn: {count} bản ghi, chuỗi băm khớp"}
