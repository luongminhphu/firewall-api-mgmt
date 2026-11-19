"""Nâng cấp DB đã có (create_all không ALTER bảng cũ): app tự thêm cột thiếu khi khởi động.

Tình huống thật: DB tạo từ bản trước chưa có autoblock_messages.sender_tenant / trusted_by → mọi chu kỳ đọc Teams lỗi
"column … does not exist". Test xóa các cột đó (giả lập DB cũ), ghi một bản ghi bằng chứng theo định dạng băm cũ,
gọi init_db() rồi kiểm tra: cột được thêm, dòng cũ có giá trị mặc định, chuỗi băm bằng chứng cũ vẫn toàn vẹn,
ORM đọc / ghi được. Chạy: bash tests/run_e2e.sh tests/db_migrate_test.py (SQLite hoặc E2E_DATABASE_URL PostgreSQL).
"""
from __future__ import annotations

import datetime as dt
import hashlib

import sqlalchemy as sa

from app.core import hashchain
from app.core.db import SessionLocal, engine, init_db
from app.core.models import AutoBlockEvidence, AutoBlockMessage

fails = 0


def chk(name, ok, extra=""):
    global fails
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}{' ' + str(extra) if extra and not ok else ''}")


init_db()
NEW = ("sender_tenant", "trusted_by")
with engine.begin() as cn:
    cn.execute(sa.text("DELETE FROM autoblock_evidence"))
    cn.execute(sa.text("DELETE FROM autoblock_messages"))
    for t in ("autoblock_messages", "autoblock_evidence"):
        for col in NEW:
            cn.execute(sa.text(f"ALTER TABLE {t} DROP COLUMN {col}"))
cols = lambda t: {c["name"] for c in sa.inspect(engine).get_columns(t)}  # noqa: E731
chk("giả lập DB bản cũ: thiếu cột sender_tenant / trusted_by", not (set(NEW) & cols("autoblock_messages")))

# bản ghi tạo bởi bản cũ: tin + bằng chứng băm theo định dạng CŨ (không có tenant / cách tin cậy)
now = dt.datetime(2026, 11, 18, 10, 0, tzinfo=dt.timezone.utc)
old_payload = "\x1f".join([now.isoformat(), "1", "m-old", "19:c@thread.v2", "u1", "SOC A", now.isoformat(),
                           now.isoformat(), "processed", "[]", "ĐỀ XUẤT CỦA SOC: BLOCK IP 1.2.3.4", "abc", ""])
old_hash = hashlib.sha256(old_payload.encode()).hexdigest()
with engine.begin() as cn:
    cn.execute(sa.text("INSERT INTO autoblock_messages (id, msg_id, sender_id, sender_name, created_at, received_at, "
                       "status, excerpt, body_hash) VALUES (1, 'm-old', 'u1', 'SOC A', :t, :t, 'processed', '', '')"),
               {"t": now})
    cn.execute(sa.text("INSERT INTO autoblock_evidence (id, captured_at, message_id, msg_id, chat_id, sender_id, "
                       "sender_name, sender_type, teams_created_at, teams_modified_at, status, commands, text, "
                       "raw_json, sha256, prev_hash, row_hash) VALUES (1, :t, 1, 'm-old', '19:c@thread.v2', 'u1', "
                       "'SOC A', '', :t, :t, 'processed', '[]', 'ĐỀ XUẤT CỦA SOC: BLOCK IP 1.2.3.4', '{}', 'abc', '', "
                       ":h)"), {"t": now, "h": old_hash})
    if engine.dialect.name == "postgresql":  # chèn id thủ công → đẩy sequence theo, như dữ liệu thật
        for t in ("autoblock_messages", "autoblock_evidence"):
            cn.execute(sa.text(f"SELECT setval(pg_get_serial_sequence('{t}', 'id'), (SELECT max(id) FROM {t}))"))

init_db()  # khởi động bản mới
chk("khởi động: tự thêm cột thiếu (autoblock_messages)", set(NEW) <= cols("autoblock_messages"))
chk("khởi động: tự thêm cột thiếu (autoblock_evidence)", set(NEW) <= cols("autoblock_evidence"))
init_db()
chk("chạy lại lần nữa không lỗi (idempotent)", True)

with SessionLocal() as db:
    row = db.scalars(sa.select(AutoBlockMessage).where(AutoBlockMessage.msg_id == "m-old")).first()
    chk("ORM đọc được tin cũ; cột mới mang giá trị mặc định ''", row and row.sender_tenant == "" and row.trusted_by == "",
        row and (row.sender_tenant, row.trusted_by))
    v = hashchain.verify(db, AutoBlockEvidence)
    chk("bằng chứng cũ vẫn toàn vẹn sau nâng cấp (định dạng băm cũ được giữ)", v["ok"], v)
    ev = AutoBlockEvidence(captured_at=now, message_id=1, msg_id="m-new", sender_id="u2", sender_name="SOC B",
                           sender_tenant="t-1", trusted_by="Tài khoản SOC B", status="processed", text="x", sha256="d")
    hashchain.append(db, AutoBlockEvidence, [ev])
    v = hashchain.verify(db, AutoBlockEvidence)
    chk("ghi bằng chứng mới (có tenant / cách tin cậy) nối tiếp chuỗi cũ, vẫn toàn vẹn", v["ok"] and v["checked"] == 2, v)
    ev.trusted_by = "Giả mạo"
    db.commit()
    chk("sửa cách tin cậy của bằng chứng mới → phát hiện", not hashchain.verify(db, AutoBlockEvidence)["ok"])

print(f"\nTỔNG: {'OK' if not fails else f'{fails} lỗi'}")
print(f"FAILS: {fails}")
raise SystemExit(1 if fails else 0)
