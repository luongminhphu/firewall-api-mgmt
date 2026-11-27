# Chạy: bash tests/run_e2e.sh tests/hashchain_multiproc_test.py   (thêm E2E_DATABASE_URL=... để kiểm liên tiến trình)
# core.hashchain.append: nhiều luồng (mọi DB) và nhiều tiến trình/pod (chỉ PostgreSQL) cùng ghi một chuỗi không được đứt.
# Liên tiến trình chỉ kiểm trên PostgreSQL (SQLite không có khóa advisory).
import datetime as dt
import os
import subprocess
import sys
import threading

sys.path.insert(0, "backend")

WORKER = "--worker" in sys.argv
N_PROC, N_EACH = 4, 50


def write_rows(tag, n):
    from app.core import hashchain
    from app.core.db import SessionLocal
    from app.core.models import GroupChange
    db = SessionLocal()
    try:
        for i in range(n):
            hashchain.append(db, GroupChange, [GroupChange(
                ts=dt.datetime.now(dt.timezone.utc), batch_id=f"{tag}-{i}", actor="t", firewall_name="fw", group_name="g",
                change_type="add", object_name="o", value="1.2.3.4", count_before=0, count_after=1,
                reason="hashchain test", source="test")])
    finally:
        db.close()


if WORKER:
    write_rows(sys.argv[sys.argv.index("--worker") + 1], N_EACH)
    sys.exit(0)

from app.core import hashchain  # noqa: E402
from app.core.db import SessionLocal, engine  # noqa: E402
from app.core.models import GroupChange  # noqa: E402

PG = engine.dialect.name == "postgresql"
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


def check_chain(label, expected):
    with SessionLocal() as db:
        v = hashchain.verify(db, GroupChange)
        n = db.query(GroupChange).count()
    chk(f"{label}: chuỗi băm liền", v["ok"], v["message"])
    chk(f"{label}: đủ số dòng", n == expected, f"{n}/{expected}")


# --- nhiều luồng trong một tiến trình (mọi DB)
ts = [threading.Thread(target=write_rows, args=(f"t{i}", 25)) for i in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
check_chain("4 luồng × 25", 100)

# --- nhiều tiến trình (mô phỏng nhiều pod) — chỉ PostgreSQL
if PG:
    procs = [subprocess.Popen([sys.executable, __file__, "--worker", f"p{i}"], env=os.environ,
                              stderr=subprocess.PIPE, text=True) for i in range(N_PROC)]
    for p in procs:
        try:
            err = p.communicate(timeout=120)[1]
        except subprocess.TimeoutExpired:  # treo khóa → FAIL thay vì treo test
            p.kill(); err = "timeout 120s: " + (p.communicate()[1] or "")
        chk("tiến trình con thoát 0", p.returncode == 0, err[-300:])
    check_chain(f"{N_PROC} tiến trình × {N_EACH}", 100 + N_PROC * N_EACH)
else:
    print("SKIP liên tiến trình (không phải PostgreSQL)")

print("RESULT", "OK" if not fails else f"FAIL ({fails})")
sys.exit(1 if fails else 0)
