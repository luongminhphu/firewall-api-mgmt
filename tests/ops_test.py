# Chạy: bash tests/run_e2e.sh tests/ops_test.py
# Vận hành: nén gzip (response lớn, tải CSV) và dọn Job cũ định kỳ (_purge_jobs).
import csv
import datetime as dt
import io
import sys

import httpx

B = "http://127.0.0.1:8090"
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")


c = httpx.Client(base_url=B, timeout=30)
r = c.post("/api/login", json={"user": "admin", "password": "socadmin"})
chk("local admin login", r.status_code == 200, r.text)
tok = r.json()["token"]
A = {"X-Auth-Token": tok}

# Tạo vài nhật ký để /api/audit và CSV vượt 1024 byte
for i in range(15):
    c.post("/api/users", json={"username": f"ops.user{i}", "permission": "readonly", "password": f"Ops2027Pass{i}x"},
           headers=A)

# ---- gzip: httpx tự giải nén nên đọc header gốc + .json()
r = c.get("/api/audit", params={"limit": 200}, headers={**A, "Accept-Encoding": "gzip"})
chk("audit gzip header", r.headers.get("content-encoding") == "gzip", dict(r.headers))
chk("audit gzip body parses as JSON", r.status_code == 200 and len(r.json()["rows"]) >= 15)
r = c.get("/api/audit", params={"limit": 200}, headers={**A, "Accept-Encoding": "identity"})
chk("identity -> not compressed", "content-encoding" not in r.headers and len(r.content) > 1024)
r = c.get("/js/main.js", headers={"Accept-Encoding": "gzip"})
chk("static js gzip", r.status_code == 200 and r.headers.get("content-encoding") == "gzip")
r = c.get("/api/audit.csv", params={"token": tok}, headers={"Accept-Encoding": "gzip"})
rows = list(csv.reader(io.StringIO(r.text)))
chk("audit.csv gzip + readable header row",
    r.headers.get("content-encoding") == "gzip" and rows and rows[0][0] == "thoi_gian" and len(rows) > 5,
    (r.headers.get("content-encoding"), rows[:1]))

# ---- purge: import app.main chỉ chạy module-level (lifespan không chạy khi không có TestClient/uvicorn)
from app import main as app_main  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.core.models import Job  # noqa: E402

now = dt.datetime.now(dt.timezone.utc)
with SessionLocal() as db:
    for jid, age in (("opsoldjob", settings.JOB_RETENTION_DAYS + 30), ("opsnewjob", 0)):
        t = now - dt.timedelta(days=age)
        db.add(Job(id=jid, kind="block", actor="ops", status="done", created_at=t, updated_at=t))
    db.commit()
app_main._purge_jobs()
with SessionLocal() as db:
    chk("old job purged", db.get(Job, "opsoldjob") is None)
    chk("new job kept", db.get(Job, "opsnewjob") is not None)

print("FAILS:", fails)
sys.exit(1 if fails else 0)
