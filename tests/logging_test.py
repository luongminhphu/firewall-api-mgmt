# Chạy: LOG_FORMAT=json bash tests/run_e2e.sh tests/logging_test.py
# Log JSON (core/logging.py): mỗi dòng là JSON, request /api/* có dòng "access" kèm request_id/actor/status/ms,
# X-Request-ID được trả về (và nhận từ App Proxy nếu có); KHÔNG lộ mật khẩu / token trong log.
import json
import os
import sys
import time

import httpx

if os.environ.get("LOG_FORMAT") != "json":
    sys.exit("Cần chạy với LOG_FORMAT=json")
B = "http://127.0.0.1:8090"
LOG = "/tmp/app_t.log"  # run_e2e.sh ghi log app vào đây
c = httpx.Client(base_url=B, timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


SECRET = "MatKhauRatBiMat-9z"
r = c.post("/api/login", json={"user": "ai-do", "password": SECRET})
r2 = c.get("/api/health", headers={"X-Request-ID": "proxy-abc123"})
chk("trả X-Request-ID (nhận từ proxy)", r2.headers.get("x-request-id") == "proxy-abc123")
chk("tự sinh X-Request-ID khi không có", bool(r.headers.get("x-request-id")))
tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
c.get("/api/firewalls", headers={"X-Auth-Token": tok})
time.sleep(0.5)

lines = [ln for ln in open(LOG, encoding="utf-8").read().splitlines() if ln.strip()]
parsed, bad = [], []
for ln in lines:
    try:
        parsed.append(json.loads(ln))
    except ValueError:
        bad.append(ln)
chk("mọi dòng log là JSON", not bad, bad[:2])
access = [p for p in parsed if p.get("logger") == "access"]
by_rid = {p.get("request_id"): p for p in access}
chk("dòng access có request_id từ proxy", "proxy-abc123" in by_rid)
fw = [p for p in access if p.get("path") == "/api/firewalls"]
chk("dòng access có actor/status/ms", bool(fw) and fw[0].get("actor") == "phu.luong@hsc.com.vn"
    and fw[0].get("status") == 200 and isinstance(fw[0].get("ms"), int), fw[:1])
raw = "\n".join(lines)
chk("không lộ mật khẩu trong log", SECRET not in raw)
chk("không lộ token trong log", tok not in raw)
print("FAILS:", fails)
sys.exit(1 if fails else 0)
