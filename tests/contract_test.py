# Hợp đồng API (lưới an toàn cho tái cấu trúc — docs/architecture.md §6 bước 1.0)
#
# Chạy:      bash tests/run_e2e.sh tests/contract_test.py
# Ghi lại:   CONTRACT_RECORD=1 bash tests/run_e2e.sh tests/contract_test.py   (CHỈ khi cố ý đổi API)
#
# So sánh với tests/contract_snapshot.json:
#  - danh sách route (method + path) của app,
#  - mã HTTP + "hình dạng" JSON (khóa của dict, phần tử đầu của list) của các response tiêu biểu,
#  - thông điệp lỗi chính (detail) — frontend hiển thị nguyên văn.
# Giá trị cụ thể (thời gian, id, token) không so sánh.
import json
import os
import sys
import time

import httpx

sys.path.insert(0, "backend")
from app.main import app  # noqa: E402  (chỉ đọc danh sách route, không chạy startup)

B = "http://127.0.0.1:8090"
SNAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contract_snapshot.json")
RECORD = os.environ.get("CONTRACT_RECORD") == "1"
c = httpx.Client(base_url=B, timeout=60)
out: dict = {}


def shape(v):
    if isinstance(v, dict):
        return {k: shape(x) for k, x in sorted(v.items())}
    if isinstance(v, list):
        return [shape(v[0])] if v else []
    return "*"


def call(name, method, path, *, keep_detail=False, **kw):
    r = c.request(method, path, **kw)
    try:
        body = r.json()
    except ValueError:
        body = None
    entry = {"status": r.status_code,
             "content_type": r.headers.get("content-type", "").split(";")[0]}
    if isinstance(body, (dict, list)):
        entry["shape"] = shape(body)
        if keep_detail and isinstance(body, dict) and isinstance(body.get("detail"), str):
            entry["detail"] = body["detail"]
    out[name] = entry
    return r, body


# ------------------------------------------------------------------ routes
routes = sorted(
    f"{m} {r.path}" for r in app.routes if getattr(r, "methods", None)
    for m in r.methods if m not in ("HEAD", "OPTIONS")
)
out["routes"] = routes

# --------------------------------------------------------------- công khai
call("health", "GET", "/api/health")
call("auth_modes", "GET", "/api/auth/modes")
call("branding", "GET", "/api/branding")
call("no_token", "GET", "/api/firewalls", keep_detail=True)
call("bad_login", "POST", "/api/login", json={"user": "khong-ton-tai", "password": "sai"}, keep_detail=True)

tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
viewer = c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]
V = {"X-Auth-Token": viewer}
call("header_login", "POST", "/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"})
call("config", "GET", "/api/config", headers=H)

# --------------------------------------------------------------- firewalls
r, fw = call("fw_create", "POST", "/api/firewalls", headers=H,
             json={"name": "FW-CONTRACT", "host": "127.0.0.1", "port": 4460,
                   "username": "apiadmin", "password": "Sophos@123"})
fid = fw["id"]
call("fw_create_missing", "POST", "/api/firewalls", headers=H, json={"name": "X"}, keep_detail=True)
call("fw_create_dup", "POST", "/api/firewalls", headers=H, keep_detail=True,
     json={"name": "FW-CONTRACT", "host": "h", "username": "u", "password": "p"})
call("fw_create_viewer", "POST", "/api/firewalls", headers=V, json={"name": "Y"}, keep_detail=True)
call("fw_create_other_group", "POST", "/api/firewalls", headers=H, keep_detail=True,
     json={"name": "FW-G", "host": "h", "username": "u", "password": "p", "default_group": "KHAC"})
call("fw_list", "GET", "/api/firewalls", headers=H)
call("fw_update", "PUT", f"/api/firewalls/{fid}", headers=H, json={"note": "contract"})
call("fw_404", "PUT", "/api/firewalls/99999", headers=H, json={}, keep_detail=True)
# Schema (1.5): trường không khai báo bị bỏ qua (không mass-assignment), sai kiểu → 400 + detail dạng chuỗi
r_ma = c.put(f"/api/firewalls/{fid}", headers=H,
             json={"id": 999, "password_enc": "x", "last_status": "hacked", "default_group": None})
EXTRA_CHECKS = [
    ("mass-assignment bị bỏ qua", r_ma.status_code == 200 and r_ma.json()["id"] == fid
     and r_ma.json()["last_status"] != "hacked"),
]
r_bad = c.put(f"/api/firewalls/{fid}", headers=H, json={"verify_ssl": {"x": 1}})
EXTRA_CHECKS.append(("sai kiểu → 400 + detail chuỗi tiếng Việt",
                     r_bad.status_code == 400 and isinstance(r_bad.json().get("detail"), str)
                     and r_bad.json()["detail"].startswith("Dữ liệu không hợp lệ")))
call("fw_test", "POST", f"/api/firewalls/{fid}/test", headers=H)
call("fw_test_all", "POST", "/api/firewalls/test-all", headers=H, json={"firewall_ids": [fid]})

# chờ lượt quét cache đầu tiên
for _ in range(60):
    m = c.get(f"/api/firewalls/{fid}/group-cache", headers=H).json()
    if m.get("cached") and not m.get("refreshing"):
        break
    time.sleep(0.25)
call("fw_groups", "GET", f"/api/firewalls/{fid}/groups", headers=H)
call("group_members", "GET", f"/api/firewalls/{fid}/group-members", headers=H)
call("group_members_other", "GET", f"/api/firewalls/{fid}/group-members?group=KHAC", headers=H, keep_detail=True)
call("group_cache_one", "GET", f"/api/firewalls/{fid}/group-cache", headers=H)
call("group_cache_all", "GET", "/api/group-cache", headers=H)

# ------------------------------------------------------------ parse / block
call("parse", "POST", "/api/parse", headers=H, json={"text": "chan 45.1.2.3, 10.0.0.1 va 185[.]220[.]101[.]0/24"})
call("block_empty", "POST", "/api/block", headers=H, json={"firewall_ids": [fid], "values": ["10.0.0.1"]},
     keep_detail=True)
call("block_viewer", "POST", "/api/block", headers=V, json={"firewall_ids": [fid], "values": ["45.1.2.3"]},
     keep_detail=True)
call("block_other_group", "POST", "/api/block", headers=H, keep_detail=True,
     json={"firewall_ids": [fid], "values": ["45.1.2.3"], "group": "KHAC"})
call("block_dry", "POST", "/api/block", headers=H,
     json={"firewall_ids": [fid], "values": ["45.1.2.3"], "dry_run": True, "reason": "contract"})
r, blk = call("block", "POST", "/api/block", headers=H,
              json={"firewall_ids": [fid], "values": ["45.1.2.3", "185.220.101.0/24"], "reason": "contract"})
call("job", "GET", f"/api/jobs/{blk['job_id']}", headers=H)
call("job_other_user", "GET", f"/api/jobs/{blk['job_id']}", headers=V, keep_detail=True)
call("unblock_empty", "POST", "/api/unblock", headers=H, json={"firewall_ids": [fid], "targets": []},
     keep_detail=True)
call("unblock", "POST", "/api/unblock", headers=H,
     json={"firewall_ids": [fid], "targets": ["45.1.2.3", "9.9.9.9"], "reason": "contract"})

# ----------------------------------------------------------- audit/changes
call("audit", "GET", "/api/audit?limit=5", headers=H)
call("audit_csv", "GET", f"/api/audit.csv?token={tok}")
call("changes", "GET", "/api/changes", headers=H)
call("changes_csv", "GET", f"/api/changes.csv?token={tok}")
call("changes_verify", "GET", "/api/changes/verify", headers=H)
call("changes_sync", "POST", "/api/changes/sync", headers=H, json={"firewall_ids": [fid]})

# ------------------------------------------------------------- users/branding
call("users", "GET", "/api/users", headers=H)
call("users_viewer", "GET", "/api/users", headers=V, keep_detail=True)
r, u = call("user_create", "POST", "/api/users", headers=H,
            json={"username": "contract.user", "display_name": "C", "auth_type": "local",
                  "password": "Matkhau12345", "permission": "readonly"})
call("user_create_weak", "POST", "/api/users", headers=H, keep_detail=True,
     json={"username": "weak.user", "auth_type": "local", "password": "123", "permission": "readonly"})
call("user_update", "PUT", f"/api/users/{u['id']}", headers=H, json={"note": "x"})
call("user_delete", "DELETE", f"/api/users/{u['id']}", headers=H)
call("me_password_shared", "POST", "/api/me/password", headers=H, json={"current": "a", "new": "b"},
     keep_detail=True)
call("logo_get_none", "GET", "/api/branding/logo")
call("logo_delete", "DELETE", "/api/branding/logo", headers=H)
call("fw_delete", "DELETE", f"/api/firewalls/{fid}", headers=H)

# ------------------------------------------------------------------ so sánh
if RECORD:
    with open(SNAP, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1, sort_keys=True)
    print(f"RECORDED {len(out)} mục vào {SNAP}")
    sys.exit(0)

with open(SNAP, encoding="utf-8") as fh:
    want = json.load(fh)
fails = 0
for name, ok in EXTRA_CHECKS:
    fails += 0 if ok else 1
    print(("PASS " if ok else "FAIL ") + name)
for k in sorted(set(want) | set(out)):
    ok = want.get(k) == out.get(k)
    fails += 0 if ok else 1
    if ok:
        print("PASS", k)
    else:
        print("FAIL", k)
        print("   muốn:", json.dumps(want.get(k), ensure_ascii=False)[:600])
        print("   được:", json.dumps(out.get(k), ensure_ascii=False)[:600])
print("FAILS:", fails)
sys.exit(1 if fails else 0)
