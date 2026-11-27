# Chạy: bash tests/run_e2e.sh tests/audit_search_test.py
# Tìm audit lọc trong SQL trước LIMIT; q là chuỗi con không phân biệt hoa thường, % _ không phải ký tự đại diện.
# Lưu ý: SQLite lower() không xử lý chữ hoa có dấu (PostgreSQL ILIKE thì có) nên không kiểm chữ hoa có dấu ở đây.
import httpx
import sqlalchemy as sa

from app.core.db import SessionLocal, engine
from app.core.models import AuditLog

c = httpx.Client(base_url="http://127.0.0.1:8090", timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")


tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}

with SessionLocal() as db:
    db.add(AuditLog(action="block", target="FW_HCM-old", firewall_name="fwA", reason="rare-needle"))
    db.add(AuditLog(action="unblock", target="FWxHCM-old", firewall_name="fwA"))
    db.add(AuditLog(action="block", target="FW_HCM-old2", firewall_name="fwB", reason="100% done"))
    db.flush()
    for i in range(30):
        db.add(AuditLog(action="test", target=f"1.1.1.{i}", firewall_name="fwC"))
    db.commit()


def get(**p):
    r = c.get("/api/audit", params=p, headers=H)
    return r.status_code, r.json()


s, j = get(q="rare-needle", limit=5)
chk("cũ hơn limit vẫn tìm thấy", s == 200 and [r["target"] for r in j["rows"]] == ["FW_HCM-old"], j)
s, j = get(q="fw_hcm", limit=5)
t = sorted(r["target"] for r in j["rows"])
chk("_ không là ký tự đại diện, không phân biệt hoa thường", t == ["FW_HCM-old", "FW_HCM-old2"], t)
s, j = get(q="FWXHCM")
chk("khớp FWxHCM không phân biệt hoa thường", [r["target"] for r in j["rows"]] == ["FWxHCM-old"], j)
s, j = get(q="100%")
chk("% là ký tự thường", [r["reason"] for r in j["rows"]] == ["100% done"], j)
s, j = get(q="fw_hcm", action="block")
chk("action + q", sorted(r["target"] for r in j["rows"]) == ["FW_HCM-old", "FW_HCM-old2"], j)
s, j = get(q="fw_hcm", action="unblock")
chk("action + q loại đúng", j["rows"] == [], j)
s, j = get(limit=5)
chk("count == len(rows)", j["count"] == len(j["rows"]) == 5, j["count"])
chk("index action tồn tại",
    any(i["column_names"] == ["action"] for i in sa.inspect(engine).get_indexes("audit_logs")))

print("FAIL" if fails else "PASS all")
raise SystemExit(1 if fails else 0)
