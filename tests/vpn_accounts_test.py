# Chạy: bash tests/run_e2e.sh tests/vpn_accounts_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# Module VPN B1 — tài khoản (CHỈ ĐỌC): quyền SSL VPN/IPsec, upsert theo (firewall, user), removed_at không xóa,
# phân quyền viewer/operator, KHÔNG lộ mật khẩu/hash/khóa ở API, DB hay log; firewall lỗi không làm hỏng lượt.
import json
import os
import sys
import time

import httpx
import sqlalchemy as sa

sys.path.insert(0, "backend")
from app.modules.vpn.accounts import compute_access  # noqa: E402

B = "http://127.0.0.1:8090"
SECRET = "MOCK-SECRET-KHONG-DUOC-LO"
D = "@hsc.com.vn"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# ---------------------------------------------------------- hàm thuần
acc = compute_access(
    users=[{"username": "a@x", "group": "G1", "sslvpn_policy": "No Policy Applied"},
           {"username": "b@x", "group": "", "sslvpn_policy": "P"},
           {"username": "c@x", "group": "", "sslvpn_policy": ""},
           {"username": "d@x", "group": "", "sslvpn_policy": ""}],
    groups=[{"name": "G1", "sslvpn_policy": "P", "members": []}, {"name": "G2", "sslvpn_policy": "", "members": ["C@X"]}],
    ssl=[], ipsec=[{"connection_type": "RemoteAccess", "allowed_users": ["G2"]},
                   {"connection_type": "SiteToSite", "allowed_users": ["d@x"]}])
by = {a["username"]: a for a in acc}
chk("quyền SSL VPN qua nhóm có policy", by["a@x"]["has_sslvpn"] and by["a@x"]["groups"] == ["G1"])
chk("quyền SSL VPN qua policy riêng", by["b@x"]["has_sslvpn"])
chk("IPsec qua nhóm trong AllowedUser (không phân biệt hoa/thường)", by["c@x"]["has_ipsec"] and not by["c@x"]["has_sslvpn"])
chk("IPsec SiteToSite không tính là VPN người dùng", not by["d@x"]["has_ipsec"])

# ---------------------------------------------------------- qua API
mk.post("/_vpn/reset")
mk.post("/_reset_stats")
H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
fid = c.post("/api/firewalls", headers=H, json={"name": "FW-VPN", "host": "127.0.0.1", "port": 4460,
                                                "username": "apiadmin", "password": "Sophos@123"}).json()["id"]
r = c.post("/api/vpn/sync", headers=V, json={"firewall_ids": [fid]})
chk("viewer không được đồng bộ", r.status_code == 403, r.status_code)
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]}).json()
chk("đồng bộ xong", r["status"] == "done" and r["results"][0]["ok"], r.get("results"))
s = r["results"][0]["summary"]
chk("lần đầu: 6 tài khoản mới", s["total"] == 6 and s["new"] == 6, s)

r = c.get("/api/vpn/accounts", headers=V)
chk("viewer xem được", r.status_code == 200)
rows = {a["username"]: a for a in r.json()["accounts"]}
chk("mặc định chỉ tài khoản có VPN (không có admin)", set(rows) == {f"tham.nq{D}", f"chau.nb{D}", f"nhan.ndt{D}",
                                                                  f"hr.test1{D}", f"old.user{D}"}, sorted(rows))
chau = rows[f"chau.nb{D}"]
chk("chau.nb: SSL VPN qua nhóm + IPsec remote access", chau["has_sslvpn"] and chau["has_ipsec"]
    and "RMS RESEARCH" in chau["groups"], chau)
chk("tham.nq: SSL VPN, không IPsec", rows[f"tham.nq{D}"]["has_sslvpn"] and not rows[f"tham.nq{D}"]["has_ipsec"])
chk("tài khoản Deactive → enabled=false", rows[f"old.user{D}"]["enabled"] is False)
chk("có email + tên hiển thị", chau["email"] == f"chau.nb{D}" and chau["display_name"] == "Ngô Bảo Châu")
r_all = c.get("/api/vpn/accounts?scope=all", headers=H).json()
chk("scope=all gồm cả admin", r_all["total"] == 6)
chk("trạng thái đồng bộ theo firewall", r_all["syncs"][0]["status"] == "ok" and r_all["syncs"][0]["firewall"] == "FW-VPN")
chk("lọc theo từ khóa", [a["username"] for a in c.get("/api/vpn/accounts?q=rms", headers=H).json()["accounts"]]
    == [f"chau.nb{D}", f"nhan.ndt{D}"])

# ---------------------------------------------------------- mất / xuất hiện lại
mk.post("/_vpn/user", params={"username": f"nhan.ndt{D}", "action": "remove"})
mk.post("/_vpn/user", params={"username": f"tham.nq{D}", "action": "disable"})
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]}).json()["results"][0]["summary"]
chk("tài khoản mất được đánh dấu (không xóa)", r["removed"] == 1 and r["total"] == 5, r)
present = {a["username"] for a in c.get("/api/vpn/accounts", headers=H).json()["accounts"]}
removed = c.get("/api/vpn/accounts?state=removed", headers=H).json()["accounts"]
chk("mặc định không hiện tài khoản đã mất", f"nhan.ndt{D}" not in present)
chk("state=removed hiện tài khoản đã mất kèm removed_at", [a["username"] for a in removed] == [f"nhan.ndt{D}"]
    and removed[0]["removed_at"])
chk("tài khoản bị disable trên firewall → enabled=false",
    {a["username"]: a for a in c.get("/api/vpn/accounts", headers=H).json()["accounts"]}[f"tham.nq{D}"]["enabled"] is False)
first_seen = removed[0]["first_seen_at"]
mk.post("/_vpn/reset")
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]}).json()["results"][0]["summary"]
back = {a["username"]: a for a in c.get("/api/vpn/accounts", headers=H).json()["accounts"]}
chk("xuất hiện lại → khôi phục, giữ first_seen", r["restored"] == 1 and back[f"nhan.ndt{D}"]["removed_at"] is None
    and back[f"nhan.ndt{D}"]["first_seen_at"] == first_seen, r)

# ---------------------------------------------------------- firewall lỗi
bad = c.post("/api/firewalls", headers=H, json={"name": "FW-DOWN", "host": "127.0.0.1", "port": 4999,
                                                "username": "apiadmin", "password": "x"}).json()["id"]
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid, bad]}).json()
res = {x["firewall"]: x for x in r["results"]}
chk("firewall lỗi không làm hỏng lượt đồng bộ firewall khác", res["FW-VPN"]["ok"] and not res["FW-DOWN"]["ok"]
    and res["FW-DOWN"]["error"], r["results"])
st = {x["firewall"]: x for x in c.get("/api/vpn/accounts", headers=H).json()["syncs"]}
chk("trạng thái lỗi được ghi lại", st["FW-DOWN"]["status"] == "error")
audit = c.get("/api/audit?action=vpn_sync", headers=H).json()["rows"]
chk("ghi audit vpn_sync (người thực hiện)", audit and audit[0]["actor"] == "phu.luong@hsc.com.vn")
chk("đồng bộ không gửi lệnh ghi nào lên firewall", mk.get("/_stats").json()["set_requests"] == 0,
    mk.get("/_stats").json())

# ---------------------------------------------------------- chọn firewall có VPN (Cài đặt › VPN)
chk("mặc định: chưa chọn firewall có VPN (= mọi firewall đang bật)",
    c.get("/api/vpn/settings", headers=V).json()["firewall_ids"] == [])
r = c.put("/api/vpn/settings", headers=V, json={"firewall_ids": [fid]})
chk("viewer không chọn được firewall có VPN", r.status_code == 403, r.status_code)
r = c.put("/api/vpn/settings", headers=H, json={"firewall_ids": [fid, 999999]})
chk("chọn firewall không tồn tại → 400", r.status_code == 400 and "999999" in r.json()["detail"], r.text[:200])
r = c.put("/api/vpn/settings", headers=H, json={"firewall_ids": [fid]})
chk("chọn chỉ FW-VPN là firewall có VPN", r.status_code == 200 and r.json()["firewall_ids"] == [fid], r.text[:200])
r = c.post("/api/vpn/sync", headers=H, json={}).json()
chk("Đồng bộ ngay (không chỉ định) → chỉ đọc firewall có VPN, bỏ FW-DOWN",
    [x["firewall"] for x in r["results"]] == ["FW-VPN"], r.get("results"))
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [bad]})
chk("chỉ định firewall chưa chọn là có VPN → 400", r.status_code == 400 and "Cài đặt › VPN" in r.json()["detail"],
    r.text[:200])
st = [x["firewall"] for x in c.get("/api/vpn/accounts", headers=H).json()["syncs"]]
chk("trạng thái đồng bộ chỉ hiện firewall có VPN", st == ["FW-VPN"], st)
r = c.put("/api/vpn/settings", headers=H, json={"firewall_ids": [bad]})
chk("đổi sang chỉ FW-DOWN", r.status_code == 200 and r.json()["firewall_ids"] == [bad])
chk("dữ liệu firewall bỏ chọn được giữ nhưng ẩn khỏi danh sách tài khoản",
    c.get("/api/vpn/accounts", headers=H).json()["total"] == 0)
r = c.put("/api/vpn/settings", headers=H, json={"firewall_ids": []})
chk("bỏ chọn hết → quay về mọi firewall đang bật, dữ liệu FW-VPN hiện lại", r.json()["firewall_ids"] == []
    and c.get("/api/vpn/accounts", headers=H).json()["total"] > 0)

# ---------------------------------------------------------- không lộ bí mật
blob = json.dumps([c.get(f"/api/vpn/accounts?scope=all&state=all", headers=H).json(),
                   c.get("/api/audit?limit=2000", headers=H).json()], ensure_ascii=False)
chk("API không chứa bí mật", SECRET not in blob)
eng = sa.create_engine(os.environ["DATABASE_URL"])
dump = []
with eng.connect() as conn:
    for t in sa.inspect(eng).get_table_names():
        dump += [str(tuple(r)) for r in conn.execute(sa.text(f'SELECT * FROM "{t}"'))]
chk("DB (mọi bảng) không chứa bí mật", dump and SECRET not in "\n".join(dump), f"{len(dump)} dòng")
time.sleep(0.3)
chk("log app không chứa bí mật", SECRET not in open("/tmp/app_t.log", encoding="utf-8").read())
print("FAILS:", fails)
sys.exit(1 if fails else 0)
