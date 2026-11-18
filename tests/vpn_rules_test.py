# Chạy: bash tests/run_e2e.sh tests/vpn_rules_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# Module VPN B2 — thời hạn truy cập qua firewall rule (CHỈ ĐỌC): chỉ rule trong Rule Group VPN, hạn Schedule > tên,
# phân loại theo ngày (as_of), liên kết rule ↔ tài khoản, lịch sử thay đổi (chuỗi băm), CSV, cấu hình admin,
# không lệnh ghi nào lên firewall, không lộ bí mật.
import csv
import io
import json
import sys

import httpx

B = "http://127.0.0.1:8090"
D = "@hsc.com.vn"
AS_OF = "2026-11-18"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


mk.post("/_vpn/reset")
mk.post("/_reset_stats")
tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
fid = c.post("/api/firewalls", headers=H, json={"name": "FW-VPN", "host": "127.0.0.1", "port": 4460,
                                                "username": "apiadmin", "password": "Sophos@123"}).json()["id"]
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]}).json()
chk("đồng bộ tài khoản + rule", r["status"] == "done" and r["results"][0]["ok"], r.get("results"))
chk("lần đầu: 8 rule trong group VPN (bỏ LAN to WAN)", r["results"][0]["rules"]["total"] == 8, r["results"][0].get("rules"))


def get(**params):
    return c.get("/api/vpn/rules", headers=H, params={"as_of": AS_OF, **params}).json()


out = get()
by = {x["rule_name"]: x for x in out["rules"]}
chk("không có rule ngoài group VPN", "LAN to WAN" not in by)
chk("giữ thứ tự trong group", [x["position"] for x in out["rules"]] == list(range(1, 9)))
t = by["THAM.NQ expire 23/04/2027"]
chk("THAM.NQ: hạn từ Schedule, còn hạn", t["expiry_source"] == "schedule" and t["expiry_date"] == "2027-04-23"
    and t["status"] == "active", t["status"])
chk("lưu đủ trường rule (nguồn, identity, đích, dịch vụ, schedule, log)",
    t["src_zones"] == ["VPN"] and t["src_networks"] == ["##ALL_SSLVPN_RW"] and t["identities"] == [f"tham.nq{D}"]
    and t["dst_networks"] == ["THAM.NQ - IT"] and t["services"] == ["RDP"] and t["schedule_name"] == "VPN-THAM-2027"
    and t["log_traffic"] is True and t["action"] == "Accept")
ch = by["RMS RESEARCH - CHAU.NB expire 19/10/2027"]
chk("CHAU.NB: Schedule (30/09) ưu tiên hơn tên (19/10) + cờ lệch", ch["expiry_date"] == "2027-09-30"
    and ch["expiry_mismatch"] and ch["team"] == "RMS RESEARCH" and ch["user_code"] == "CHAU.NB")
chk("NHAN.NDT (thiếu chữ expire): hạn từ tên", by["RMS RESEARCH - NHAN.NDT 30/06/2027"]["expiry_source"] == "name")
chk("HR (43 ngày, ngưỡng 30) → còn hạn", by["HR team testing HRIS - expire 31/12/2026"]["status"] == "active")
chk("rule không có ngày → không có hạn", by["VPN - RMS RESEARCH GROUP access Factset Server"]["status"] == "no_expiry")
ou = by["OLD.USER expire 01/01/2025"]
chk("OLD.USER: user bị khóa → 'User không còn / bị khóa', vẫn có cờ hết hạn còn bật",
    ou["status"] == "user_gone" and "expired_enabled" in ou["flags"], ou["flags"])
chk("rule đã tắt + hết hạn → expired_disabled", by["TEMP.VENDOR expire 15/03/2026"]["status"] == "expired_disabled")
chk("ngày không tồn tại (31/02) → không đọc được tên", by["ABC expire 31/02/2027"]["status"] == "unreadable")
chk("liên kết rule ↔ tài khoản qua identity", [a["username"] for a in t["accounts"]] == [f"tham.nq{D}"])
f = by["VPN - RMS RESEARCH GROUP access Factset Server"]
chk("liên kết qua nhóm (identity là group)", sorted(a["username"] for a in f["accounts"]) == [f"chau.nb{D}", f"nhan.ndt{D}"])
s = out["summary"]
chk("thẻ đếm theo trạng thái", s["active"] == 4 and s["expired_disabled"] == 1 and s["unreadable"] == 1
    and s["user_gone"] == 1 and s["no_expiry"] == 1 and s["mismatch"] == 1, s)
chk("danh sách team", out["teams"] == ["ABC", "HR team testing HRIS", "RMS RESEARCH"], out["teams"])

# ---------------------------------------------------------- lọc
chk("lọc theo team", {x["rule_name"] for x in get(team="rms research")["rules"]} ==
    {"RMS RESEARCH - CHAU.NB expire 19/10/2027", "RMS RESEARCH - NHAN.NDT 30/06/2027",
     "VPN - RMS RESEARCH GROUP access Factset Server"})
chk("lọc theo trạng thái (nhiều)", get(status="unreadable,no_expiry")["total"] == 2)
chk("lọc 'Lệch thời hạn'", [x["user_code"] for x in get(status="mismatch")["rules"]] == ["CHAU.NB"])
chk("lọc khoảng ngày hết hạn", {x["user_code"] for x in get(date_from="2027-01-01", date_to="2027-06-30")["rules"]}
    == {"THAM.NQ", "NHAN.NDT"})
chk("lọc theo firewall", get(firewall_id=fid)["total"] == 8 and get(firewall_id=99999)["total"] == 0)
chk("as_of: ngày 2027-04-01 → THAM.NQ sắp hết hạn",
    {x["user_code"]: x for x in c.get("/api/vpn/rules", headers=H, params={"as_of": "2027-04-01"}).json()["rules"]}
    ["THAM.NQ"]["status"] == "expiring")
chk("viewer xem được", c.get("/api/vpn/rules", headers=V).status_code == 200)

# ---------------------------------------------------------- cấu hình (admin)
r = c.put("/api/vpn/settings", headers=V, json={"expiring_days": 60})
chk("viewer không sửa được cấu hình", r.status_code == 403)
r = c.put("/api/vpn/settings", headers=H, json={"rule_groups": ["Default"]})
chk("Rule Group ngoài whitelist bị từ chối", r.status_code == 400 and "cho phép" in r.json()["detail"], r.text)
r = c.put("/api/vpn/settings", headers=H, json={"expiring_days": 0})
chk("ngưỡng ngoài 1–365 bị từ chối", r.status_code == 400)
r = c.put("/api/vpn/settings", headers=H, json={"expiring_days": 60}).json()
chk("đổi ngưỡng 60 ngày", r["expiring_days"] == 60 and r["allowed_rule_groups"] == ["VPN"])
chk("ngưỡng mới → HR (43 ngày) sắp hết hạn", {x["team"]: x for x in get()["rules"]}["HR team testing HRIS"]["status"]
    == "expiring")
c.put("/api/vpn/settings", headers=H, json={"expiring_days": 30})
chk("đổi cấu hình được ghi audit", any(a["target"] == "vpn" for a in
                                       c.get("/api/audit?action=settings_cud", headers=H).json()["rows"]))

# ---------------------------------------------------------- lịch sử thay đổi
ch0 = c.get("/api/vpn/changes", headers=H).json()["changes"]
chk("lần đầu: một sự kiện baseline (không 8 sự kiện thêm)", [x["change_type"] for x in ch0] == ["baseline"], ch0)
mk.post("/_vpn/rule", params={"name": "THAM.NQ expire 23/04/2027", "schedule_end": "2027-12-31 23:59:00"})
mk.post("/_vpn/rule", params={"name": "RMS RESEARCH - NHAN.NDT 30/06/2027", "dst": "RMS,NEW-SERVER"})
mk.post("/_vpn/rule", params={"name": "HR team testing HRIS - expire 31/12/2026", "status": "Disable"})
mk.post("/_vpn/rule", params={"name": "TEMP.VENDOR expire 15/03/2026", "action": "remove"})
mk.post("/_vpn/rule", params={"name": "ABC expire 31/02/2027", "new_name": "ABC expire 28/02/2027"})
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid], "kind": "rules"}).json()["results"][0]["rules"]
chk("đồng bộ lần 2: đổi 3, mất 2 (1 xóa + 1 đổi tên), mới 1", r["changed"] == 3 and r["removed"] == 2 and r["new"] == 1, r)
evs = c.get("/api/vpn/changes", headers=H).json()["changes"]
kinds = {(x["rule_name"], x["change_type"]) for x in evs}
chk("ghi đổi hạn", ("THAM.NQ expire 23/04/2027", "expiry_changed") in kinds)
chk("ghi đổi đích", ("RMS RESEARCH - NHAN.NDT 30/06/2027", "destination_changed") in kinds)
chk("ghi bật/tắt", ("HR team testing HRIS - expire 31/12/2026", "status_changed") in kinds)
chk("ghi rule bị xóa", ("TEMP.VENDOR expire 15/03/2026", "rule_removed") in kinds)
chk("đổi tên = xóa tên cũ + thêm tên mới", ("ABC expire 31/02/2027", "rule_removed") in kinds
    and ("ABC expire 28/02/2027", "rule_added") in kinds)
e = next(x for x in evs if x["change_type"] == "expiry_changed")
chk("sự kiện có trước/sau", e["before"]["expiry_date"] == "2027-04-23" and e["after"]["expiry_date"] == "2027-12-31", e)
v = c.get("/api/vpn/changes/verify", headers=H).json()
chk("chuỗi băm lịch sử VPN toàn vẹn", v["ok"] and v["checked"] == len(evs), v)
chk("rule đã xóa không hiện mặc định", "TEMP.VENDOR expire 15/03/2026" not in {x["rule_name"] for x in get()["rules"]})
rid = {x["rule_name"]: x["id"] for x in get()["rules"]}["THAM.NQ expire 23/04/2027"]
d = c.get(f"/api/vpn/rules/{rid}", headers=H).json()
chk("chi tiết rule kèm lịch sử", d["rule"]["expiry_date"] == "2027-12-31" and
    [h["change_type"] for h in d["history"]] == ["expiry_changed"])
r = c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid], "kind": "rules"}).json()["results"][0]["rules"]
chk("đồng bộ lại không đổi gì → không sinh sự kiện", r["events"] == 0 and r["changed"] == 0, r)

# ---------------------------------------------------------- CSV
r = c.get("/api/vpn/rules.csv", params={"token": tok, "status": "expired_enabled,user_gone,unreadable", "as_of": AS_OF})
rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
chk("CSV danh sách cần xử lý", r.status_code == 200 and rows[0][3] == "ten_rule"
    and {x[3] for x in rows[1:]} == {"OLD.USER expire 01/01/2025"}, [x[3] for x in rows[1:]])
chk("CSV cần token hợp lệ", c.get("/api/vpn/rules.csv", params={"token": "sai"}).status_code == 401)

# ---------------------------------------------------------- an toàn
st = mk.get("/_stats").json()
chk("không lệnh ghi nào lên firewall trong suốt test", st["set_requests"] == 0, st)
blob = json.dumps([get(include_removed=True), evs], ensure_ascii=False)
chk("không lộ bí mật", "MOCK-SECRET" not in blob)
print("FAILS:", fails)
sys.exit(1 if fails else 0)
