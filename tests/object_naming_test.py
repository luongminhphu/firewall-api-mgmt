# Chạy: bash tests/run_e2e.sh tests/object_naming_test.py
# v1.4: tên IP Host = chính địa chỉ IP/CIDR (45.138.12.16, 185.220.101.0/24), tương thích object kiểu cũ SOC_BLOCK_*.
import json
import sys

import httpx

sys.path.insert(0, "backend")
from app.ipparse import host_object_name, is_app_owned, legacy_object_name  # noqa: E402
from app.sophos import SophosClient  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# 1) Hàm đặt tên
chk("IP -> name = IP", host_object_name("45.138.12.16") == "45.138.12.16")
chk("CIDR -> name = CIDR", host_object_name("185.220.101.0/24") == "185.220.101.0/24")
chk("CIDR normalized", host_object_name("185.220.101.7/24") == "185.220.101.0/24")
chk("/32 -> plain IP", host_object_name("45.138.12.16/32") == "45.138.12.16")
chk("legacy name", legacy_object_name("45.138.12.16") == "SOC_BLOCK_45_138_12_16")
chk("owned: name==value", is_app_owned("45.138.12.16", "45.138.12.16"))
chk("owned: legacy prefix", is_app_owned("SOC_BLOCK_1_2_3_4", None))
chk("not owned: IP-name pointing elsewhere", not is_app_owned("1.2.3.4", "10.0.0.1"))
chk("not owned: IP-name without known value", not is_app_owned("1.2.3.4", None))
chk("not owned: admin object", not is_app_owned("PARTNER_VPN_GW", "203.0.113.5"))

tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
fw = {"name": "FW-HCM", "host": "127.0.0.1", "port": 4460, "username": "apiadmin", "password": "Sophos@123"}
fid = c.post("/api/firewalls", json=fw, headers=H).json()["id"]
fc = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123",
                  verify_ssl=False, timeout=10)

# 2) Preview (extract) hiển thị tên mới
ex = c.post("/api/parse", json={"text": "SOC: 45.138.12[.]16, 185.220.101.0/24"}, headers=H)
objs = [i.get("object") for i in ex.json().get("accepted", [])]
chk("preview object names = IP/CIDR", objs == ["45.138.12.16", "185.220.101.0/24"], objs)

# 3) Chặn thật -> object tên = IP
r = c.post("/api/block", json={"values": ["45.138.12.16", "185.220.101.0/24"], "firewall_ids": [fid],
                               "reason": "Tet 2027"}, headers=H).json()["results"][0]
chk("block ok", r["ok"] and r["group_result"]["changed"], json.dumps(r["group_result"]))
g = fc.get_group("SCANPORT GROUP")
chk("group has 45.138.12.16 & 185.220.101.0/24", {"45.138.12.16", "185.220.101.0/24"} <= set(g["hosts"]), g["hosts"])
hosts = {h["name"]: h for h in fc.get_hosts(["45.138.12.16", "185.220.101.0/24"])}
chk("IP Host 45.138.12.16 type IP", hosts.get("45.138.12.16", {}).get("ip_address") == "45.138.12.16")
chk("IP Host 185.220.101.0/24 type Network", hosts.get("185.220.101.0/24", {}).get("host_type") == "Network")
chk("no SOC_BLOCK_ object created", not any(h["name"] == "SOC_BLOCK_45_138_12_16" for h in fc.get_hosts()))

# 4) IP đã chặn dưới tên kiểu cũ -> nhận ra, không tạo trùng
r = c.post("/api/block", json={"values": ["45.155.204.11"], "firewall_ids": [fid]}, headers=H).json()["results"][0]
row = r["rows"][0]
chk("legacy member recognized as existed", row["result"] == "existed" and row["object"] == "SOC_BLOCK_45_155_204_11", row)
chk("no duplicate object for legacy IP", not any(h["name"] == "45.155.204.11" for h in fc.get_hosts()))
r = c.post("/api/block", json={"values": ["45.138.12.16"], "firewall_ids": [fid], "dry_run": True},
           headers=H).json()["results"][0]
chk("dry-run: already blocked -> existed", r["rows"][0]["result"] == "existed", r["rows"][0])

# 5) Object tên trùng IP nhưng trỏ địa chỉ khác (admin tạo) -> không dùng nhầm
fc.add_ip_host("91.240.118.9", "IP", "10.10.10.10", "admin tao nham")
r = c.post("/api/block", json={"values": ["91.240.118.9"], "firewall_ids": [fid]}, headers=H).json()["results"][0]
chk("name-collision with wrong address -> error", r["rows"][0]["result"] == "error", r["rows"][0]["message"])
chk("collision object not linked", "91.240.118.9" not in fc.get_group("SCANPORT GROUP")["hosts"])

# 6) Bỏ chặn + xóa object: tên mới và tên cũ đều xóa được
r = c.post("/api/unblock", json={"targets": ["45.138.12.16", "45.155.204.11"], "firewall_ids": [fid],
                                 "delete_object": True, "reason": "FP"}, headers=H).json()["results"][0]
msgs = [x["message"] for x in r["rows"]]
chk("unblock both removed", r["summary"]["removed"] == 2, msgs)
names = {h["name"] for h in fc.get_hosts()}
chk("object 45.138.12.16 deleted", "45.138.12.16" not in names, msgs)
chk("legacy object deleted", "SOC_BLOCK_45_155_204_11" not in names, msgs)

# 7) Client từ chối xóa object không do app tạo
for name, val in [("91.240.118.9", "10.10.10.10"), ("PARTNER_VPN_GW", None), ("91.240.118.9", None)]:
    try:
        fc.delete_ip_host(name, val)
        chk(f"refuse delete {name}", False)
    except ValueError:
        chk(f"refuse delete {name} (value={val})", True)

print("RESULT", "OK" if not fails else f"{fails} FAIL")
