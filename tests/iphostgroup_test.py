# Chạy: bash tests/run_e2e.sh tests/iphostgroup_test.py
# Kiểm tra mapping Object Group -> Sophos IPHostGroup theo đúng mẫu XML:
#   <IPHostGroup><Name/><IPFamily/><Description/><HostList><Host/>...</HostList></IPHostGroup>
import json, re, sys

import httpx

sys.path.insert(0, "backend")
from app.sophos import SophosClient, build_iphostgroup_xml  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# 1) Builder: đúng thứ tự thẻ
x = build_iphostgroup_xml("SCANPORT GROUP", ["SOC_BLOCK_1_2_3_4", "SOC_BLOCK_1_2_3_4", "H2"], "Mô tả", "IPv4")
tags = re.findall(r"<(\w+)>", x)
chk("builder order Name→IPFamily→Description→HostList",
    tags[:5] == ["IPHostGroup", "Name", "IPFamily", "Description", "HostList"], tags[:5])
chk("builder dedup Host", x.count("<Host>SOC_BLOCK_1_2_3_4</Host>") == 1)
for bad, why in [(("A,B", []), "comma name"), (("G", ["h,1"]), "comma host"),
                 (("G", ["h" * 61]), "host > 60"), (("G", [], "", "ipv4"), "family")]:
    try:
        build_iphostgroup_xml(*bad)
        chk(f"builder rejects {why}", False)
    except ValueError:
        chk(f"builder rejects {why}", True)

tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
fw = {"name": "FW-HCM", "host": "127.0.0.1", "port": 4460, "username": "apiadmin",
      "password": "Sophos@123"}
fid = c.post("/api/firewalls", json=fw, headers=H).json()["id"]
fc = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123",
                  verify_ssl=False, timeout=10)
desc_before = fc.get_group("SCANPORT GROUP")["description"]

# 2) Dry-run trả payload IPHostGroup dự kiến
r = c.post("/api/block", json={"values": ["45.155.205.10", "185.220.101.0/24"], "firewall_ids": [fid],
                               "dry_run": True}, headers=H).json()["results"][0]
gx = r.get("group_xml", "")
chk("dry-run has group_xml + operation update", "<IPHostGroup>" in gx and r["group_operation"] == "update", r.get("group_operation"))
chk("dry-run xml order", re.findall(r"<(\w+)>", gx)[:5] == ["IPHostGroup", "Name", "IPFamily", "Description", "HostList"])
chk("dry-run xml lists new hosts", "<Host>SOC_BLOCK_45_155_205_10</Host>" in gx and "<Host>SOC_BLOCK_185_220_101_0-24</Host>" in gx)
chk("dry-run did not touch firewall", "SOC_BLOCK_45_155_205_10" not in fc.get_group("SCANPORT GROUP")["hosts"])

# 3) Chạy thật: mock từ chối nếu sai thứ tự thẻ → phải thành công
r = c.post("/api/block", json={"values": ["45.155.205.10", "185.220.101.0/24"], "firewall_ids": [fid],
                               "reason": "test IPHostGroup"}, headers=H).json()["results"][0]
chk("real block accepted by strict mock", r["ok"] and r["group_result"]["changed"], json.dumps(r["group_result"]))
g = fc.get_group("SCANPORT GROUP")
chk("hosts linked in IPHostGroup", {"SOC_BLOCK_45_155_205_10", "SOC_BLOCK_185_220_101_0-24"} <= set(g["hosts"]))
chk("Description preserved", g["description"] == desc_before, g["description"])
chk("IPFamily preserved IPv4", g["ip_family"] == "IPv4")

# 4) HARDENING: mọi group khác SCANPORT GROUP đều bị từ chối (403) và không chạm firewall
others = fc.list_groups()
chk("client.list_groups only exposes SCANPORT GROUP", [g["name"] for g in others] == ["SCANPORT GROUP"], [g["name"] for g in others])
import json as _j
raw = _j.load(open("/tmp/mock_t.json"))
other_before = {k: v["HostList"] for k, v in raw["groups"].items() if k != "SCANPORT GROUP"}
for grp in ["SOC_BLOCKED_IPS", "SOC_BLOCKED_IPV6", "scanport group", "SCANPORT GROUP ", "SCANPORT_GROUP", "NEW_GRP"]:
    r = c.post("/api/block", json={"values": ["91.240.118.8"], "firewall_ids": [fid], "group": grp}, headers=H)
    ok = r.status_code == 403 or (grp.strip() == "SCANPORT GROUP" and r.status_code == 200)
    chk(f"block group={grp!r} -> {r.status_code}", ok, r.text[:90])
r = c.post("/api/unblock", json={"targets": ["45.155.204.11"], "firewall_ids": [fid], "group": "SOC_BLOCKED_IPS"}, headers=H)
chk("unblock other group -> 403", r.status_code == 403)
r = c.get(f"/api/firewalls/{fid}/group-members?group=SOC_BLOCKED_IPS", headers=H)
chk("view other group members -> 403", r.status_code == 403)
r = c.post("/api/changes/sync", json={"group": "SOC_BLOCKED_IPS"}, headers=H)
chk("sync other group -> 403", r.status_code == 403)
r = c.get("/api/changes?group=SOC_BLOCKED_IPS", headers=H)
chk("history other group -> 403", r.status_code == 403)
r = c.post("/api/firewalls", json={**fw, "name": "FW-X", "default_group": "SOC_BLOCKED_IPS"}, headers=H)
chk("create firewall with other default_group -> 403", r.status_code == 403)
r = c.put(f"/api/firewalls/{fid}", json={"default_group": "SOC_BLOCKED_IPS"}, headers=H)
chk("update firewall default_group -> 403", r.status_code == 403)
fwl = c.get("/api/firewalls", headers=H).json()
fwl = fwl if isinstance(fwl, list) else fwl.get("firewalls", fwl.get("items", []))
chk("firewall default_group forced", all(f["default_group"] == "SCANPORT GROUP" for f in fwl))
raw = _j.load(open("/tmp/mock_t.json"))
chk("other groups on firewall untouched", {k: v["HostList"] for k, v in raw["groups"].items() if k != "SCANPORT GROUP"} == other_before)
au = c.get("/api/audit?action=policy_violation", headers=H).json()
rows = au if isinstance(au, list) else au.get("rows", au.get("items", []))
chk("policy violations audited", len(rows) >= 8, len(rows))
try:
    fc.set_group_hosts("SOC_BLOCKED_IPS", [], "", "IPv4"); chk("client refuses other group", False)
except ValueError:
    chk("client refuses other group (defense in depth)", True)
try:
    fc.delete_ip_host("PARTNER_VPN_GW"); chk("client refuses deleting non-prefix host", False)
except ValueError:
    chk("client refuses deleting non-prefix host", True)
cfg = c.get("/api/config", headers=H).json()
chk("config exposes block_group", cfg.get("block_group") == "SCANPORT GROUP")

# 6) Bỏ chặn: ghi lại HostList, giữ Description
r = c.post("/api/unblock", json={"targets": ["45.155.205.10"], "firewall_ids": [fid], "reason": "FP"},
           headers=H).json()["results"][0]
g = fc.get_group("SCANPORT GROUP")
chk("unblock removes from HostList", "SOC_BLOCK_45_155_205_10" not in g["hosts"] and r["summary"]["removed"] == 1)
chk("unblock keeps Description", g["description"] == desc_before)

# 7) Groups endpoint chỉ trả về group cố định
gl = c.get(f"/api/firewalls/{fid}/groups", headers=H).json()
chk("groups endpoint returns only SCANPORT GROUP", [x["name"] for x in gl["groups"]] == ["SCANPORT GROUP"] and gl["locked"], gl.get("groups"))

print("RESULT", "OK" if not fails else f"{fails} FAIL")
