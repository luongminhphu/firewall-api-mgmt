# Chạy: bash tests/run_e2e.sh  (mock Sophos :4460 + app :8090, SQLite tạm trong /tmp)
import httpx, json, sqlite3, time
B="http://127.0.0.1:8090"
c=httpx.Client(base_url=B, timeout=30)
def chk(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ")+name, extra)
# header SSO
r=c.post("/api/auth/header", headers={"X-SRB-UPN":"Phu.Luong@hsc.com.vn","X-SRB-NAME":"Lương Minh Phú".encode("utf-8")})
chk("header sso admin", r.status_code==200 and r.json()["role"]=="admin", r.text[:120])
tok=r.json()["token"]; H={"X-Auth-Token":tok}
r=c.post("/api/auth/header", headers={"X-SRB-UPN":"guest@hsc.com.vn"})
chk("header sso default viewer", r.json().get("role")=="viewer")
vtok=r.json()["token"]
r=c.post("/api/auth/header")
chk("header missing -> 401", r.status_code==401, r.text[:100])
# local login -> admin role
r=c.post("/api/login", json={"user":"soc.truc","password":"socadmin"})
chk("local login", r.status_code==200)
r=c.post("/api/login", json={"user":"x","password":"bad"}); chk("local bad pw 401", r.status_code==401)
# oidc not ready
r=c.get("/api/auth/oidc/login", follow_redirects=False); chk("oidc not configured -> 500 msg", r.status_code==500, r.text[:100])
# config
r=c.get("/api/config", headers=H); chk("config role/name", r.json()["role"]=="admin" and r.json()["name"]=="Lương Minh Phú", r.json()["user"])
# viewer cannot add firewall
fwp={"name":"FW-HCM","host":"127.0.0.1","port":4460,"username":"apiadmin","password":"Sophos@123"}
r=c.post("/api/firewalls", json=fwp, headers={"X-Auth-Token":vtok}); chk("viewer add fw -> 403", r.status_code==403)
r=c.post("/api/firewalls", json=fwp, headers=H); chk("admin add fw", r.status_code==200, r.text[:100]); fid=r.json()["id"]
r=c.post("/api/block", json={"values":["45.155.205.10"],"firewall_ids":[fid]}, headers={"X-Auth-Token":vtok}); chk("viewer block -> 403", r.status_code==403)
# block 3 IPs
r=c.post("/api/block", json={"values":["45.155.205.10","185.220.101.0/24","91.240.118.7"],"firewall_ids":[fid],"reason":"SOC ticket #123 do quet","source":"teams-paste"}, headers=H)
res=r.json()["results"][0]; chk("block 3", res["summary"]["added"]+res["summary"]["existed"]==3, json.dumps(res["summary"]))
# changes
r=c.get("/api/changes", headers=H).json()
kinds=[b["kind"] for b in r["batches"]]
chk("changes has baseline+change", "baseline" in kinds and "change" in kinds, kinds)
chg=[b for b in r["batches"] if b["kind"]=="change"][0]
chk("change items + counts", len(chg["added"])==3 and chg["count_after"]-chg["count_before"]==3 and chg["actor"]=="phu.luong@hsc.com.vn", f'{chg["count_before"]}->{chg["count_after"]} {[a["value"] for a in chg["added"]]}')
# drift: modify mock state directly — remove one + add one externally
st=json.load(open("/tmp/mock_t.json"))
print("mock keys", list(st.keys()))
# ---- drift: thay đổi trực tiếp trên firewall bằng client riêng (giả lập admin sửa WebAdmin)
import sys; sys.path.insert(0,"/home/user/workspace/sophos-blocker/backend")
from app.sophos import SophosClient
fc=SophosClient(host="127.0.0.1",port=4460,username="apiadmin",password="Sophos@123",verify_ssl=False,timeout=10)
fc.add_ip_host("MANUAL_BAD_1","IP","103.77.1.9","them tay tren WebAdmin")
g=fc.get_group("SCANPORT GROUP")
hosts=[h for h in g["hosts"] if h!="91.240.118.7"]+["MANUAL_BAD_1"]
fc.set_group_hosts("SCANPORT GROUP",hosts,g["description"],g["ip_family"])
r=c.post("/api/changes/sync", json={"firewall_ids":[fid]}, headers=H).json()
res=r["results"][0]; chk("sync detects drift", res["added"]==["MANUAL_BAD_1"] and res["removed"]==["91.240.118.7"], json.dumps(res))
r=c.get("/api/changes?type=drift", headers=H).json()
vals=sorted([a["value"] for b in r["batches"] for a in b["added"]]+["-"+x["value"] for b in r["batches"] for x in b["removed"]])
chk("drift values resolved", "103.77.1.9" in vals and "-91.240.118.7" in vals and all(b["actor"]=="ngoai-app" for b in r["batches"]), vals)
# sync again -> no new drift
r=c.post("/api/changes/sync", json={"firewall_ids":[fid]}, headers=H).json()["results"][0]
chk("sync idempotent", not r["added"] and not r["removed"])
# unblock
r=c.post("/api/unblock", json={"targets":["45.155.205.10","185.220.101.0"],"firewall_ids":[fid],"reason":"False positive - IP doi tac"}, headers=H).json()
chk("unblock 2", r["results"][0]["summary"]["removed"]==2, json.dumps(r["results"][0]["summary"]))
b=c.get("/api/changes?q=45.155.205.10", headers=H).json()["batches"]
chk("search by IP returns add+remove batches", len(b)==2 and {len(x["added"])>0 for x in b}=={True,False}, [ (x["kind"],len(x["added"]),len(x["removed"])) for x in b])
rm=[x for x in b if x["removed"]][0]
chk("remove batch counts", rm["count_after"]==rm["count_before"]-2 and rm["reason"].startswith("False"), f'{rm["count_before"]}->{rm["count_after"]}')
# member view triggers no false drift
r=c.get(f"/api/firewalls/{fid}/group-members?group=SCANPORT%20GROUP", headers=H); chk("members view", r.status_code==200, r.json()["total"])
d=c.get("/api/changes?type=drift", headers=H).json()["totals"]["drift"]; chk("no false drift after app ops", d==1, d)
# filters
r=c.get("/api/changes?actor=phu.luong&from=2020-01-01&to=2099-12-31", headers=H).json(); chk("actor+date filter", r["totals"]["batches"]==2, r["totals"])
r=c.get("/api/changes?from=bad", headers=H); chk("bad date 400", r.status_code==400)
# csv
r=c.get(f"/api/changes.csv?token={tok}"); lines=r.text.strip().splitlines()
chk("csv export", r.status_code==200 and lines[0].startswith("\ufeffthoi_gian_vn") and any(",BOT,91.240.118.7" in l for l in lines), f"{len(lines)} dòng")
print("   ", lines[1][:160])
# verify chain ok
v=c.get("/api/changes/verify", headers=H).json(); chk("chain ok", v["ok"], v["message"])
# tamper: edit one row
db=sqlite3.connect("/tmp/sb_t.db"); db.execute("update group_changes set value='1.1.1.1' where id=3"); db.commit()
v=c.get("/api/changes/verify", headers=H).json(); chk("tamper edit detected", not v["ok"] and v["broken_at"]==3, v["message"])
db.execute("update group_changes set value=(select value from group_changes where id=3) where id=3")
