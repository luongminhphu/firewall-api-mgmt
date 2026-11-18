# Chạy: bash tests/run_e2e.sh tests/review_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# Rà soát quyền VPN định kỳ (ISO 27001 A.5.18): vai trò reviewer (đại diện team) chỉ dùng được rà soát, phạm vi theo team,
# quyết định + lý do, Infra quyết định thay, ảnh chụp không đổi, email mở/nhắc/quá hạn, tự mở theo quý, đóng đợt,
# CSV bằng chứng / cần xử lý, chuỗi băm phát hiện sửa.
import csv
import datetime as dt
import io
import os
import sys

import httpx
import sqlalchemy as sa

sys.path.insert(0, "backend")
from app.auth.oidc import AuthError  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import resolve_sso  # noqa: E402
from app.modules.review import service as rv  # noqa: E402

B = "http://127.0.0.1:8090"
D = "@hsc.com.vn"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
mk.post("/_vpn/reset")
mk.post("/_vpn/rule", params={"name": "HR team testing HRIS - expire 31/12/2026", "action": "remove"})  # hr.test1 → mồ côi
fid = c.post("/api/firewalls", headers=H, json={"name": "FW-VPN", "host": "127.0.0.1", "port": 4460,
                                                "username": "apiadmin", "password": "Sophos@123"}).json()["id"]
c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]})
c.put("/api/notify/contacts", headers=H, json={"contacts": [
    {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn"}, {"team": "KETOAN", "emails": "kt.lead@hsc.com.vn"}]})
c.put("/api/notify/settings", headers=H, json={"infra_emails": "infra@hsc.com.vn"})

# ------------------------------------------------------------ đăng nhập reviewer
with SessionLocal() as db:
    p = resolve_sso(db, {"user": "rms.lead@hsc.com.vn", "name": "RMS Lead", "role": None, "method": "entra-oidc"})
    chk("đại diện team (không là người dùng app, không App Role) → vai trò reviewer", p["role"] == "reviewer")
    try:
        resolve_sso(db, {"user": "la@hsc.com.vn", "name": "Lạ", "role": None, "method": "entra-oidc"})
        chk("người lạ không App Role vẫn bị từ chối", False)
    except AuthError:
        chk("người lạ không App Role vẫn bị từ chối", True)
R = {"X-Auth-Token": issue_token("rms.lead@hsc.com.vn", role="reviewer", method="entra-oidc", name="RMS Lead")}
r = c.get("/api/config", headers=R)
chk("reviewer: /api/config OK", r.status_code == 200 and r.json()["role"] == "reviewer")
blocked = {u: c.get(u, headers=R).status_code for u in
           ("/api/firewalls", "/api/vpn/rules", "/api/vpn/accounts", "/api/audit", "/api/review/campaigns",
            "/api/notify/outbox", "/api/users")}
chk("reviewer: mọi API khác → 403", set(blocked.values()) == {403}, blocked)
chk("reviewer: không chặn được IP", c.post("/api/block", headers=R, json={"values": ["1.2.3.4"]}).status_code == 403)
chk("reviewer: không tải được CSV audit", c.get(f"/api/audit.csv?token={R['X-Auth-Token']}").status_code == 403)
chk("reviewer: chưa có đợt mở", c.get("/api/review/my", headers=R).json()["campaign"] is None)

# ------------------------------------------------------------ mở đợt
chk("viewer không mở được đợt", c.post("/api/review/campaigns", headers=V, json={}).status_code == 403)
r = c.post("/api/review/campaigns", headers=H, json={"name": "Rà soát thử"})
camp = r.json()
chk("admin mở đợt: 7 rule + 1 tài khoản mồ côi", r.status_code == 200 and camp["totals"]["total"] == 8
    and camp["totals"]["pending"] == 8, camp.get("totals"))
scopes = {s["scope"]: s["total"] for s in camp["by_scope"]}
chk("phạm vi: 3 mục RMS RESEARCH, 5 mục Infra", scopes == {"infra": 5, "rms research": 3}, scopes)
chk("không mở được đợt thứ hai khi đợt cũ chưa đóng", c.post("/api/review/campaigns", headers=H, json={}).status_code == 409)
cid = camp["id"]
all_items = c.get(f"/api/review/campaigns/{cid}/items", headers=V).json()["items"]
orphan = [i for i in all_items if i["kind"] == "orphan_account"]
chk("tài khoản mồ côi hr.test1 → Infra", [i["title"] for i in orphan] == [f"hr.test1{D}"] and orphan[0]["scope"] == "infra")

# ------------------------------------------------------------ reviewer quyết định
my = c.get("/api/review/my", headers=R).json()
mine = {i["snapshot"]["user_code"] or i["title"]: i for i in my["items"]}
chk("reviewer chỉ thấy 3 mục của team mình", len(my["items"]) == 3 and {i["scope"] for i in my["items"]} == {"rms research"})
infra_item = next(i for i in all_items if i["scope"] == "infra" and i["kind"] == "rule")
r = c.post(f"/api/review/items/{infra_item['id']}/decision", headers=R, json={"decision": "keep"})
chk("reviewer không quyết định được mục ngoài team", r.status_code == 403)
r = c.post(f"/api/review/items/{mine['CHAU.NB']['id']}/decision", headers=R, json={"decision": "keep"})
chk("reviewer: Còn cần", r.status_code == 200 and r.json()["decision"] == "keep" and r.json()["decided_by"] == "rms.lead@hsc.com.vn")
r = c.post(f"/api/review/items/{mine['NHAN.NDT']['id']}/decision", headers=R, json={"decision": "revoke"})
chk("thu hồi không có lý do → 400", r.status_code == 400)
r = c.post(f"/api/review/items/{mine['NHAN.NDT']['id']}/decision", headers=R,
           json={"decision": "revoke", "comment": "Đã chuyển công tác"})
chk("reviewer: Thu hồi kèm lý do", r.status_code == 200 and r.json()["decision"] == "revoke")
factset = next(i for i in my["items"] if "Factset" in i["title"])
r = c.post(f"/api/review/items/{factset['id']}/decision", headers=H, json={"decision": "change", "comment": "Thu hẹp cổng"})
chk("admin quyết định thay mục của team → on_behalf", r.json()["on_behalf"] is True)
r = c.post(f"/api/review/items/{orphan[0]['id']}/decision", headers=H, json={"decision": "revoke", "comment": "Không còn rule"})
chk("admin quyết định mục Infra → không phải 'thay'", r.json()["on_behalf"] is False)
chk("viewer không quyết định được", c.post(f"/api/review/items/{infra_item['id']}/decision", headers=V,
                                           json={"decision": "keep"}).status_code == 403)

# ảnh chụp không đổi theo đồng bộ sau
mk.post("/_vpn/rule", params={"name": "RMS RESEARCH - CHAU.NB expire 19/10/2027", "dst": "OTHER-SERVER"})
c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid], "kind": "rules"})
snap = next(i for i in c.get("/api/review/my", headers=R).json()["items"] if i["id"] == mine["CHAU.NB"]["id"])["snapshot"]
chk("ảnh chụp lúc mở đợt không đổi khi rule thay đổi", snap["dst_networks"] == ["192.168.82.46"], snap["dst_networks"])

# gỡ khỏi danh sách đại diện → mất quyền ngay
c.put("/api/notify/contacts", headers=H, json={"contacts": [{"team": "KETOAN", "emails": "kt.lead@hsc.com.vn"}]})
chk("gỡ đại diện → token reviewer bị từ chối ngay", c.get("/api/review/my", headers=R).status_code == 401)
c.put("/api/notify/contacts", headers=H, json={"contacts": [
    {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn"}, {"team": "KETOAN", "emails": "kt.lead@hsc.com.vn"}]})

# ------------------------------------------------------------ email mở / nhắc / quá hạn
ob = c.get("/api/notify/outbox?limit=200", headers=H).json()["emails"]
opened = sorted((tuple(m["to"]), m["kind"]) for m in ob if m["kind"] == "review_open")
chk("email mở đợt: đại diện RMS + Infra", opened == [(("infra@hsc.com.vn",), "review_open"),
                                                    (("rms.lead@hsc.com.vn",), "review_open")], opened)
due = dt.date.fromisoformat(camp["due_date"])
rv.tick(today=due - dt.timedelta(days=2))
rv.tick(today=due - dt.timedelta(days=1))
ob = c.get("/api/notify/outbox?limit=200", headers=H).json()["emails"]
rem = [m for m in ob if m["kind"] == "review_remind"]
chk("nhắc hạn: chỉ phạm vi còn mục chưa quyết định (Infra), một lần", len(rem) == 1 and rem[0]["to"] == ["infra@hsc.com.vn"],
    [(m["to"], m["subject"]) for m in rem])
rv.tick(today=due + dt.timedelta(days=1))
rv.tick(today=due + dt.timedelta(days=2))
chk("quá hạn: báo Infra một lần", len([m for m in c.get("/api/notify/outbox?limit=200", headers=H).json()["emails"]
                                      if m["kind"] == "review_overdue"]) == 1)

# ------------------------------------------------------------ đóng đợt + bằng chứng
chk("viewer không đóng được đợt", c.post(f"/api/review/campaigns/{cid}/close", headers=V).status_code == 403)
r = c.post(f"/api/review/campaigns/{cid}/close", headers=H).json()
t = r["totals"]
chk("đóng đợt: mục chưa quyết định → Không phản hồi", r["status"] == "closed" and t["pending"] == 0
    and (t["keep"], t["revoke"], t["change"], t["no_response"]) == (1, 2, 1, 4), t)
chk("không quyết định được sau khi đóng", c.post(f"/api/review/items/{infra_item['id']}/decision", headers=H,
                                                 json={"decision": "keep"}).status_code == 409)
chk("reviewer không còn đợt mở", c.get("/api/review/my", headers=R).json()["campaign"] is None)
tokV = V["X-Auth-Token"]
ev = list(csv.reader(io.StringIO(c.get(f"/api/review/campaigns/{cid}/evidence.csv?token={tokV}").text.lstrip("﻿"))))
chk("CSV bằng chứng: đủ 8 mục + mã băm cho mục đã quyết định", len(ev) == 9 and ev[0][-1] == "ma_bam_nhat_ky"
    and all(len(x[-1]) == 64 for x in ev[1:]), len(ev))
rk = list(csv.reader(io.StringIO(c.get(f"/api/review/campaigns/{cid}/revocations.csv?token={tokV}").text.lstrip("﻿"))))
chk("CSV cần xử lý: thu hồi + điều chỉnh + không phản hồi", len(rk) - 1 == 7 and {x[3] for x in rk[1:]} ==
    {"Thu hồi", "Cần điều chỉnh", "Không phản hồi"})
chk("reviewer không tải được CSV bằng chứng",
    c.get(f"/api/review/campaigns/{cid}/evidence.csv?token={R['X-Auth-Token']}").status_code in (401, 403))
v = c.get("/api/review/verify", headers=V).json()
chk("chuỗi băm quyết định toàn vẹn", v["ok"], v)
eng = sa.create_engine(os.environ["DATABASE_URL"])
with eng.begin() as conn:
    conn.execute(sa.text("UPDATE review_decisions SET comment='sua len' WHERE decision='revoke'"))
v = c.get("/api/review/verify", headers=V).json()
chk("sửa quyết định trong DB → phát hiện", not v["ok"] and v["broken_at"], v)

# ------------------------------------------------------------ tự mở theo quý
q_next = dt.date(due.year + (1 if due.month >= 10 else 0), ((due.month - 1) // 3 * 3 + 3) % 12 + 1, 2)
out1 = rv.tick(today=q_next)
out2 = rv.tick(today=q_next + dt.timedelta(days=1))
key = rv.quarter_key(q_next)[0]
chk("đầu quý → tự mở đợt theo quý, không mở trùng", out1["opened"] == key and out2["opened"] is None, (out1, out2))
camps = c.get("/api/review/campaigns", headers=V).json()["campaigns"]
chk("danh sách đợt: đợt quý mới đang mở", camps[0]["period_key"] == key and camps[0]["status"] == "open")
print("FAILS:", fails)
sys.exit(1 if fails else 0)
