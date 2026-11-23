# Chạy: bash tests/run_e2e.sh tests/vpn_groups_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# Group VPN: tạo group + đại diện + gán user VPN (một user ≤ 1 group); đợt rà soát giao mục theo thành viên group;
# email rà soát (ISO 27001 A.5.18) dạng bản nháp: xem, tải .eml (Outlook mở thành thư nháp), gửi qua SMTP; chỉ admin.
import email
import email.policy
import json
import os
import subprocess
import sys
import tempfile
import time

import httpx

sys.path.insert(0, "backend")
from app.core.db import SessionLocal  # noqa: E402
from app.core.security import issue_token  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


out = tempfile.mktemp(suffix=".jsonl")
smtp_proc = subprocess.Popen([sys.executable, "mock/mock_smtp.py", "--port", "2526", "--out", out])
time.sleep(1)


def mails():
    return [json.loads(x) for x in open(out, encoding="utf-8") if x.strip()] if os.path.exists(out) else []


try:
    H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
    V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
    mk.post("/_vpn/reset")
    mk.post("/_vpn/rule", params={"name": "HR team testing HRIS - expire 31/12/2026", "action": "remove"})  # hr.test1 mồ côi
    fid = c.post("/api/firewalls", headers=H, json={"name": "FW-VPN", "host": "127.0.0.1", "port": 4460,
                                                    "username": "apiadmin", "password": "Sophos@123"}).json()["id"]
    c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]})
    c.put("/api/notify/settings", headers=H, json={"infra_emails": "infra@hsc.com.vn"})

    # ------------------------------------------------------------ gợi ý group từ tên rule
    chk("viewer không xem được gợi ý group", c.get("/api/notify/contacts/suggest", headers=V).status_code == 403)
    sg = {s["team"]: s for s in c.get("/api/notify/contacts/suggest", headers=H).json()["suggestions"]}
    rms = sg.get("RMS RESEARCH", {})
    chk("gợi ý group mới RMS RESEARCH từ tên rule, thành viên = user của các rule đó",
        rms.get("existing") is False and rms.get("users") == ["chau.nb@hsc.com.vn", "nhan.ndt@hsc.com.vn"]
        and len(rms.get("rules", [])) == 3, rms)
    chk("rule không có team (chỉ tên user, vd THAM.NQ) không thành gợi ý group", "THAM.NQ" not in sg, list(sg))
    c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn", "members": ["chau.nb@hsc.com.vn"]}]})
    rms = {s["team"]: s for s in c.get("/api/notify/contacts/suggest", headers=H).json()["suggestions"]}.get("RMS RESEARCH", {})
    chk("group đã có nhưng thiếu user → gợi ý bổ sung đúng user còn thiếu",
        rms.get("existing") is True and rms.get("users") == ["nhan.ndt@hsc.com.vn"], rms)
    c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn", "members": ["chau.nb@hsc.com.vn"]},
        {"team": "KHAC", "emails": "khac@hsc.com.vn", "members": ["nhan.ndt@hsc.com.vn"]}]})
    rms = {s["team"]: s for s in c.get("/api/notify/contacts/suggest", headers=H).json()["suggestions"]}.get("RMS RESEARCH")
    chk("user đã thuộc group khác không gợi ý chuyển; group đủ thành viên thì hết gợi ý", rms is None, rms)
    c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn", "members": ["chau.nb@hsc.com.vn"]},
        {"team": "KHAC", "emails": "khac@hsc.com.vn", "members": ["nhan.ndt@hsc.com.vn", "x@hsc.com.vn"]}]})
    with SessionLocal() as db:
        from app.modules.notify import planner
        taken = next((s for s in planner.suggest_groups(db) if s["team"] == "RMS RESEARCH"), None)
    chk("gợi ý không đổi dữ liệu (chỉ đọc)",
        {x["team"]: x["members"] for x in c.get("/api/notify/settings", headers=H).json()["contacts"]}
        == {"KHAC": ["nhan.ndt@hsc.com.vn", "x@hsc.com.vn"], "RMS RESEARCH": ["chau.nb@hsc.com.vn"]} and taken is None)

    # ------------------------------------------------------------ group + đại diện + thành viên
    IT = ["tham.nq@hsc.com.vn", "HR.TEST1@hsc.com.vn", "ghost@hsc.com.vn"]
    r = c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn", "members": ["chau.nb@hsc.com.vn"]},
        {"team": "IT", "emails": "it.lead@hsc.com.vn", "members": ["tham.nq@hsc.com.vn"]},
        {"team": "KETOAN", "emails": "kt.lead@hsc.com.vn", "members": ["Tham.NQ@hsc.com.vn"]}]})
    chk("một user không nằm ở 2 group → 400", r.status_code == 400 and "2 group" in r.json()["detail"], r.text[:200])
    r = c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "IT", "emails": "it.lead@hsc.com.vn", "members": ["a\nb"]}]})
    chk("tên user có xuống dòng → 400", r.status_code == 400, r.text[:200])
    r = c.put("/api/notify/contacts", headers=V, json={"contacts": []})
    chk("viewer không sửa được group", r.status_code == 403)
    r = c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": "rms.lead@hsc.com.vn"},
        {"team": "IT", "emails": "it.lead@hsc.com.vn", "members": IT + ["tham.nq@hsc.com.vn"], "note": "Phòng IT"},
        {"team": "KETOAN", "emails": "kt.lead@hsc.com.vn", "members": "ketoan1@hsc.com.vn; ketoan2@hsc.com.vn"}]})
    got = {x["team"]: x["members"] for x in r.json().get("contacts", [])}
    chk("lưu group: thành viên giữ nguyên tên, bỏ trùng; nhận cả chuỗi phân cách ;",
        r.status_code == 200 and got.get("IT") == IT and got.get("KETOAN") == ["ketoan1@hsc.com.vn", "ketoan2@hsc.com.vn"]
        and got.get("RMS RESEARCH") == [], got)
    chk("đọc lại cấu hình có thành viên group",
        {x["team"]: x["members"] for x in c.get("/api/notify/settings", headers=H).json()["contacts"]} == got)

    # ------------------------------------------------------------ đợt rà soát giao mục theo group
    camp = c.post("/api/review/campaigns", headers=H, json={"name": "Rà soát quý thử"}).json()
    cid = camp["id"]
    scopes = {s["scope"]: s["total"] for s in camp["by_scope"]}
    items = c.get(f"/api/review/campaigns/{cid}/items", headers=V).json()["items"]
    it_items = sorted((i["kind"], i["title"]) for i in items if i["scope"] == "it")
    chk("rule có user thuộc group IT + tài khoản mồ côi thành viên IT → phạm vi IT",
        ("orphan_account", "hr.test1@hsc.com.vn") in it_items and any(k == "rule" and "THAM.NQ" in t for k, t in it_items),
        it_items)
    chk("RMS RESEARCH vẫn theo team trong tên rule", scopes.get("rms research") == 3, scopes)
    orphan = next(i for i in items if i["kind"] == "orphan_account")
    chk("mục mồ côi ghi tên group", orphan["team"] == "IT", orphan["team"])

    # ------------------------------------------------------------ email rà soát (bản nháp)
    R = {"X-Auth-Token": issue_token("it.lead@hsc.com.vn", role="reviewer", method="entra-oidc", name="IT Lead")}
    chk("viewer / reviewer không xem được bản nháp",
        c.get(f"/api/review/campaigns/{cid}/drafts", headers=V).status_code == 403
        and c.get(f"/api/review/campaigns/{cid}/drafts/it", headers=R).status_code == 403)
    ds = {d["scope"]: d for d in c.get(f"/api/review/campaigns/{cid}/drafts", headers=H).json()["drafts"]}
    chk("danh sách bản nháp theo group: người nhận = đại diện, có Infra và group chưa có mục",
        ds["it"]["to"] == ["it.lead@hsc.com.vn"] and ds["it"]["members"] == 3 and ds["infra"]["to"] == ["infra@hsc.com.vn"]
        and ds.get("ketoan", {}).get("total") == 0, ds)
    d = c.get(f"/api/review/campaigns/{cid}/drafts/IT", headers=H).json()
    body = d["body"]
    chk("bản nháp: gửi đại diện, Cc Infra, tiêu đề nêu ISO 27001 + group + hạn",
        d["to"] == ["it.lead@hsc.com.vn"] and d["cc"] == ["infra@hsc.com.vn"] and "ISO 27001" in d["subject"]
        and "IT" in d["subject"] and camp["due_date"].split("-")[0] in d["subject"], d["subject"])
    chk("nội dung: căn cứ A.5.18, danh sách user, quyền cần xác nhận, 3 lựa chọn, hạn",
        "A.5.18" in body and "tham.nq@hsc.com.vn" in body and "HR.TEST1@hsc.com.vn" in body
        and "Còn cần" in body and "Thu hồi" in body and "Cần điều chỉnh" in body and "THAM.NQ" in body, body[:400])
    chk("thành viên không còn tài khoản trên firewall được chỉ ra",
        "ghost@hsc.com.vn — KHÔNG còn tài khoản trên firewall" in body, body)
    chk("group không có → 404", c.get(f"/api/review/campaigns/{cid}/drafts/khong-co", headers=H).status_code == 404)

    edited = {"to": "it.lead@hsc.com.vn", "cc": ["infra@hsc.com.vn"],
              "subject": "Rà soát VPN\r\nBcc: x@evil.com", "body": body + "\nGhi chú thêm của Infra.\n"}
    r = c.post(f"/api/review/campaigns/{cid}/drafts/it/eml", headers=H, json=edited)
    m = email.message_from_bytes(r.content, policy=email.policy.default) if r.status_code == 200 else None
    chk("tải .eml: thư nháp Outlook (X-Unsent), người nhận đã lọc, nội dung đã sửa, không chèn được header",
        m is not None and m["X-Unsent"] == "1" and m["To"] == "it.lead@hsc.com.vn" and m["Cc"] == "infra@hsc.com.vn"
        and m["Bcc"] is None and "Ghi chú thêm của Infra." in m.get_content()
        and "attachment" in r.headers.get("content-disposition", ""), r.text[:200])
    r = c.post(f"/api/review/campaigns/{cid}/drafts/it/eml", headers=H, json={**edited, "to": "khong-hop-le"})
    chk("người nhận sai định dạng → 400 nêu rõ địa chỉ", r.status_code == 400 and "khong-hop-le" in r.json()["detail"])
    r = c.post(f"/api/review/campaigns/{cid}/drafts/it/eml", headers=H, json={**edited, "to": ""})
    chk("không có người nhận → 400", r.status_code == 400)

    r = c.post(f"/api/review/campaigns/{cid}/drafts/it/send", headers=H, json=edited)
    chk("chưa cấu hình SMTP → báo lỗi rõ", r.status_code == 400 and "SMTP" in r.json()["detail"], r.text[:200])
    c.put("/api/settings/smtp", headers=H, json={"enabled": True, "host": "127.0.0.1", "port": 2526, "security": "none",
                                                  "from_addr": "soc-rapid-block@hsc.com.vn", "from_name": "SOC Rapid Block"})
    r = c.post(f"/api/review/campaigns/{cid}/drafts/it/send", headers=H, json=edited)
    time.sleep(0.5)
    sent = mails()
    msg = email.message_from_string(sent[-1]["data"], policy=email.policy.default) if sent else None
    chk("gửi qua SMTP: tới đại diện + Cc Infra, đúng nội dung đã sửa",
        r.status_code == 200 and msg is not None and sorted(sent[-1]["to"]) == ["infra@hsc.com.vn", "it.lead@hsc.com.vn"]
        and "Ghi chú thêm của Infra." in msg.get_body(preferencelist=("plain",)).get_content(), r.text[:200])
    acts = [a for a in c.get("/api/audit", headers=H, params={"limit": 50}).json()["rows"]
            if a["action"] == "review" and "email rà soát" in a["message"]]
    ds = {d["scope"]: d for d in c.get(f"/api/review/campaigns/{cid}/drafts", headers=H).json()["drafts"]}
    sent = ds["it"].get("sent") or {}
    chk("bảng email ghi lần gửi gần nhất (SMTP, người gửi, số lần = .eml + SMTP); group chưa gửi → null",
        sent.get("method") == "SMTP" and sent.get("by") == "phu.luong@hsc.com.vn" and sent.get("count") == 2
        and "it.lead@hsc.com.vn" in sent.get("detail", "") and ds["infra"].get("sent") is None, ds["it"])
    chk("bản nháp mở lại cho biết đã gửi", (c.get(f"/api/review/campaigns/{cid}/drafts/it", headers=H).json()
                                           .get("sent") or {}).get("method") == "SMTP")
    v = c.get("/api/review/verify", headers=V).json()
    chk("lần gửi nằm trong nhật ký rà soát nối chuỗi băm, chuỗi vẫn toàn vẹn", v["ok"], v)
    chk("audit ghi lần gửi email rà soát (cả lần lỗi)", len(acts) >= 2 and {a["result"] for a in acts} == {"ok", "error"},
        [(a["result"], a["message"][:60]) for a in acts])
finally:
    smtp_proc.terminate()

print("FAILS:", fails)
sys.exit(1 if fails else 0)
