# Chạy: bash tests/run_e2e.sh tests/notify_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# Phase 5 — thông báo email: cấu hình SMTP trên giao diện (mật khẩu mã hóa, không lộ), gửi thử, kế hoạch nhắc hạn VPN
# theo mốc (idempotent qua dedupe_key), người nhận = đại diện team + Infra, retry khi lỗi, chỉ quản trị viên.
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import time

import httpx
import sqlalchemy as sa

sys.path.insert(0, "backend")
from app.modules.notify.planner import bucket, plan  # noqa: E402

B = "http://127.0.0.1:8090"
D = "@hsc.com.vn"
SMTP_PW = "Mat-khau-SMTP#2026"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# ------------------------------------------------------------ hàm thuần
R = [30, 14, 7, 1]
chk("mốc nhắc: còn 20 ngày → mốc 30", bucket(20, R) == 30)
chk("mốc nhắc: còn 10 → 14, còn 7 → 7, còn 0 → 1", (bucket(10, R), bucket(7, R), bucket(0, R)) == (14, 7, 1))
chk("mốc nhắc: còn 40 ngày → chưa nhắc; quá hạn → không thuộc nhắc trước hạn", bucket(40, R) is None and bucket(-1, R) is None)
rule = {"firewall_id": 1, "firewall": "FW", "rule_name": "RMS RESEARCH - CHAU.NB expire 19/10/2027", "group_name": "VPN",
        "team": "RMS RESEARCH", "user_code": "CHAU.NB", "accounts": [{"username": "chau.nb@x"}], "identities": [],
        "expiry_date": "2026-12-01", "expiry_source": "name", "dst_zones": ["LAN"], "dst_networks": [], "services": [],
        "days_left": 13, "flags": ["expiring"]}
cfg = {"infra_emails": ["infra@x.vn"], "reminder_days": R, "expired_weekly": True}
m = plan([rule], cfg, {"rms research": ["lead@x.vn"]}, dt.date(2026, 11, 18))
chk("kế hoạch: đại diện team + Infra, khóa chống trùng theo mốc", len(m) == 1 and m[0]["to"] == ["infra@x.vn", "lead@x.vn"]
    and m[0]["dedupe_key"].endswith(":2026-12-01:14"), m)
chk("kế hoạch: tiêu đề nêu số ngày", "sau 13 ngày" in m[0]["subject"])
exp = {**rule, "days_left": -5, "flags": ["expired_enabled"], "expiry_date": "2026-11-13"}
m = plan([exp], cfg, {"rms research": ["lead@x.vn"]}, dt.date(2026, 11, 18))
chk("hết hạn còn bật: chỉ Infra, khóa theo tuần ISO", len(m) == 1 and m[0]["to"] == ["infra@x.vn"]
    and m[0]["dedupe_key"].endswith(":2026-W47"), m and m[0]["dedupe_key"])
chk("không có người nhận → không xếp hàng", plan([rule], {**cfg, "infra_emails": []}, {}, dt.date(2026, 11, 18)) == [])

# ------------------------------------------------------------ SMTP giả lập
out = tempfile.mktemp(suffix=".jsonl")
smtp_proc = subprocess.Popen([sys.executable, "mock/mock_smtp.py", "--port", "2525", "--out", out])
time.sleep(1)


def mails():
    if not os.path.exists(out):
        return []
    return [json.loads(x) for x in open(out, encoding="utf-8") if x.strip()]


try:
    H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
    V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
    chk("viewer không xem/sửa được SMTP", c.get("/api/settings/smtp", headers=V).status_code == 403
        and c.put("/api/settings/smtp", headers=V, json={"host": "x"}).status_code == 403)
    r = c.put("/api/settings/smtp", headers=H, json={"enabled": True, "host": "127.0.0.1"})
    chk("bật gửi khi thiếu địa chỉ gửi → 400", r.status_code == 400, r.text)
    r = c.put("/api/settings/smtp", headers=H, json={"from_name": "SOC\r\nBcc: x@evil.com"})
    chk("chặn header injection ở tên người gửi", r.status_code == 400)
    r = c.put("/api/settings/smtp", headers=H, json={"from_addr": "khong-phai-email"})
    chk("địa chỉ gửi sai dạng → 400", r.status_code == 400)
    r = c.put("/api/settings/smtp", headers=H, json={
        "enabled": True, "host": "127.0.0.1", "port": 2525, "security": "none", "username": "smtpuser",
        "password": SMTP_PW, "from_addr": "soc-rapid-block@hsc.com.vn", "from_name": "SOC Rapid Block"})
    s = r.json()
    chk("lưu SMTP; API không trả mật khẩu", r.status_code == 200 and s["has_password"] and "password" not in s
        and "password_enc" not in s and SMTP_PW not in r.text, s)
    r = c.put("/api/settings/smtp", headers=H, json={"port": 2525})
    chk("lưu lại không nhập mật khẩu → giữ mật khẩu cũ", r.json()["has_password"])
    eng = sa.create_engine(os.environ["DATABASE_URL"])
    with eng.connect() as conn:
        raw = conn.execute(sa.text("SELECT value FROM app_settings WHERE key='smtp.settings'")).scalar()
    chk("DB lưu mật khẩu SMTP đã mã hóa", SMTP_PW not in raw and '"password_enc": "v1:' in raw)

    r = c.post("/api/settings/smtp/test", headers=H, json={"to": "phu.luong@hsc.com.vn"})
    chk("gửi thử thành công", r.status_code == 200 and r.json()["ok"], r.text)
    ms = mails()
    chk("thư thử tới đúng người, đăng nhập SMTP bằng tài khoản đã lưu", len(ms) == 1 and ms[0]["to"] == [f"phu.luong{D}"]
        and ms[0]["user"] == "smtpuser" and "Auto-Submitted: auto-generated" in ms[0]["data"], ms[-1:] and ms[-1]["to"])
    c.put("/api/settings/smtp", headers=H, json={"password": "sai"})
    r = c.post("/api/settings/smtp/test", headers=H, json={"to": "phu.luong@hsc.com.vn"})
    chk("sai mật khẩu SMTP → 400 có lý do", r.status_code == 400 and "Sai tài khoản SMTP" in r.json()["detail"], r.text)
    c.put("/api/settings/smtp", headers=H, json={"password": SMTP_PW})

    # ------------------------------------------------------------ cấu hình thông báo
    r = c.put("/api/notify/settings", headers=H, json={"enabled": True})
    chk("bật thông báo khi chưa có email Infra → 400", r.status_code == 400)
    r = c.put("/api/notify/settings", headers=H, json={"enabled": True, "infra_emails": "infra@hsc.com.vn; noc@hsc.com.vn",
                                                       "reminder_days": [7, 30, 14, 1]})
    chk("lưu cấu hình thông báo (mốc sắp xếp giảm dần)", r.json()["reminder_days"] == [30, 14, 7, 1]
        and r.json()["infra_emails"] == ["infra@hsc.com.vn", "noc@hsc.com.vn"], r.json())
    r = c.put("/api/notify/contacts", headers=H, json={"contacts": [{"team": "RMS RESEARCH", "emails": "x@"}]})
    chk("email đại diện sai dạng → 400", r.status_code == 400)
    r = c.put("/api/notify/contacts", headers=H, json={"contacts": [
        {"team": "RMS RESEARCH", "emails": ["rms.lead@hsc.com.vn"]}, {"team": "HR team testing HRIS", "emails": "hr.lead@hsc.com.vn"}]})
    chk("lưu đại diện team (nhập tay)", [x["team"] for x in r.json()["contacts"]] == ["HR team testing HRIS", "RMS RESEARCH"])

    # ------------------------------------------------------------ dữ liệu VPN: tạo hạn tương đối theo hôm nay
    mk.post("/_vpn/reset")
    fid = c.post("/api/firewalls", headers=H, json={"name": "FW-VPN", "host": "127.0.0.1", "port": 4460,
                                                    "username": "apiadmin", "password": "Sophos@123"}).json()["id"]
    today = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=7)).date()
    d10, d5 = today + dt.timedelta(days=10), today + dt.timedelta(days=5)
    mk.post("/_vpn/rule", params={"name": "THAM.NQ expire 23/04/2027", "schedule_end": f"{d10} 23:59:00"})
    mk.post("/_vpn/rule", params={"name": "RMS RESEARCH - NHAN.NDT 30/06/2027",
                                  "new_name": f"RMS RESEARCH - NHAN.NDT {d5:%d/%m/%Y}"})
    c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid]})
    before = len(mails())
    r = c.post("/api/notify/run", headers=H).json()
    # THAM (10 ngày, mốc 14, chỉ Infra vì không có team) + NHAN (5 ngày, mốc 7, RMS + Infra)
    # + OLD.USER (hết hạn còn bật → Infra) = 3 thư
    chk("chạy ngay: xếp hàng + gửi 3 thư", r["queued"] == 3 and r["sent"] == 3, r)
    new = mails()[before:]
    import email  # noqa: E402
    from email import policy  # noqa: E402

    # tiêu đề tiếng Việt được mã hóa RFC 2047 → giải mã đúng chuẩn
    by = {str(email.message_from_string(m["data"], policy=policy.default)["Subject"]): m for m in new}
    nhan = next((m for s_, m in by.items() if "NHAN.NDT" in s_), None)
    chk("nhắc NHAN.NDT tới đại diện RMS RESEARCH + Infra", nhan and sorted(nhan["to"]) ==
        ["infra@hsc.com.vn", "noc@hsc.com.vn", "rms.lead@hsc.com.vn"], nhan and nhan["to"])
    old = next((m for s_, m in by.items() if "OLD.USER" in s_), None)
    chk("hết hạn còn bật OLD.USER chỉ tới Infra", old and sorted(old["to"]) == ["infra@hsc.com.vn", "noc@hsc.com.vn"])
    chk("nội dung không lộ bí mật firewall / mật khẩu SMTP",
        all("MOCK-SECRET" not in m["data"] and SMTP_PW not in m["data"] for m in new))
    r = c.post("/api/notify/run", headers=H).json()
    chk("chạy lại → không gửi trùng (idempotent)", r["queued"] == 0 and r["sent"] == 0 and len(mails()) == before + 3, r)
    mk.post("/_vpn/rule", params={"name": "THAM.NQ expire 23/04/2027", "schedule_end": f"{today + dt.timedelta(days=3)} 23:59:00"})
    c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid], "kind": "rules"})
    r = c.post("/api/notify/run", headers=H).json()
    chk("đổi hạn → nhắc theo hạn/mốc mới (1 thư)", r["queued"] == 1 and r["sent"] == 1, r)

    # ------------------------------------------------------------ lỗi gửi → thử lại; SMTP tắt → nằm chờ
    c.put("/api/settings/smtp", headers=H, json={"port": 2599})
    mk.post("/_vpn/rule", params={"name": "THAM.NQ expire 23/04/2027", "schedule_end": f"{today} 23:59:00"})
    c.post("/api/vpn/sync", headers=H, json={"firewall_ids": [fid], "kind": "rules"})
    r = c.post("/api/notify/run", headers=H).json()
    chk("SMTP không kết nối được → thư chuyển sang thử lại", r["queued"] == 1 and r["retry"] == 1 and r["pending"] == 1, r)
    e = c.get("/api/notify/outbox?status=pending", headers=H).json()["emails"][0]
    chk("hàng đợi ghi lỗi + lần thử + giờ thử lại", e["attempts"] == 1 and "Không kết nối được" in e["last_error"]
        and e["next_attempt_at"] > dt.datetime.now(dt.timezone.utc).isoformat(), e)
    r = c.post("/api/notify/run", headers=H).json()
    chk("chưa tới giờ thử lại → không gửi lại ngay", r["retry"] == 0 and r["sent"] == 0)
    c.put("/api/settings/smtp", headers=H, json={"enabled": False, "port": 2525})
    r = c.post("/api/notify/run", headers=H).json()
    chk("SMTP tắt → thư nằm chờ, không tính lỗi", r["pending"] == 1 and "nằm chờ" in r.get("note", ""), r)
    chk("viewer không xem được hàng đợi", c.get("/api/notify/outbox", headers=V).status_code == 403)
    sent = c.get("/api/notify/outbox?status=sent", headers=H).json()["emails"]
    chk("hàng đợi: 4 thư đã gửi", len(sent) == 4)
    acts = {(a["action"], a["target"]) for a in c.get("/api/audit?limit=500", headers=H).json()["rows"]}
    chk("audit: cấu hình SMTP, gửi thử, người nhận, chạy thông báo", {("settings_cud", "smtp"), ("smtp_test", f"phu.luong{D}"),
        ("settings_cud", "team_contacts"), ("notify_run", "vpn")} <= acts)
    time.sleep(0.3)
    chk("log app không chứa mật khẩu SMTP", SMTP_PW not in open("/tmp/app_t.log", encoding="utf-8").read())
finally:
    smtp_proc.terminate()

print("FAILS:", fails)
sys.exit(1 if fails else 0)
