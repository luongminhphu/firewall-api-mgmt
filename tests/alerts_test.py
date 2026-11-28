# Chạy: bash tests/run_e2e.sh tests/alerts_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# F1 — job fw-health: firewall mất kết nối ≥ ngưỡng → đúng 1 email fw_down; hồi phục → đúng 1 email fw_up;
# F2 — drift gần thời gian thực (probe → quét lite), email drift CHỈ ngoài giờ hành chính, con trỏ luôn tiến, lệnh chặn
# chen giữa lượt quét không sinh drift giả; audit fw_health chỉ khi đổi trạng thái; auth_error giãn 60 phút; outbox.deliver có khóa (không gửi trùng).
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import httpx

sys.path.insert(0, "backend")
from app.core import jobs  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.core.models import AppSetting, AuditLog, EmailOutbox, Firewall, GroupChange  # noqa: E402
from app.integrations.sophos import SophosClient  # noqa: E402
from app.modules.ipblock import changelog, group_cache  # noqa: E402
from app.modules.notify import health, outbox  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


def n_mail(kind, fid):
    with SessionLocal() as db:
        return sum(1 for m in db.query(EmailOutbox).filter(EmailOutbox.kind == kind)
                   if json.loads(m.ref_json).get("firewall_id") == fid)


def n_audit(fid):
    with SessionLocal() as db:
        return db.query(AuditLog).filter(AuditLog.action == "fw_health", AuditLog.firewall_id == fid).count()


def last_checked(fid):
    with SessionLocal() as db:
        return db.get(Firewall, fid).last_checked


def state(fid):
    with SessionLocal() as db:
        return health.load_state(db).get("fw", {}).get(str(fid))


H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
base = {"username": "apiadmin", "password": "Sophos@123"}


def mkfw(name, port, **kw):
    return c.post("/api/firewalls", headers=H, json={"name": name, "host": "127.0.0.1", "port": port, **{**base, **kw}}).json()["id"]


fa, fb = mkfw("FW-A", 4460), mkfw("FW-B", 9)
fc = mkfw("FW-C", 4460, password="sai-mat-khau")

# cấu hình: cảnh báo F1 không phụ thuộc công tắc nhắc hạn VPN (enabled giữ false)
r = c.put("/api/notify/settings", headers=H, json={"fw_down_minutes": 2})
chk("ngưỡng < 5 phút → 400", r.status_code == 400, r.text)
r = c.put("/api/notify/settings", headers=H, json={"fw_down_minutes": "x"})
chk("ngưỡng không phải số → 422/400", r.status_code in (400, 422), r.text)
r = c.put("/api/notify/settings", headers=H, json={"infra_emails": "infra@hsc.com.vn", "fw_down_minutes": 15})
j = r.json()
chk("lưu cấu hình F1; enabled vẫn tắt", r.status_code == 200 and j["alert_fw_down"] is True
    and j["fw_down_minutes"] == 15 and j["alert_drift"] is True and j["enabled"] is False, j)

T0 = dt.datetime.now(dt.timezone.utc)
health.probe_all(T0)
chk("B lỗi, C auth_error, A ok", state(fa)["status"] == "ok" and state(fb)["status"] == "error"
    and state(fc)["status"] == "auth_error", (state(fa), state(fb), state(fc)))
chk("chưa đủ ngưỡng → 0 email", n_mail("fw_down", fb) == 0 and n_mail("fw_down", fc) == 0)
chk("audit fw_health: B 1 dòng (lần đầu lỗi), C 1 dòng, A 0 dòng (ok lần đầu không ghi)",
    (n_audit(fb), n_audit(fc), n_audit(fa)) == (1, 1, 0))
nc = state(fc)["next_probe_at"]
chk("auth_error → next_probe_at ≈ +60 phút", nc and abs((dt.datetime.fromisoformat(nc) - T0).total_seconds() - 3600) < 5, nc)

lc = last_checked(fc)
mk.post("/_reset_stats")
health.probe_all(T0 + dt.timedelta(minutes=20))
chk("C không bị probe lại trong 60 phút (last_checked không đổi)", last_checked(fc) == lc)
chk("quá ngưỡng 20 phút → đúng 1 email fw_down cho B", n_mail("fw_down", fb) == 1)
health.probe_all(T0 + dt.timedelta(minutes=21))
health.probe_all(T0 + dt.timedelta(minutes=22))
chk("chạy thêm nhiều lần vẫn 1 email; audit B vẫn 1 dòng", n_mail("fw_down", fb) == 1 and n_audit(fb) == 1)
with SessionLocal() as db:
    m = db.query(EmailOutbox).filter(EmailOutbox.kind == "fw_down").first()
    chk("email: đúng người nhận, nêu tên firewall, không lộ mật khẩu",
        m.to_addrs == "infra@hsc.com.vn" and "FW-B" in m.subject and "Sophos@123" not in m.body
        and "sai-mat-khau" not in m.body, m.subject)

chk("C đang giãn chu kỳ vẫn xét ngưỡng → 1 email fw_down đúng hạn (không chờ hết 60 phút)", n_mail("fw_down", fc) == 1)
health.probe_all(T0 + dt.timedelta(minutes=61))
chk("C hết giãn → probe lại, vẫn 1 email fw_down, audit 1 dòng", n_mail("fw_down", fc) == 1 and n_audit(fc) == 1)
c.put(f"/api/firewalls/{fc}", headers=H, json={"password": "Sophos@123"})  # admin sửa mật khẩu khi đang giãn chu kỳ
health.probe_all(T0 + dt.timedelta(minutes=63))
chk("sửa mật khẩu → probe ngay (không chờ hết giãn), hồi phục → 1 email fw_up",
    state(fc)["status"] == "ok" and n_mail("fw_up", fc) == 1, state(fc))
chk("A không có email / audit", n_mail("fw_down", fa) == 0 and n_mail("fw_up", fa) == 0 and n_audit(fa) == 0)

# hồi phục
c.put(f"/api/firewalls/{fb}", headers=H, json={"port": 4460})
health.probe_all(T0 + dt.timedelta(minutes=62))
chk("B trỏ lại mock → 1 email fw_up, audit thêm 1 dòng", n_mail("fw_up", fb) == 1 and n_audit(fb) == 2
    and state(fb)["down_since"] is None and not state(fb)["alerted"], state(fb))
health.probe_all(T0 + dt.timedelta(minutes=63))
chk("probe tiếp → không thêm email / audit", n_mail("fw_up", fb) == 1 and n_audit(fb) == 2)

# alert_fw_down tắt → không email; hồi phục khi chưa gửi email lỗi → không email fw_up
fd = mkfw("FW-D", 9)
c.put("/api/notify/settings", headers=H, json={"alert_fw_down": False})
T1 = T0 + dt.timedelta(minutes=70)
health.probe_all(T1)
health.probe_all(T1 + dt.timedelta(minutes=30))
chk("alert_fw_down=false → không email fw_down", n_mail("fw_down", fd) == 0)
c.put(f"/api/firewalls/{fd}", headers=H, json={"port": 4460})
health.probe_all(T1 + dt.timedelta(minutes=31))
chk("hồi phục khi chưa từng gửi email lỗi → không email fw_up", n_mail("fw_up", fd) == 0)

# firewall tắt → xoá state
c.put(f"/api/firewalls/{fd}", headers=H, json={"enabled": False})
health.probe_all(T1 + dt.timedelta(minutes=32))
chk("firewall tắt → xoá state", state(fd) is None)

# ---- F2: drift
def ext_add(name, ip):
    """Giả lập admin sửa WebAdmin: thêm IP Host + đưa vào SCANPORT GROUP, không qua app."""
    fc_ = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123", verify_ssl=False, timeout=10)
    fc_.add_ip_host(name, "IP", ip, "them tay tren WebAdmin")
    g = fc_.get_group("SCANPORT GROUP")
    fc_.set_group_hosts("SCANPORT GROUP", list(g["hosts"]) + [name], g["description"], g["ip_family"])


def max_id():
    with SessionLocal() as db:
        return db.query(GroupChange.id).order_by(GroupChange.id.desc()).limit(1).scalar() or 0


def drifts(after, fid=None):
    with SessionLocal() as db:
        q = db.query(GroupChange).filter(GroupChange.id > after, GroupChange.change_type.in_(("drift_add", "drift_remove")))
        if fid:
            q = q.filter(GroupChange.firewall_id == fid)
        return [(r.change_type, r.object_name, r.value) for r in q.order_by(GroupChange.id)]


def set_ts(after, fid, vn):
    """Đặt thời điểm drift (giờ VN) — chỉ dùng trong test để điều khiển 'ngoài giờ / trong giờ'."""
    with SessionLocal() as db:
        for r in db.query(GroupChange).filter(GroupChange.id > after, GroupChange.firewall_id == fid,
                                              GroupChange.change_type.like("drift_%")):
            r.ts = vn.astimezone(dt.timezone.utc)
        db.commit()


def drift_mails(fid):
    with SessionLocal() as db:
        return [m for m in db.query(EmailOutbox).filter(EmailOutbox.kind == "drift").order_by(EmailOutbox.id)
                if json.loads(m.ref_json).get("firewall_id") == fid]


def cursor():
    with SessionLocal() as db:
        row = db.get(AppSetting, "alerts.drift")
        return json.loads(row.value)["cursor"] if row else None


VNTZ = dt.timezone(dt.timedelta(hours=7))
SAT = dt.datetime(2025, 11, 22, 10, 0, tzinfo=VNTZ)  # thứ 7 trong quá khứ (ts tương lai sẽ làm scan coi là "bị chen")
TUE = dt.datetime(2025, 11, 18, 10, 0, tzinfo=VNTZ)  # thứ 3 10:00, giờ hành chính
with SessionLocal() as db:
    group_cache.scan(db, db.get(Firewall, fa), mode="full")  # baseline
with SessionLocal() as db:  # job notify của app đã đặt con trỏ lúc khởi động → xoá để mô phỏng "lần đầu"
    db.query(AppSetting).filter(AppSetting.key == "alerts.drift").delete()
    db.commit()
m0 = max_id()
ext_add("EXT_OLD", "198.51.100.9")
health.probe_all()
chk("probe phát hiện sửa WebAdmin ngay trong cùng lượt → drift_add", any(d[0] == "drift_add" and d[1] == "EXT_OLD" for d in drifts(m0, fa)), drifts(m0, fa))
chk("chưa có con trỏ", cursor() is None)
outbox.run_cycle()
chk("lần đầu (chưa có con trỏ) với drift cũ → không email, con trỏ = max id", not drift_mails(fa) and cursor() == max_id(), cursor())

m1 = max_id()
ext_add("EXT_SAT", "198.51.100.2")
health.probe_all()
set_ts(m1, fa, SAT)
outbox.run_cycle()
ml = drift_mails(fa)
chk("drift lúc thứ 7 → đúng 1 email drift có IP + lý do", len(ml) == 1 and "198.51.100.2" in ml[0].body
    and "Cuối tuần" in ml[0].body and ml[0].to_addrs == "infra@hsc.com.vn" and "198.51.100.9" not in ml[0].body, ml and ml[0].body)
outbox.run_cycle()
chk("run_cycle lần 2 → vẫn 1 email", len(drift_mails(fa)) == 1)

m2 = max_id()
ext_add("EXT_TUE", "198.51.100.3")
health.probe_all()
set_ts(m2, fa, TUE)
outbox.run_cycle()
r = c.get("/api/changes?type=drift", headers=H).json()
vals = [a["value"] for b in r["batches"] for a in b["added"]]
chk("drift thứ 3 10:00 → không email, nhưng có trong Lịch sử", len(drift_mails(fa)) == 1 and "198.51.100.3" in vals, vals)

m3 = max_id()
c.put("/api/notify/settings", headers=H, json={"alert_drift": False})
ext_add("EXT_OFF", "198.51.100.4")
health.probe_all()
set_ts(m3, fa, SAT)
outbox.run_cycle()
chk("alert_drift tắt → không email, con trỏ vẫn tiến", len(drift_mails(fa)) == 1 and cursor() == max_id(), cursor())
c.put("/api/notify/settings", headers=H, json={"alert_drift": True})
outbox.run_cycle()
chk("bật lại → drift cũ không được gửi", len(drift_mails(fa)) == 1)

# D1c: lệnh chặn ghi nhật ký giữa lúc scan đọc firewall → không drift giả, dirty=True, lượt sau mới so
m4 = max_id()
ext_add("EXT_RACE", "198.51.100.5")
orig = group_cache._scan_members


def racing(cli, group, mode, known, hints):
    res = orig(cli, group, mode, known, hints)
    with SessionLocal() as d2:  # lệnh chặn của app ghi sau lúc scan bắt đầu đọc
        changelog.record(d2, fw=d2.get(Firewall, fa), group=group, change_type="add", items=[("RACE_X", "198.51.100.77")],
                         count_before=1, count_after=2, who={"user": "soc", "name": "SOC", "method": "test"})
    return res


group_cache._scan_members = racing
try:
    with SessionLocal() as db:
        row = group_cache.scan(db, db.get(Firewall, fa), mode="lite")
        dirty = row.dirty
finally:
    group_cache._scan_members = orig
chk("lệnh chặn chen giữa lượt quét → không drift giả, row.dirty True", not drifts(m4, fa) and dirty is True, drifts(m4, fa))
with SessionLocal() as db:
    row = group_cache.scan(db, db.get(Firewall, fa), mode="lite")
    dirty = row.dirty
chk("lượt sau (không chen) so lại → thấy drift thật, dirty False", any(d[1] == "EXT_RACE" for d in drifts(m4, fa)) and dirty is False, drifts(m4, fa))

# C-14: lệnh chặn đã commit nhật ký (ts < t_start của scan) nhưng chưa lưu snapshot → còn giữ fw-write → scan không so
m5 = max_id()
ext_add("EXT_GAP", "198.51.100.6")  # firewall khác snapshot, như sau khi lệnh chặn ghi firewall
with SessionLocal() as db:
    changelog.record(db, fw=db.get(Firewall, fa), group="SCANPORT GROUP", change_type="remove",
                     items=[("GAP_X", "198.51.100.88")], count_before=2, count_after=1,
                     who={"user": "soc", "name": "SOC", "method": "test"})
with jobs.lock(f"fw-write:{fa}") as held:
    with SessionLocal() as db:
        row = group_cache.scan(db, db.get(Firewall, fa), mode="full")
        dirty = row.dirty
chk("lệnh chặn đang giữ fw-write (đã ghi nhật ký, chưa snapshot) → không drift giả, dirty True",
    held and not drifts(m5, fa) and dirty is True, drifts(m5, fa))
with SessionLocal() as db:  # lệnh chặn hoàn tất: lưu snapshot như service làm
    members = {m["object"]: m["value"] for m in group_cache.data(group_cache.get_row(db, fa))["members"]}
    changelog.save_snapshot(db, fa, "SCANPORT GROUP", members)
    db.commit()
with SessionLocal() as db:
    row = group_cache.scan(db, db.get(Firewall, fa), mode="full")
    dirty = row.dirty
chk("sau khi lệnh chặn nhả khoá + snapshot → không drift giả, dirty False", not drifts(m5, fa) and dirty is False, drifts(m5, fa))

# C-15: raced (dirty) rồi có sửa WebAdmin thật → probe quét dù tên thành viên cache == firewall
m6 = max_id()
ext_add("EXT_REAL", "198.51.100.7")
with jobs.lock(f"fw-write:{fa}"):
    with SessionLocal() as db:
        dirty = group_cache.scan(db, db.get(Firewall, fa), mode="lite").dirty
chk("raced → cache đã có EXT_REAL, chưa drift, dirty True", dirty is True and not drifts(m6, fa), drifts(m6, fa))
health.probe_all()
with SessionLocal() as db:
    dirty = group_cache.get_row(db, fa).dirty
chk("probe khi dirty (tên cache == firewall) → ghi drift_add thật, dirty False",
    any(d[0] == "drift_add" and d[1] == "EXT_REAL" for d in drifts(m6, fa)) and dirty is False, drifts(m6, fa))

# ---- deliver có khóa
out = tempfile.mktemp(suffix=".jsonl")
smtp_proc = subprocess.Popen([sys.executable, "mock/mock_smtp.py", "--port", "2525", "--out", out])
time.sleep(1)
try:
    r = c.put("/api/settings/smtp", headers=H, json={
        "enabled": True, "host": "127.0.0.1", "port": 2525, "security": "none", "username": "u", "password": "p",
        "from_addr": "soc@hsc.com.vn", "from_name": "SOC"})
    with SessionLocal() as db:
        pend = db.query(EmailOutbox).filter(EmailOutbox.status == "pending").count()
    with jobs.lock("outbox-deliver", blocking=False) as got:
        with SessionLocal() as db:
            busy = outbox.deliver(db)
    chk("đang có tiến trình khác gửi → không gửi, báo pending", got and busy["sent"] == 0 and busy["pending"] == pend
        and "khác" in busy.get("note", ""), busy)
    res = []

    def run():
        with SessionLocal() as db:
            res.append(outbox.deliver(db))

    ts = [threading.Thread(target=run) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    sent = [json.loads(x) for x in open(out, encoding="utf-8") if x.strip()] if os.path.exists(out) else []
    chk("deliver hai luồng song song → mỗi thư gửi đúng 1 lần", pend >= 3 and len(sent) == pend
        and sum(x["sent"] for x in res) == pend, (pend, len(sent), res))
finally:
    smtp_proc.terminate()

# Nút Đồng bộ (Lịch sử thay đổi) khi lệnh chặn / bỏ chặn đang giữ khoá fw-write → không so drift (Gate 2 vòng 2, F1).
# Khoá liên tiến trình chỉ có trên PostgreSQL (pg_advisory_lock); SQLite chỉ khoá trong một tiến trình.
from app.core.db import engine as _eng  # noqa: E402
if _eng.dialect.name == "postgresql":
    with jobs.lock(f"fw-write:{fa}"):
        r = c.post("/api/changes/sync", json={"firewall_ids": [fa]}, headers=H).json()["results"][0]
    chk("Đồng bộ khi đang có lệnh chặn → từ chối, không so drift", r["ok"] is False and "thử lại" in r["error"], r)
    r = c.post("/api/changes/sync", json={"firewall_ids": [fa]}, headers=H).json()["results"][0]
    chk("Đồng bộ khi không có lệnh chặn → chạy bình thường", r["ok"] is True, r)
else:
    print("SKIP Đồng bộ khi đang có lệnh chặn (cần PostgreSQL)")

print("FAILS:", fails)
sys.exit(1 if fails else 0)
