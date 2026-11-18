# Chạy: bash tests/run_e2e.sh tests/autoblock_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# v2.2 — tự động chặn IP từ group chat Teams: cú pháp "ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>" (IN HOA, khớp chính xác),
# chỉ tài khoản SOC, bỏ qua tin đã sửa, khung giờ, ngưỡng N IP/giờ (ngắt → chờ duyệt + cảnh báo Admin),
# công tắc khẩn cấp, duyệt / từ chối / gỡ chặn, chu kỳ đọc chỉnh trên giao diện, chuỗi băm.
import datetime as dt
import os
import json
import re
import sys
import time
import unicodedata

import httpx

sys.path.insert(0, "backend")
from app.core.security import issue_token  # noqa: E402
from app.modules.autoblock import parser  # noqa: E402
from app.modules.autoblock import settings as abs_  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=60)
g = httpx.Client(base_url="http://127.0.0.1:4470", timeout=10)
SOC_ID = "11111111-2222-3333-4444-555555555555"
SOC2_ID = "11111111-2222-3333-4444-666666666666"
OTHER_ID = "99999999-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT = "12345678-1234-1234-1234-123456789abc"
CHAT = "19:mockchat@thread.v2"
CMD = parser.PREFIX
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")


def group_hosts():
    st = json.load(open("/tmp/mock_t.json"))
    return st["groups"]["SCANPORT GROUP"]["HostList"]


def post(html, sender=SOC_ID, name="SOC Ca đêm", **kw):
    return g.post("/_post", json={"sender_id": sender, "name": name, "html": html, **kw}).json()


def poll():
    r = c.post("/api/autoblock/poll", headers=H)
    assert r.status_code == 200, r.text
    return r.json()


def reqs(view="all"):
    return c.get(f"/api/autoblock/requests?view={view}", headers=H).json()["items"]


def by_ip(ip):
    return next((r for r in reqs() if r["ip"] == ip), None)


def wait_status(ip, want, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        r = by_ip(ip)
        if r and r["status"] == want:
            return r
        time.sleep(0.3)
    return by_ip(ip)


# ------------------------------------------------------------ hàm thuần
chk("cú pháp: dòng IN HOA đúng → nhận", [x["ip"] for x in parser.find_commands(f"Dạ chào các anh\n{CMD} 195.178.110.102")]
    == ["195.178.110.102"])
chk("cú pháp: chữ thường / viết hoa đầu câu → KHÔNG nhận",
    parser.find_commands("Đề xuất của SOC: BLOCK IP 1.2.3.4\nĐỀ XUẤT CỦA SOC: block ip 1.2.3.4") == [])
chk("cú pháp: câu có chữ khác trước/sau lệnh → không nhận",
    parser.find_commands(f"Nhờ anh {CMD} 1.2.3.4\n{CMD} 1.2.3.4 nhé") == [])
chk("cú pháp: Unicode tổ hợp (NFD) + &nbsp; + khoảng trắng thừa vẫn nhận",
    [x["ip"] for x in parser.find_commands(parser.html_to_text(
        unicodedata.normalize("NFD", "<p>ĐỀ XUẤT CỦA SOC:&nbsp;BLOCK IP   8.8.4.4 </p>")))] == ["8.8.4.4"])
cm = parser.find_commands(f"{CMD} 1.2.3.0/24\n{CMD} 1.2.3.999\n{CMD} 2001:db8::1")
chk("cú pháp: CIDR / IP sai / IPv6 → lệnh lỗi (không chặn)", len(cm) == 3 and all(x["ip"] == "" and x["error"] for x in cm))
chk("cú pháp: nhiều dòng lệnh trong một tin", len(parser.find_commands(
    parser.html_to_text(f"<div>{CMD} 5.5.5.5</div><div>{CMD} 6.6.6.6</div>"))) == 2)
VN = dt.timezone(dt.timedelta(hours=7))
W = {"window_enabled": True, "window_start": "18:00", "window_end": "08:00", "weekend_full": True, "holidays": []}
chk("khung giờ 18:00–08:00: 23:00 và 07:59 trong, 08:00 và 12:00 ngoài",
    abs_.in_window(W, dt.datetime(2026, 11, 18, 23, 0, tzinfo=VN)) and abs_.in_window(W, dt.datetime(2026, 11, 19, 7, 59, tzinfo=VN))
    and not abs_.in_window(W, dt.datetime(2026, 11, 19, 8, 0, tzinfo=VN))
    and not abs_.in_window(W, dt.datetime(2026, 11, 19, 12, 0, tzinfo=VN)))
chk("khung giờ tắt = 24/7", abs_.in_window({**W, "window_enabled": False}, dt.datetime(2026, 11, 19, 12, 0, tzinfo=VN)))
s, e = abs_.off_hours_span(W, dt.datetime(2026, 11, 19, 10, 0, tzinfo=VN))  # thứ 5
chk("ca ngoài giờ lúc 10:00 thứ 5 = 18:00 thứ 4 → 08:00 thứ 5",
    (s.day, s.hour, e.day, e.hour) == (18, 18, 19, 8), (s, e))
s, e = abs_.off_hours_span(W, dt.datetime(2026, 11, 19, 2, 0, tzinfo=VN))
chk("ca ngoài giờ lúc 02:00 = 18:00 hôm qua → 08:00 sáng nay", (s.day, s.hour, e.day, e.hour) == (18, 18, 19, 8))
chk("thứ 7 / Chủ nhật 12:00 → tự chặn cả ngày (Cuối tuần)",
    abs_.window_reason(W, dt.datetime(2026, 11, 21, 12, 0, tzinfo=VN)) == "Cuối tuần"
    and abs_.in_window(W, dt.datetime(2026, 11, 22, 15, 0, tzinfo=VN)))
chk("tắt tùy chọn cuối tuần → thứ 7 12:00 là giờ hành chính",
    not abs_.in_window({**W, "weekend_full": False}, dt.datetime(2026, 11, 21, 12, 0, tzinfo=VN)))
s, e = abs_.off_hours_span(W, dt.datetime(2026, 11, 21, 12, 0, tzinfo=VN))
chk("ca cuối tuần = 18:00 thứ 6 → 08:00 thứ 2", (s.strftime("%a %H:%M"), e.strftime("%a %H:%M")) == ("Fri 18:00", "Mon 08:00"),
    (s, e))
HW = {**W, "holidays": [{"from": "2026-12-31", "to": "2027-01-01", "name": "Tết Dương lịch"}]}
chk("ngày lễ rơi vào ngày thường (thứ 5, 10:00) → tự chặn cả ngày, nêu tên",
    abs_.window_reason(HW, dt.datetime(2026, 12, 31, 10, 0, tzinfo=VN)) == "Ngày lễ: Tết Dương lịch"
    and not abs_.in_window(W, dt.datetime(2026, 12, 31, 10, 0, tzinfo=VN)))
s, e = abs_.off_hours_span(HW, dt.datetime(2026, 12, 31, 10, 0, tzinfo=VN))
chk("ngày lễ liền cuối tuần gộp một ca: 18:00 thứ 4 30/12 → 08:00 thứ 2 04/01",
    (s.strftime("%d/%m %H:%M"), e.strftime("%d/%m %H:%M")) == ("30/12 18:00", "04/01 08:00"), (s, e))
chk("lịch tắt (24/7) → ca = 24 giờ qua", abs_.window_reason({**W, "window_enabled": False}) == "24/7")
for bad in ([{"from": "31/12/2026"}], [{"from": "2026-12-31", "to": "2026-12-30"}], [{"from": "2027-01-01", "to": "2027-03-01"}]):
    try:
        abs_.parse_holidays(bad)
        chk(f"ngày lễ sai {bad} → lỗi", False)
    except Exception:  # noqa: BLE001
        chk(f"ngày lễ sai {bad} → lỗi", True)

# ------------------------------------------------------------ chuẩn bị
H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
V = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]}
O = {"X-Auth-Token": issue_token("truc.dem@hsc.com.vn", role="operator", method="local", name="Trực đêm")}
g.post("/_reset")
fw = c.post("/api/firewalls", headers=H, json={"name": "FW-HCM", "host": "127.0.0.1", "port": 4460,
                                                "username": "apiadmin", "password": "Sophos@123"}).json()

chk("viewer xem được trạng thái", c.get("/api/autoblock/status", headers=V).status_code == 200)
chk("viewer không xem/sửa cấu hình, không đọc ngay",
    c.get("/api/autoblock/settings", headers=V).status_code == 403
    and c.put("/api/autoblock/settings", headers=V, json={"enabled": True}).status_code == 403
    and c.post("/api/autoblock/poll", headers=V).status_code == 403)
chk("operator không sửa cấu hình", c.put("/api/autoblock/settings", headers=O, json={"hourly_limit": 5}).status_code == 403)
st = c.get("/api/autoblock/settings", headers=H).json()
chk("mặc định: tắt, chu kỳ 300 giây, 20 IP/giờ, khung 18:00–08:00, công tắc bật",
    not st["enabled"] and st["poll_seconds"] == 300 and st["hourly_limit"] == 20
    and (st["window_start"], st["window_end"]) == ("18:00", "08:00") and st["auto_enabled"], st)
chk("bật khi chưa cấu hình → 400", c.put("/api/autoblock/settings", headers=H, json={"enabled": True}).status_code == 400)
chk("Tenant ID sai dạng → 400", c.put("/api/autoblock/settings", headers=H, json={"tenant_id": "abc"}).status_code == 400)
chk("Chat ID sai dạng → 400", c.put("/api/autoblock/settings", headers=H, json={"chat_id": "abc"}).status_code == 400)
chk("chu kỳ đọc ngoài 60–3600 giây → 400",
    c.put("/api/autoblock/settings", headers=H, json={"poll_seconds": 30}).status_code == 400
    and c.put("/api/autoblock/settings", headers=H, json={"poll_seconds": 7200}).status_code == 400)
r = c.put("/api/autoblock/settings", headers=H, json={"poll_seconds": 120})
chk("quản trị viên chỉnh chu kỳ đọc trên giao diện (120 giây)", r.status_code == 200 and r.json()["poll_seconds"] == 120
    and c.get("/api/autoblock/status", headers=V).json()["poll_seconds"] == 120, r.text)
r = c.put("/api/autoblock/settings", headers=H, json={"tenant_id": TENANT, "client_id": CLIENT, "chat_id": "19:khac@thread.v2",
    "client_secret": "x", "soc_senders": [{"id": SOC_ID}], "enabled": True})
chk("lưu lần đầu: đặt Chat ID + bật cùng lúc không lỗi", r.status_code == 200 and r.json()["enabled"], r.text[:200])
c.put("/api/autoblock/settings", headers=H, json={"enabled": False, "soc_senders": []})
r = c.put("/api/autoblock/settings", headers=H, json={"tenant_id": TENANT, "client_id": CLIENT, "chat_id": CHAT,
                                                       "client_secret": "sai-secret"})
chk("lưu kết nối Graph; không trả secret", r.status_code == 200 and r.json()["has_secret"]
    and "sai-secret" not in r.text and "secret_enc" not in r.text, r.text)
r = c.post("/api/autoblock/test", headers=H)
chk("kiểm tra kết nối với secret sai → báo lỗi Entra", r.status_code == 502 and "token" in r.json()["detail"], r.text)
c.put("/api/autoblock/settings", headers=H, json={"client_secret": "graph-secret"})
post(f"<p>Chào các anh</p><p>{CMD} 1.1.1.1</p>", minutes_ago=30)
post("tin của người khác", sender=OTHER_ID, name="Người lạ", minutes_ago=29)
r = c.post("/api/autoblock/test", headers=H)
chk("kiểm tra kết nối: liệt kê người gửi gần đây + số lệnh", r.status_code == 200 and r.json()["messages"] == 2
    and {s["id"] for s in r.json()["senders"]} == {SOC_ID, OTHER_ID}
    and next(s for s in r.json()["senders"] if s["id"] == SOC_ID)["commands"] == 1, r.text)
chk("bật khi chưa có tài khoản SOC → 400", c.put("/api/autoblock/settings", headers=H, json={"enabled": True}).status_code == 400)
r = c.put("/api/autoblock/settings", headers=H, json={
    "enabled": True, "soc_senders": [{"id": SOC_ID.upper(), "name": "SOC Ca đêm"}, {"id": SOC2_ID, "name": "SOC 2"}],
    "window_enabled": False, "hourly_limit": 3, "admin_emails": "admin1@hsc.com.vn; admin2@hsc.com.vn"})
chk("bật tự động chặn (24/7, ngưỡng 3 IP/giờ để kiểm thử)", r.status_code == 200 and r.json()["enabled"]
    and [s["id"] for s in r.json()["soc_senders"]] == [SOC_ID, SOC2_ID], r.text)

# ------------------------------------------------------------ trả lời vào group chat (Teams Workflows)
WF_URL = "http://127.0.0.1:4470/_workflow"
chk("bật trả lời khi chưa có URL webhook → 400",
    c.put("/api/autoblock/settings", headers=H, json={"reply_enabled": True}).status_code == 400)
chk("URL webhook không phải https → 400", c.put("/api/autoblock/settings", headers=H, json={
    "reply_webhook_url": "http://evil.example.com/hook"}).status_code == 400)
r = c.put("/api/autoblock/settings", headers=H, json={"reply_enabled": True,
          "reply_webhook_url": WF_URL + "?sig=bi-mat-chu-ky"})
chk("lưu URL webhook: chỉ trả tên máy, không lộ chữ ký sig", r.status_code == 200 and r.json()["has_reply_url"]
    and r.json()["reply_url_host"] == "127.0.0.1" and "bi-mat-chu-ky" not in r.text, r.text[:300])
r = c.post("/api/autoblock/reply-test", headers=H)
wf = g.get("/_workflow").json()
chk("gửi thử trả lời → workflow nhận Adaptive Card đúng cú pháp", r.status_code == 200 and len(wf) == 1
    and wf[0]["type"] == "message" and wf[0]["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    and wf[0]["text"].startswith("[THỬ] INFRA ĐÃ BLOCK 192.0.2.1 THEO YÊU CẦU LÚC "), r.text)
chk("operator không gửi thử được", c.post("/api/autoblock/reply-test", headers=O).status_code == 403)
g.post("/_reset")
post(f"<p>Chào các anh</p><p>{CMD} 1.1.1.1</p>", minutes_ago=30)

# ------------------------------------------------------------ đọc & tự chặn
p = poll()
chk("tin gửi TRƯỚC lúc bật không bị xử lý (1.1.1.1 cũ)", p["ok"] and p["messages"] == 0 and by_ip("1.1.1.1") is None, p)
post(f"<p>Dạ chào các anh, team ghi nhận dò quét từ 195.178.110.102</p><p>{CMD} 195.178.110.102</p>")
post(f"<p>{CMD} 45.33.32.156</p>", sender=OTHER_ID, name="Người lạ")
post(f"<p>{CMD} 23.94.5.10</p>", edited=True)
post(f"<p>{CMD} 23.94.5.11</p>", deleted=True)
post("<p>Đề xuất của SOC: BLOCK IP 23.94.5.12</p><p>ĐỀ XUẤT CỦA SOC: block ip 23.94.5.13</p>")
post(f"<p>{CMD} 10.45.2.62</p><p>{CMD} 103.0.0.0/24</p>")
p = poll()
chk("đọc: 6 tin mới, 3 lệnh hợp lệ cú pháp từ SOC", p["ok"] and p["messages"] == 6 and p["commands"] == 3, p)
r = wait_status("195.178.110.102", "blocked")
chk("IP của SOC được TỰ CHẶN trên firewall", r and r["status"] == "blocked" and r["mode"] == "auto"
    and "195.178.110.102" in group_hosts(), r)
chk("kết quả từng firewall được lưu", r and r["results"] and r["results"][0]["result"] == "added", r)
REPLY_RE = re.compile(r"^INFRA ĐÃ BLOCK 195\.178\.110\.102 THEO YÊU CẦU LÚC \d\d/\d\d/\d{4} \d\d:\d\d:\d\d$")
texts = [m["text"] for m in g.get("/_workflow").json()]
chk("sau khi chặn: trả lời vào group chat đúng cú pháp INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>",
    any(REPLY_RE.match(t) for t in texts) and r["reply_status"] == "sent", texts)
bt = dt.datetime.fromisoformat(r["blocked_at"]).astimezone(dt.timezone(dt.timedelta(hours=7)))
chk("thời điểm trong tin = lúc chặn xong (giờ VN)", any(t.endswith(bt.strftime("%d/%m/%Y %H:%M:%S")) for t in texts), (texts, bt))
chk("IP không chặn (người lạ / safe-list) → không trả lời", len(texts) == 1, texts)
chk("người ngoài danh sách SOC → không chặn", by_ip("45.33.32.156") is None and "45.33.32.156" not in group_hosts())
chk("tin đã sửa / đã xóa → bỏ qua", by_ip("23.94.5.10") is None and by_ip("23.94.5.11") is None)
chk("sai chữ hoa → bỏ qua", by_ip("23.94.5.12") is None and by_ip("23.94.5.13") is None)
r10 = by_ip("10.45.2.62")
chk("IP nội bộ → không chặn (safe-list)", r10 and r10["status"] == "invalid" and "10.45.2.62" not in group_hosts(), r10)
chk("CIDR → lệnh lỗi, không chặn", (by_ip("103.0.0.0/24") or {}).get("status") == "invalid")
ch = c.get("/api/changes?q=195.178.110.102", headers=H).json()
chk("lịch sử thay đổi ghi người thực hiện = autoblock, nguồn teams-auto",
    any(x.get("actor") == "autoblock" and x.get("source") == "teams-auto" for x in ch.get("batches", [])),
    str(ch)[:400])
post(f"<p>{CMD} 195.178.110.102</p>")
poll()
chk("lệnh trùng IP đang chặn → 'duplicate', không chặn lại",
    [x["status"] for x in reqs() if x["ip"] == "195.178.110.102"].count("duplicate") == 1)

# ------------------------------------------------------------ ngưỡng N IP/giờ
post("".join(f"<p>{CMD} 31.13.{i}.1</p>" for i in range(1, 5)))  # đã dùng 1 → còn 2 lượt tự chặn
p = poll()
time.sleep(1)
st = c.get("/api/autoblock/status", headers=V).json()
modes = {x["ip"]: x for x in reqs()}
chk("ngưỡng 3 IP/giờ: 2 IP đầu tự chặn, 2 IP sau chuyển chờ duyệt",
    [modes[f"31.13.{i}.1"]["mode"] for i in range(1, 5)] == ["auto", "auto", "pending", "pending"], p)
chk("vượt ngưỡng → ngắt (breaker) và hiện lý do", st["breaker_tripped_at"] and "vượt ngưỡng" in st["breaker_reason"], st)
ob = c.get("/api/notify/outbox", headers=H).json()
ob = ob["emails"]
kinds = {m["kind"]: m for m in ob}
chk("cảnh báo vượt ngưỡng gửi nhóm Admin", "autoblock_breaker" in kinds
    and kinds["autoblock_breaker"]["to"] == ["admin1@hsc.com.vn", "admin2@hsc.com.vn"], [m["kind"] for m in ob])
chk("email IP chờ duyệt gửi nhóm Admin", "autoblock_pending" in kinds)
post(f"<p>{CMD} 31.13.9.9</p>")
poll()
chk("sau khi ngắt: lệnh mới vẫn chờ duyệt", by_ip("31.13.9.9")["status"] == "pending"
    and "chờ quản trị viên mở lại" in by_ip("31.13.9.9")["pending_reason"])
chk("operator không mở lại được ngưỡng", c.post("/api/autoblock/breaker/reset", headers=O).status_code == 403)
r = c.post("/api/autoblock/breaker/reset", headers=H)
chk("quản trị viên mở lại", r.status_code == 200 and not r.json()["breaker_tripped_at"])

# ------------------------------------------------------------ duyệt / từ chối
chk("viewer không duyệt được", c.post("/api/autoblock/approve", headers=V, json={"ids": [by_ip("31.13.3.1")["id"]]}).status_code == 403)
r = c.post("/api/autoblock/approve", headers=O, json={"ids": [by_ip("31.13.3.1")["id"]]})
r3 = wait_status("31.13.3.1", "blocked")
chk("operator duyệt → chặn, ghi người duyệt", r.status_code in (200, 202) and r3["status"] == "blocked"
    and r3["decided_by"] == "truc.dem@hsc.com.vn" and "31.13.3.1" in group_hosts(), r.text)
r = c.post("/api/autoblock/reject", headers=O, json={"ids": [by_ip("31.13.4.1")["id"]], "note": "IP đối tác"})
chk("từ chối → không chặn", r.json()["rejected"] == 1 and by_ip("31.13.4.1")["status"] == "rejected"
    and "31.13.4.1" not in group_hosts())
chk("duyệt lại mục đã từ chối → 409", c.post("/api/autoblock/approve", headers=O,
                                            json={"ids": [by_ip("31.13.4.1")["id"]]}).status_code == 409)

chk("duyệt xong cũng trả lời vào group chat", any(m["text"].startswith("INFRA ĐÃ BLOCK 31.13.3.1 ")
                                                   for m in g.get("/_workflow").json()))
chk("lệnh bị từ chối → không trả lời", not any("31.13.4.1" in m["text"] for m in g.get("/_workflow").json()))

# ------------------------------------------------------------ whitelist (HSC / Akamai / đối tác)
st = c.get("/api/autoblock/settings", headers=H).json()
chk("mặc định có 3 whitelist HSC / Akamai / Đối tác (rỗng)",
    [w["name"] for w in st["whitelists"]] == ["HSC", "Akamai", "Đối tác"] and not any(w["entries"] for w in st["whitelists"]))
chk("whitelist: dòng không phải IPv4/CIDR → 400",
    c.put("/api/autoblock/settings", headers=H, json={"whitelists": [{"name": "HSC", "entries": "abc"}]}).status_code == 400)
chk("whitelist: trùng tên → 400", c.put("/api/autoblock/settings", headers=H, json={"whitelists": [
    {"name": "HSC", "entries": []}, {"name": "hsc", "entries": []}]}).status_code == 400)
chk("operator không sửa whitelist", c.put("/api/autoblock/settings", headers=O, json={"whitelists": []}).status_code == 403)
r = c.put("/api/autoblock/settings", headers=H, json={"whitelists": [
    {"name": "HSC", "entries": "113.161.0.0/24  # dải public HSC\n113.161.0.0/24"},
    {"name": "Akamai", "entries": "23.32.0.0/11, 104.64.0.0/10;2.16.0.1"},
    {"name": "Đối tác", "entries": ["203.113.88.9/32"]},
    {"name": "Nhà cung cấp SOC", "entries": "45.117.80.0/22"}]})
wl = {w["name"]: w["entries"] for w in r.json().get("whitelists", [])}
chk("lưu whitelist: chuẩn hóa, bỏ trùng, bỏ ghi chú #, thêm được danh sách riêng", r.status_code == 200
    and wl == {"HSC": ["113.161.0.0/24"], "Akamai": ["23.32.0.0/11", "104.64.0.0/10", "2.16.0.1"],
               "Đối tác": ["203.113.88.9"], "Nhà cung cấp SOC": ["45.117.80.0/22"]}, r.text[:300])
used_before = c.get("/api/autoblock/status", headers=V).json()["auto_last_hour"]
post(f"<p>{CMD} 23.33.1.1</p><p>{CMD} 203.113.88.9</p><p>{CMD} 113.161.0.20</p>")
poll()
ra, rp, rh = by_ip("23.33.1.1"), by_ip("203.113.88.9"), by_ip("113.161.0.20")
chk("IP thuộc whitelist Akamai / Đối tác / HSC → KHÔNG tự chặn, chờ quản trị viên",
    all(x["status"] == "pending" and x["needs_admin"] for x in (ra, rp, rh))
    and ra["whitelist"] == "Akamai: 23.32.0.0/11" and rp["whitelist"] == "Đối tác: 203.113.88.9"
    and "23.33.1.1" not in group_hosts(), (ra, rp))
chk("lý do chờ nêu rõ danh sách", "whitelist Akamai" in ra["pending_reason"] and "Approve" in ra["pending_reason"])
chk("whitelist không tính vào ngưỡng IP/giờ, không ngắt",
    c.get("/api/autoblock/status", headers=V).json()["auto_last_hour"] == used_before
    and not c.get("/api/autoblock/status", headers=V).json()["breaker_tripped_at"])
r = c.post("/api/autoblock/approve", headers=O, json={"ids": [ra["id"]]})
chk("operator KHÔNG Approve được IP thuộc whitelist", r.status_code == 403 and "quản trị viên" in r.json()["detail"], r.text)
r = c.post("/api/autoblock/approve", headers=H, json={"ids": [ra["id"]]})
ra = wait_status("23.33.1.1", "blocked")
chk("quản trị viên Approve → chặn, ghi người duyệt", r.status_code in (200, 202) and ra["status"] == "blocked"
    and ra["decided_by"] == "phu.luong@hsc.com.vn" and "23.33.1.1" in group_hosts(), r.text)
chk("operator vẫn từ chối được mục whitelist",
    c.post("/api/autoblock/reject", headers=O, json={"ids": [rp["id"], rh["id"]]}).json()["rejected"] == 2)

# ------------------------------------------------------------ khung giờ + công tắc
now = dt.datetime.now(VN)
ws, we = (now + dt.timedelta(hours=2)).strftime("%H:%M"), (now + dt.timedelta(hours=3)).strftime("%H:%M")
c.put("/api/autoblock/settings", headers=H, json={"window_enabled": True, "window_start": ws, "window_end": we,
                                                   "hourly_limit": 50, "weekend_full": False, "holidays": []})
post(f"<p>{CMD} 64.62.197.1</p>")
poll()
r = by_ip("64.62.197.1")
chk("trong giờ hành chính → chờ duyệt, nêu lý do", r["status"] == "pending" and "Ngoài khung giờ" in r["pending_reason"], r)
chk("operator không bật ngày lễ hôm nay", c.post("/api/autoblock/holiday-today", headers=O, json={"on": True}).status_code == 403)
st = c.post("/api/autoblock/holiday-today", headers=H, json={"on": True, "name": "Nghỉ bù"}).json()
chk("quản trị viên bật 'tự chặn cả ngày hôm nay' → đang trong khung (Ngày lễ)", st["in_window"] and st["holiday_today"]
    and st["window_reason"] == "Ngày lễ: Nghỉ bù", st)
post(f"<p>{CMD} 64.62.197.9</p>")
poll()
chk("ngày lễ kích hoạt → tự chặn ban ngày", (wait_status("64.62.197.9", "blocked") or {}).get("mode") == "auto")
st = c.post("/api/autoblock/holiday-today", headers=H, json={"on": False}).json()
chk("tắt lại ngày lễ hôm nay", not st["holiday_today"] and not st["in_window"], st)
r = c.put("/api/autoblock/settings", headers=H, json={"holidays": [{"from": "2027-02-05", "to": "2027-02-11", "name": "Tết Nguyên đán"}]})
chk("lưu đợt nghỉ lễ nhiều ngày", r.status_code == 200 and r.json()["holidays"][0]["to"] == "2027-02-11", r.text[:200])
chk("ngày lễ sai định dạng → 400", c.put("/api/autoblock/settings", headers=H, json={"holidays": [{"from": "05/02/2027"}]}).status_code == 400)
c.put("/api/autoblock/settings", headers=H, json={"window_enabled": False})
r = c.post("/api/autoblock/switch", headers=O, json={"on": False})
chk("operator TẮT KHẨN CẤP được", r.status_code == 200 and not r.json()["auto_enabled"], r.text)
post(f"<p>{CMD} 64.62.197.2</p>")
poll()
chk("công tắc tắt → lệnh chờ duyệt", by_ip("64.62.197.2")["status"] == "pending"
    and "TẮT" in by_ip("64.62.197.2")["pending_reason"])
chk("operator KHÔNG bật lại được", c.post("/api/autoblock/switch", headers=O, json={"on": True}).status_code == 403)
chk("quản trị viên bật lại", c.post("/api/autoblock/switch", headers=H, json={"on": True}).json()["auto_enabled"])
post(f"<p>{CMD} 64.62.197.3</p>", sender=SOC2_ID, name="SOC 2")
poll()
chk("bật lại → tự chặn tiếp (tài khoản SOC thứ hai)", (wait_status("64.62.197.3", "blocked") or {}).get("status") == "blocked")

g.post("/_workflow/fail?on=true")
post(f"<p>{CMD} 64.62.197.4</p>")
poll()
r = wait_status("64.62.197.4", "blocked")
chk("webhook Teams lỗi → vẫn chặn, ghi 'chưa báo được'", r["status"] == "blocked" and r["reply_status"] == "failed"
    and "Teams" in r["note"], r)
g.post("/_workflow/fail?on=false")
poll()
r = by_ip("64.62.197.4")
chk("chu kỳ đọc sau: tự gửi lại trả lời", r["reply_status"] == "sent" and r["reply_attempts"] == 2 and not r["note"]
    and any(m["text"].startswith("INFRA ĐÃ BLOCK 64.62.197.4 ") for m in g.get("/_workflow").json()), r)

# ------------------------------------------------------------ danh sách ca đêm + gỡ chặn
nv = c.get("/api/autoblock/requests?view=night", headers=V).json()
chk("danh sách ca trả mốc bắt đầu / kết thúc (giờ VN)", nv["night"]["start"].endswith("+07:00")
    and nv["night"]["end"].endswith("+07:00"), nv.get("night"))
_auto = {x["ip"] for x in reqs() if x["mode"] == "auto"}
chk("lịch 24/7: danh sách ca = IP tự chặn trong 24 giờ qua",
    {x["ip"] for x in nv["items"]} == _auto, ({x["ip"] for x in nv["items"]}, _auto))
chk("danh sách chờ duyệt", {x["ip"] for x in reqs("pending")} == {"31.13.9.9", "64.62.197.1", "64.62.197.2"},
    {x["ip"] for x in reqs("pending")})
chk("viewer không gỡ chặn được", c.post("/api/autoblock/unblock", headers=V, json={"ids": [1]}).status_code == 403)
rid = next(x["id"] for x in reqs() if x["ip"] == "195.178.110.102" and x["status"] == "blocked")
r = c.post("/api/autoblock/unblock", headers=O, json={"ids": [rid]})
for _ in range(50):
    r1 = next(x for x in reqs() if x["id"] == rid)
    if r1["status"] == "unblocked":
        break
    time.sleep(0.3)
chk("gỡ chặn 1 chạm → bỏ khỏi SCANPORT GROUP", r.status_code in (200, 202) and r1["status"] == "unblocked"
    and r1["unblocked_by"] == "truc.dem@hsc.com.vn" and "195.178.110.102" not in group_hosts(), r.text)
chk("gỡ mục không bị chặn → 409", c.post("/api/autoblock/unblock", headers=O, json={"ids": [rid]}).status_code == 409)
post(f"<p>{CMD} 195.178.110.102</p>")
poll()
chk("đã gỡ thì SOC đề xuất lại được chặn lại", [x["status"] for x in reqs() if x["ip"] == "195.178.110.102"][0]
    in ("blocking", "blocked"))

# ------------------------------------------------------------ mốc đọc tin: lọc phía Graph, không đọc lại lịch sử
import json as _json  # noqa: E402
import sqlalchemy as _sa  # noqa: E402

_eng = _sa.create_engine(os.environ["DATABASE_URL"])


def _state(**kw):
    with _eng.begin() as cn:
        raw = cn.execute(_sa.text("SELECT value FROM app_settings WHERE key='autoblock.state'")).scalar()
        st = _json.loads(raw)
        st.update(kw)
        cn.execute(_sa.text("UPDATE app_settings SET value=:v WHERE key='autoblock.state'"), {"v": _json.dumps(st)})
    return st


c.put("/api/autoblock/settings", headers=H, json={"window_enabled": False, "hourly_limit": 50, "stale_minutes": 30})
poll()
calls = g.get("/_calls").json()
chk("đọc tin dùng bộ lọc phía Graph: $filter=lastModifiedDateTime gt <mốc> + $orderby cùng trường",
    calls["last_filter"].startswith("lastModifiedDateTime gt ") and calls["last_orderby"].startswith("lastModifiedDateTime"),
    calls)
p2 = poll()
chk("chu kỳ không có tin mới → Graph trả 0 tin, không đọc lại lịch sử", g.get("/_calls").json()["returned"] == 0
    and p2["messages"] == 0, (g.get("/_calls").json(), p2))
st = c.get("/api/autoblock/status", headers=V).json()
chk("trạng thái: mốc đọc theo giờ Graph, số tin đọc lượt cuối = 0, đang lọc phía server",
    st["cursor"] and st["last_fetched"] == 0 and st["server_filter"] is True and not st["last_truncated"], st)
first = post(f"<p>{CMD} 77.77.77.1</p>")
poll()
g.post("/_touch", json={"id": first["id"]})  # SOC thả cảm xúc → lastModifiedDateTime đổi
p3 = poll()
chk("tin đã xử lý được thả cảm xúc / sửa nhẹ → Graph trả lại nhưng KHÔNG xử lý lại",
    g.get("/_calls").json()["returned"] == 1 and p3["messages"] == 0
    and [x["ip"] for x in reqs()].count("77.77.77.1") == 1, p3)
g.post("/_filter?reject=true")
post(f"<p>{CMD} 77.77.77.2</p>")
p4 = poll()
chk("tenant không nhận $filter → tự quay về đọc theo createdDateTime, vẫn chặn được",
    p4["ok"] and by_ip("77.77.77.2") is not None and c.get("/api/autoblock/status", headers=V).json()["server_filter"] is False, p4)
g.post("/_filter?reject=false")

# lệnh cũ (app ngừng / mất mạng): gửi 45 phút trước, giờ mới đọc → không tự chặn
now_utc = dt.datetime.now(dt.timezone.utc)
_state(start_at=(now_utc - dt.timedelta(hours=2)).isoformat(), cursor=(now_utc - dt.timedelta(hours=2)).isoformat())
post(f"<p>{CMD} 77.77.77.3</p>", minutes_ago=45)
poll()
r = by_ip("77.77.77.3")
chk("lệnh SOC gửi quá ngưỡng (45 > 30 phút) mới được đọc → chờ duyệt, nêu độ trễ", r and r["status"] == "pending"
    and "Lệnh cũ" in r["pending_reason"] and "trễ 4" in r["pending_reason"], r)
chk("lưu thời điểm SOC gửi (createdDateTime của Graph), khác lúc app xử lý",
    r and r["requested_at"] and (dt.datetime.fromisoformat(r["created_at"]) - dt.datetime.fromisoformat(r["requested_at"])).total_seconds() > 40 * 60, r)
chk("ngưỡng lệnh cũ ngoài 5–1440 phút → 400",
    c.put("/api/autoblock/settings", headers=H, json={"stale_minutes": 2}).status_code == 400)

# khung giờ tính theo LÚC SOC GỬI: gửi 10 phút trước (trong khung), app đọc bây giờ (đã ra khỏi khung)
now_vn = dt.datetime.now(VN)
ws, we = (now_vn - dt.timedelta(minutes=60)).strftime("%H:%M"), (now_vn - dt.timedelta(minutes=3)).strftime("%H:%M")
c.put("/api/autoblock/settings", headers=H, json={"window_enabled": True, "window_start": ws, "window_end": we,
                                                   "weekend_full": False, "holidays": []})
_state(cursor=(now_utc - dt.timedelta(hours=2)).isoformat())
post(f"<p>{CMD} 77.77.77.4</p>", minutes_ago=10)
poll()
r = wait_status("77.77.77.4", "blocked")
chk("khung giờ tự chặn tính theo lúc SOC gửi (trong khung) dù app đọc sau khi hết khung → tự chặn",
    r and r["mode"] == "auto", r)
c.put("/api/autoblock/settings", headers=H, json={"window_enabled": False})

# ------------------------------------------------------------ bằng chứng: SOC gửi lệnh rồi XÓA tin
import hashlib as _hl  # noqa: E402

VT = V["X-Auth-Token"]

c.put("/api/autoblock/settings", headers=H, json={"window_enabled": False})
_state(cursor=dt.datetime.now(dt.timezone.utc).isoformat())
sent = post(f"<p>Dạ team ghi nhận dò quét từ 88.88.88.1</p><p>{CMD} 88.88.88.1</p>")
poll()
r = wait_status("88.88.88.1", "blocked")
evr = c.get(f"/api/autoblock/requests/{r['id']}/evidence", headers=V)
chk("viewer xem được bản chụp bằng chứng của lệnh", evr.status_code == 200, evr.text[:200])
ev = evr.json()
chk("bản chụp: nội dung gốc, người gửi + Object ID, Message ID, giờ Teams, giờ app nhận, SHA-256",
    "BLOCK IP 88.88.88.1" in ev["evidence"]["text"] and ev["evidence"]["sender_id"] == SOC_ID
    and ev["evidence"]["msg_id"] == sent["id"] and ev["evidence"]["teams_created_at"] and ev["evidence"]["captured_at"]
    and len(ev["evidence"]["sha256"]) == 64 and ev["evidence"]["intact"] and ev["teams_now"]["state"] == "intact", ev)
chk("bản chụp có trước khi chặn (captured_at ≤ blocked_at)",
    dt.datetime.fromisoformat(ev["evidence"]["captured_at"]) <= dt.datetime.fromisoformat(r["blocked_at"]), (ev["evidence"]["captured_at"], r["blocked_at"]))
g.post("/_delete", json={"id": sent["id"]})  # người dùng xóa tin BLOCK IP trên Teams
poll()
ev2 = c.get(f"/api/autoblock/requests/{r['id']}/evidence", headers=V).json()
chk("tin bị XÓA trên Teams → app ghi mốc xóa (giờ Microsoft + lúc phát hiện), bản chụp gốc giữ nguyên",
    ev2["teams_now"]["state"] == "deleted" and ev2["teams_now"]["deleted_at"] and ev2["teams_now"]["deleted_seen_at"]
    and ev2["evidence"]["text"] == ev["evidence"]["text"] and ev2["evidence"]["sha256"] == ev["evidence"]["sha256"]
    and ev2["evidence"]["intact"], ev2["teams_now"])
chk("tin bị xóa không làm thay đổi kết quả chặn", by_ip("88.88.88.1")["status"] == "blocked")
fr = c.get(f"/api/autoblock/requests/{r['id']}/evidence.json?token={VT}")
doc = fr.json() if fr.status_code == 200 else {}
chk("tải file bằng chứng JSON (?token=)", fr.status_code == 200 and "attachment" in fr.headers.get("content-disposition", ""),
    fr.status_code)
chk("kiểm chứng độc lập: SHA-256(graph_message_raw) = evidence.sha256, raw chứa nội dung gốc trước khi xóa",
    _hl.sha256(doc.get("graph_message_raw", "").encode()).hexdigest() == doc.get("evidence", {}).get("sha256")
    and "BLOCK IP 88.88.88.1" in doc.get("graph_message_raw", "") and doc["teams_now"]["state"] == "deleted")
chk("file bằng chứng không token → 401", c.get(f"/api/autoblock/requests/{r['id']}/evidence.json").status_code == 401)
ab_ev = c.get("/api/audit?action=evidence_export", headers=H).json()["rows"]
chk("audit evidence_export khi tải bằng chứng", len(ab_ev) == 1 and ab_ev[0]["actor"] == "xem@hsc.com.vn")

sent2 = post(f"<p>{CMD} 88.88.88.2</p>")
poll()
g.post("/_edit", json={"id": sent2["id"], "html": "<p>xin lỗi gửi nhầm</p>"})
poll()
r2 = wait_status("88.88.88.2", "blocked")
ev3 = c.get(f"/api/autoblock/requests/{r2['id']}/evidence", headers=V).json()
chk("tin bị SỬA sau khi xử lý → ghi mốc sửa, bản chụp vẫn là nội dung gốc",
    ev3["teams_now"]["state"] == "edited" and "BLOCK IP 88.88.88.2" in ev3["evidence"]["text"], ev3["teams_now"])
with _eng.connect() as cn:
    n_ev = cn.execute(_sa.text("SELECT count(*) FROM autoblock_evidence")).scalar()
    n_stranger = cn.execute(_sa.text("SELECT count(*) FROM autoblock_evidence WHERE status='ignored_sender'")).scalar()
chk("chụp bằng chứng cả lệnh bị bỏ qua (người ngoài danh sách SOC)", n_stranger >= 1 and n_ev >= 10, (n_ev, n_stranger))
with _eng.begin() as cn:  # thử sửa trực tiếp bản chụp trong DB → kiểm tra toàn vẹn phải phát hiện
    cn.execute(_sa.text("UPDATE autoblock_evidence SET text='giả mạo' WHERE id=(SELECT min(id) FROM autoblock_evidence)"))
v = c.get("/api/autoblock/verify", headers=V).json()
chk("sửa NỘI DUNG bản chụp trực tiếp trong DB → kiểm tra toàn vẹn phát hiện", not v["ok"] and "Bằng chứng" in v["message"], v)
chk("sửa SHA-256 của bản chụp trong DB → kiểm tra toàn vẹn báo đứt chuỗi", not v["ok"] and "Bằng chứng" in v["message"], v)

# ------------------------------------------------------------ lỗi Graph, chuỗi băm, audit
c.put("/api/autoblock/settings", headers=H, json={"client_secret": "het-han"})
p = c.post("/api/autoblock/poll", headers=H).json()
st = c.get("/api/autoblock/status", headers=V).json()
chk("Graph lỗi → không chặn gì, trạng thái báo lỗi", not p["ok"] and st["last_ok"] is False and st["last_error"], st)
c.put("/api/autoblock/settings", headers=H, json={"client_secret": "graph-secret"})
v = c.get("/api/autoblock/verify", headers=V).json()
chk("nhật ký tự động chặn: chuỗi sự kiện vẫn toàn vẹn (bản chụp đã bị sửa ở bước trước)", v["checked"] > 10
    and v["message"].startswith("Bằng chứng"), v)
au = c.get("/api/audit?action=autoblock_switch", headers=H).json()
items = au["rows"]
chk("audit ghi bật/tắt công tắc + ngắt ngưỡng", sum(1 for x in items if x.get("action") == "autoblock_switch") >= 4,
    str(au)[:300])
cfg = c.get("/api/autoblock/settings", headers=H).json()
chk("người gửi đã thấy được liệt kê (để quản trị viên chọn tài khoản SOC)",
    {s["id"] for s in cfg["seen_senders"]} >= {SOC_ID, OTHER_ID, SOC2_ID})
chk("trạng thái: bộ lập lịch tắt trong kiểm thử (AUTOBLOCK_POLL_SECONDS=0)", st["scheduler"] is False)

print("\nTỔNG:", "OK" if not fails else f"{fails} lỗi")
sys.exit(1 if fails else 0)
