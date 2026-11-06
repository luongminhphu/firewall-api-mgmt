# Chạy: bash tests/run_e2e.sh tests/group_cache_test.py
# v1.6: cache IP Host Group theo firewall + quét lại sau mỗi lần thêm/xóa IP; logo tùy chỉnh.
import base64
import sys
import time

import httpx

sys.path.insert(0, "backend")
from app.sophos import SophosClient  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
fw = {"name": "FW-HCM", "host": "127.0.0.1", "port": 4460, "username": "apiadmin", "password": "Sophos@123"}
fid = c.post("/api/firewalls", json=fw, headers=H).json()["id"]
fc = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123", verify_ssl=False, timeout=10)


def wait_clean(timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        m = c.get(f"/api/firewalls/{fid}/group-cache", headers=H).json()
        if m["cached"] and not m["dirty"] and not m["refreshing"]:
            return m
        time.sleep(0.2)
    return m


# 1) Tạo firewall → quét nền tạo cache
m = wait_clean()
chk("tạo firewall → cache được quét nền", m["cached"] and m["status"] == "ok", m)
base_total = m["total"]

# 2) Đọc từ cache
t = time.perf_counter(); r = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json(); ms_cache = (time.perf_counter() - t) * 1000
chk("đọc danh sách từ cache", r["source"] == "cache" and r["total"] == base_total, f"{ms_cache:.1f} ms")
chk("kèm thời điểm quét", bool(r["cache"]["scanned_at"]))

# 3) Thay đổi ngoài app → cache cũ vẫn trả ngay; refresh=1 quét lại
fc.add_ip_host("MANUAL_X_1", "IP", "103.77.9.9", "them tay")
g = fc.get_group("SCANPORT GROUP"); fc.set_group_hosts("SCANPORT GROUP", g["hosts"] + ["MANUAL_X_1"], g["description"], g["ip_family"])
r = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
chk("thay đổi ngoài app: cache chưa thấy (đúng thiết kế)", all(x["object"] != "MANUAL_X_1" for x in r["members"]))
time.sleep(5.1)
t = time.perf_counter(); r = c.get(f"/api/firewalls/{fid}/group-members?refresh=1", headers=H).json(); ms_live = (time.perf_counter() - t) * 1000
chk("Quét lại (refresh=1) → thấy object mới", r["source"] == "live" and any(x["object"] == "MANUAL_X_1" for x in r["members"]), f"{ms_live:.1f} ms")
r2 = c.get(f"/api/firewalls/{fid}/group-members?refresh=1", headers=H).json()
chk("quét tay liên tục bị giãn cách (dùng kết quả vừa quét)", r2["source"] == "cache")
ch = c.get("/api/changes", headers=H).json()
items = ch if isinstance(ch, list) else ch.get("items", ch.get("changes", []))
chk("quét cache vẫn ghi nhận thay đổi ngoài app (drift)", "ngoai-app" in str(ch) and ("MANUAL_X_1" in str(ch) or "103.77.9.9" in str(ch)), str(ch)[:300])

# 4) Chặn IP → cache đánh dấu dirty, quét lại nền
r = c.post("/api/block", json={"values": ["45.138.12.16", "185.220.101.0/24"], "firewall_ids": [fid], "reason": "Tet"}, headers=H).json()
chk("block trả danh sách firewall cần quét lại", r.get("cache_refresh") == [fid], r.get("cache_refresh"))
m = wait_clean()
r = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
objs = {x["object"] for x in r["members"]}
chk("sau khi chặn: cache có IP mới", {"45.138.12.16", "185.220.101.0/24"} <= objs and r["source"] == "cache")
chk("tổng số khớp firewall", r["total"] == len(fc.get_group("SCANPORT GROUP")["hosts"]))

# dry-run không quét lại
r = c.post("/api/block", json={"values": ["45.138.12.17"], "firewall_ids": [fid], "dry_run": True}, headers=H).json()
chk("chạy thử không đánh dấu cache", r.get("cache_refresh") == [])

# 5) Bỏ chặn → cache cập nhật
r = c.post("/api/unblock", json={"targets": ["45.138.12.16"], "firewall_ids": [fid], "delete_object": True}, headers=H).json()
chk("unblock trả firewall cần quét lại", r.get("cache_refresh") == [fid])
wait_clean()
r = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
chk("sau khi bỏ chặn: cache không còn IP", all(x["object"] != "45.138.12.16" for x in r["members"]))

# 6) Tổng quan + tìm kiếm trên cache
o = c.get("/api/group-cache", headers=H).json()
chk("tổng quan mọi firewall", o["group"] == "SCANPORT GROUP" and o["firewalls"][0]["total"] == r["total"])
s = c.get(f"/api/firewalls/{fid}/group-members?q=185.220", headers=H).json()
chk("tìm kiếm trên cache", len(s["members"]) == 1 and s["total"] == r["total"])
gr = c.get(f"/api/firewalls/{fid}/groups", headers=H).json()
chk("/groups dùng cache", gr["groups"][0]["count"] == r["total"] and gr["cache"]["cached"])

# 7) Firewall lỗi kết nối → giữ dữ liệu cache cũ, báo lỗi
c.put(f"/api/firewalls/{fid}", json={"port": 4999}, headers=H)
time.sleep(1.5)
r = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
chk("firewall lỗi: vẫn hiển thị cache cũ + trạng thái lỗi", r["total"] > 0 and r["cache"]["status"] == "error", r["cache"]["error"][:60])
c.put(f"/api/firewalls/{fid}", json={"port": 4460}, headers=H); wait_clean()

# 8) Logo
chk("chưa có logo", c.get("/api/branding").json()["has_logo"] is False)
png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
du = "data:image/png;base64," + base64.b64encode(png).decode()
chk("readonly/không đăng nhập không đổi được logo", c.put("/api/branding/logo", json={"data_url": du}).status_code in (401, 403))
bad = "data:image/svg+xml;base64," + base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>').decode()
chk("SVG có script bị từ chối", c.put("/api/branding/logo", json={"data_url": bad}, headers=H).status_code == 400)
fake = "data:image/png;base64," + base64.b64encode(b"<html>not png</html>").decode()
chk("file giả PNG bị từ chối", c.put("/api/branding/logo", json={"data_url": fake}, headers=H).status_code == 400)
big = "data:image/png;base64," + base64.b64encode(png[:8] + b"0" * 400 * 1024).decode()
chk("logo quá dung lượng bị từ chối", c.put("/api/branding/logo", json={"data_url": big}, headers=H).status_code == 400)
r = c.put("/api/branding/logo", json={"data_url": du}, headers=H)
chk("upload PNG", r.status_code == 200 and r.json()["has_logo"], r.text[:100])
lg = c.get(c.get("/api/branding").json()["logo_url"])
chk("tải logo công khai (màn hình đăng nhập)", lg.status_code == 200 and lg.content == png and lg.headers["content-type"] == "image/png")
chk("logo có CSP sandbox + nosniff", "sandbox" in lg.headers.get("content-security-policy", "") and lg.headers.get("x-content-type-options") == "nosniff")
svg = "data:image/svg+xml;base64," + base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#fff"/></svg>').decode()
chk("upload SVG sạch", c.put("/api/branding/logo", json={"data_url": svg}, headers=H).status_code == 200)
au = c.get("/api/audit?action=branding", headers=H).json()
chk("audit ghi nhận đổi logo", "logo" in str(au))
chk("gỡ logo", c.delete("/api/branding/logo", headers=H).json()["has_logo"] is False)

# 9) Xóa firewall → xóa cache
c.delete(f"/api/firewalls/{fid}", headers=H)
chk("xóa firewall → xóa cache", c.get("/api/group-cache", headers=H).json()["firewalls"] == [])
print("RESULT", "OK" if fails == 0 else f"{fails} FAIL")
