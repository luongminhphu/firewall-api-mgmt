# Chạy: GROUP_SCAN_TIMEOUT=3 API_TIMEOUT=2 GROUP_CACHE_REFRESH_WAIT=2 bash tests/run_e2e.sh tests/slow_fw_test.py
# v1.6.1: firewall chậm khi trả toàn bộ IP Host — chặn/bỏ chặn không còn phụ thuộc lệnh nặng này,
# cache cập nhật nhẹ sau mỗi thay đổi, quét đầy đủ có timeout riêng + fallback, TTL 24h + lịch hằng ngày.
import datetime as dt
import json
import sys
import time

import httpx

sys.path.insert(0, "backend")
from app.sophos import SophosClient  # noqa: E402

B = "http://127.0.0.1:8090"
M = "https://127.0.0.1:4460"
c = httpx.Client(base_url=B, timeout=60)
mk = httpx.Client(base_url=M, verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


def stats():
    return mk.get("/_stats").json()


tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
H = {"X-Auth-Token": tok}
fid = c.post("/api/firewalls", json={"name": "FW-CHAM", "host": "127.0.0.1", "port": 4460,
                                       "username": "apiadmin", "password": "Sophos@123"}, headers=H).json()["id"]
fc = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123", timeout=10)


def cache():
    return c.get(f"/api/firewalls/{fid}/group-cache", headers=H).json()


def wait_clean(timeout=20):
    t0 = time.time()
    m = cache()
    while time.time() - t0 < timeout:
        m = cache()
        if m["cached"] and not m["dirty"] and not m["refreshing"]:
            return m
        time.sleep(0.2)
    return m


m = wait_clean()
chk("quét đầy đủ ban đầu", m["status"] == "ok" and m["details_mode"] == "full", m.get("details_mode"))
chk("TTL mặc định 24 giờ", m["ttl_minutes"] == 1440, m["ttl_minutes"])
chk("có mốc quét đầy đủ + dự kiến lần kế tiếp", bool(m["full_scanned_at"]) and bool(m["next_full_scan_at"]))
full_at0 = m["full_scanned_at"]

# Firewall trở nên rất chậm khi trả toàn bộ IP Host (5 giây > API_TIMEOUT=2, > GROUP_SCAN_TIMEOUT=3)
mk.post("/_delay", params={"seconds": 5})
s0 = stats()

t = time.perf_counter()
r = c.post("/api/block", json={"firewall_ids": [fid], "values": ["45.155.205.77", "103.9.8.0/24"],
                               "reason": "Quet port Tet", "source": "manual"}, headers=H).json()
ms = (time.perf_counter() - t) * 1000
fw = r["results"][0]
chk("chặn vẫn thành công khi firewall chậm", fw["ok"] and fw["summary"]["added"] == 2, fw.get("error", ""))
chk("chặn không chờ lệnh đọc toàn bộ IP Host", ms < 2000, f"{ms:.0f} ms")
m = wait_clean()
chk("sau chặn: cache cập nhật bằng quét nhẹ", m["status"] == "ok" and m["details_mode"] in ("lite", "full"), m)
chk("quét nhẹ không làm mới mốc quét đầy đủ (TTL tính từ lần quét đầy đủ)", m["full_scanned_at"] == full_at0)
mem = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
by = {x["object"]: x for x in mem["members"]}
chk("IP mới có trong cache ngay", "45.155.205.77" in by and "103.9.8.0/24" in by, list(by))
chk("ghi chú = lý do chặn (không cần đọc lại firewall)", by.get("45.155.205.77", {}).get("description") == "Quet port Tet")
chk("CIDR hiển thị đúng loại/giá trị", by.get("103.9.8.0/24", {}).get("host_type") == "Network"
    and by["103.9.8.0/24"]["value"] == "103.9.8.0/24")
chk("object cũ giữ ghi chú từ lần quét đầy đủ", by.get("SOC_BLOCK_45_155_204_11", {}).get("description") == "Scan SSH tet 2026")

# Object tạo tay (tên không phải IP) → tra đúng 1 object bằng Filter, không đọc toàn bộ
fc.add_ip_host("WEB_SCANNER_X", "IP", "198.51.100.7", "them tay")
g = fc.get_group("SCANPORT GROUP")
fc.set_group_hosts("SCANPORT GROUP", g["hosts"] + ["WEB_SCANNER_X"], g["description"], g["ip_family"])

t = time.perf_counter()
r = c.post("/api/unblock", json={"firewall_ids": [fid], "targets": ["45.155.205.77"]}, headers=H).json()
ms = (time.perf_counter() - t) * 1000
chk("bỏ chặn thành công khi firewall chậm", r["results"][0]["ok"], r["results"][0].get("error", ""))
chk("bỏ chặn không chờ lệnh đọc toàn bộ", ms < 2000, f"{ms:.0f} ms")
m = wait_clean()
mem = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
by = {x["object"]: x for x in mem["members"]}
chk("sau bỏ chặn cache không còn IP", "45.155.205.77" not in by)
chk("object tạo tay đọc được chi tiết qua tra theo tên", by.get("WEB_SCANNER_X", {}).get("value") == "198.51.100.7", by.get("WEB_SCANNER_X"))
s1 = stats()
chk("không có lệnh đọc toàn bộ IP Host trong chặn/bỏ chặn/quét nhẹ", s1["iphost_full"] == s0["iphost_full"],
    f"{s0} → {s1}")
chk("có dùng tra cứu theo tên", s1["iphost_one"] > s0["iphost_one"])

# Bấm Quét lại (đầy đủ) khi firewall chậm: request trả trong GROUP_CACHE_REFRESH_WAIT, quét tiếp nền rồi fallback
time.sleep(5.2)
t = time.perf_counter()
r = c.get(f"/api/firewalls/{fid}/group-members?refresh=1", headers=H).json()
ms = (time.perf_counter() - t) * 1000
chk("Quét lại không treo request khi firewall chậm", ms < 3500 and r["source"] == "cache", f"{ms:.0f} ms, {r['source']}")
chk("báo đang quét nền", r["cache"]["refreshing"])
m = wait_clean(30)
chk("quét đầy đủ quá timeout → vẫn cập nhật thành viên (partial), không lỗi", m["status"] == "ok"
    and m["details_mode"] == "partial", f"{m['details_mode']} / {m['note'][:80]}")
chk("có ghi chú giải thích cho người dùng", "chậm" in m["note"])
mem = c.get(f"/api/firewalls/{fid}/group-members", headers=H).json()
chk("danh sách vẫn đầy đủ sau fallback", {"WEB_SCANNER_X", "103.9.8.0/24"} <= {x["object"] for x in mem["members"]})

# Firewall nhanh trở lại → quét đầy đủ thành công, mốc TTL được làm mới
mk.post("/_delay", params={"seconds": 0})
time.sleep(5.2)
r = c.get(f"/api/firewalls/{fid}/group-members?refresh=1", headers=H).json()
chk("firewall nhanh: Quét lại trả kết quả trực tiếp", r["source"] == "live" and r["cache"]["details_mode"] == "full")
chk("mốc quét đầy đủ được làm mới", r["cache"]["full_scanned_at"] != full_at0)

# Lập lịch: TTL + mốc giờ hằng ngày (giờ Việt Nam)
from app import group_cache as gc  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import GroupCache  # noqa: E402

UTC = dt.timezone.utc
now = dt.datetime(2026, 11, 9, 3, 0, tzinfo=UTC)  # 10:00 giờ VN


def row(full_at, status="ok"):
    return GroupCache(firewall_id=999, group_name="SCANPORT GROUP", status=status, scanned_at=full_at,
                      data_json=json.dumps({"full_scanned_at": full_at.isoformat()}))


settings.GROUP_CACHE_DAILY_AT = ""
chk("TTL: quét đầy đủ 23 giờ trước → chưa đến hạn", not gc.due_for_full(row(now - dt.timedelta(hours=23)), now))
chk("TTL: quét đầy đủ 25 giờ trước → đến hạn", gc.due_for_full(row(now - dt.timedelta(hours=25)), now))
settings.GROUP_CACHE_DAILY_AT = "02:00"
chk("lịch 02:00: lần cuối 01:30 VN hôm nay → đến hạn",
    gc.due_for_full(row(dt.datetime(2026, 11, 8, 18, 30, tzinfo=UTC)), now))
chk("lịch 02:00: lần cuối 02:05 VN hôm nay → chưa đến hạn",
    not gc.due_for_full(row(dt.datetime(2026, 11, 8, 19, 5, tzinfo=UTC)), now))
settings.GROUP_CACHE_DAILY_AT = ""
chk("chưa có cache → đến hạn", gc.due_for_full(None, now))

print("RESULT", "OK" if fails == 0 else f"{fails} FAIL")
sys.exit(1 if fails else 0)
