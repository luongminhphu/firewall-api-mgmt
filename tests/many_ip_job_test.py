# Chạy: JOB_SYNC_WAIT=6 bash tests/run_e2e.sh tests/many_ip_job_test.py
# v1.7 — tái hiện lỗi 504: chặn 10 IP trên 3 firewall phản hồi chậm.
#  - Mỗi firewall chỉ còn 1 lệnh tạo object (gộp) + 1 lệnh ghi group, chạy song song giữa các firewall.
#  - Lâu hơn JOB_SYNC_WAIT → HTTP 202 + mã công việc, theo dõi qua /api/jobs/{id}, kết quả từng firewall hiện dần.
#  - Người khác (không phải quản trị viên) không xem được công việc của mình.
import os
import subprocess
import sys
import time

import httpx

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=120)
fails = 0
SYNC_WAIT = float(os.environ.get("JOB_SYNC_WAIT", "20"))


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# Hai firewall giả lập nữa (cổng 4461, 4462), trạng thái riêng
procs = []
for port in (4461, 4462):
    st = f"/tmp/mock_job_{port}.json"
    if os.path.exists(st):
        os.remove(st)
    procs.append(subprocess.Popen([sys.executable, "mock/mock_sophos.py", "--port", str(port)],
                                  env={**os.environ, "MOCK_STATE": st},
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
mocks = {port: httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=False, timeout=10)
         for port in (4460, 4461, 4462)}
for port, mk in mocks.items():
    for _ in range(60):
        try:
            mk.get("/_stats"); break
        except httpx.HTTPError:
            time.sleep(0.25)

try:
    tok = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
    H = {"X-Auth-Token": tok}
    ids = []
    for port in (4460, 4461, 4462):
        r = c.post("/api/firewalls", json={"name": f"FW-{port}", "host": "127.0.0.1", "port": port,
                                           "username": "apiadmin", "password": "Sophos@123"}, headers=H)
        ids.append(r.json()["id"])
    time.sleep(1.5)  # để lượt quét cache khởi động chạy xong, không lẫn vào số lệnh đo bên dưới

    ips = ["94.102.49.190", "103.158.121.4", "216.218.206.67", "159.203.190.206", "147.182.202.179",
           "138.226.239.5", "204.76.203.40", "149.56.31.99", "69.5.169.21", "109.105.209.42"]

    # ---- 1) firewall chậm vừa phải: xong trong JOB_SYNC_WAIT, trả 200 như trước
    for mk in mocks.values():
        mk.post("/_delay", params={"seconds": 0, "per_request": 0.5})
        mk.post("/_reset_stats")
    t0 = time.time()
    r = c.post("/api/block", json={"firewall_ids": ids, "values": ips[:5], "reason": "t1"}, headers=H)
    took = time.time() - t0
    body = r.json()
    chk("5 IP × 3 firewall chậm 0.5s/lệnh → 200 trong JOB_SYNC_WAIT", r.status_code == 200 and body["status"] == "done",
        f"{r.status_code} {took:.1f}s")
    # Bản cũ: tuần tự ~ (1 get_group + 5 add + 1 set) × 3 × 0.5s ≈ 10.5s. Bản mới: song song, gộp → ~1.5–3s
    chk("chạy song song + gộp lệnh (< 5s)", took < 5, f"{took:.1f}s")
    chk("đủ 3 firewall, mỗi firewall thêm 5", len(body["results"]) == 3 and
        all(x["summary"]["added"] == 5 and x["ok"] for x in body["results"]),
        [x["summary"] for x in body["results"]])
    st = [mk.get("/_stats").json() for mk in mocks.values()]
    chk("mỗi firewall đúng 2 lệnh Set (1 tạo 5 object gộp + 1 ghi group)",
        all(s["set_requests"] == 2 and s["iphost_set_entities"] == 5 for s in st),
        [(s["set_requests"], s["iphost_set_entities"]) for s in st])
    chk("không tra cứu từng object / đọc toàn bộ IP Host khi chặn",
        all(s["iphost_one"] == 0 and s["iphost_full"] == 0 for s in st),
        [(s["iphost_one"], s["iphost_full"]) for s in st])

    # ---- 2) firewall rất chậm: quá JOB_SYNC_WAIT → 202 + theo dõi công việc
    per = SYNC_WAIT / 2 + 0.5  # 3 lệnh/firewall ≈ 1.5 × JOB_SYNC_WAIT
    for port, mk in mocks.items():  # FW-4462 chậm hơn → thấy kết quả 2 firewall trước khi xong cả 3
        mk.post("/_delay", params={"seconds": 0, "per_request": per * (1.6 if port == 4462 else 1)})
    t0 = time.time()
    r = c.post("/api/block", json={"firewall_ids": ids, "values": ips, "reason": "t2"}, headers=H)
    took = time.time() - t0
    body = r.json()
    chk("firewall rất chậm → 202 sau khoảng JOB_SYNC_WAIT (không treo tới 504)",
        r.status_code == 202 and body["status"] == "running" and took < SYNC_WAIT + 3,
        f"{r.status_code} {took:.1f}s")
    job = body["job_id"]
    chk("202 kèm danh sách IP + firewall để giao diện hiển thị tiến độ",
        len(body["entries"]) == 10 and len(body["firewalls"]) == 3 and body["total"] == 3)

    viewer = c.post("/api/auth/header", headers={"X-SRB-UPN": "khach@hsc.com.vn"}).json()["token"]
    rv = c.get(f"/api/jobs/{job}", headers={"X-Auth-Token": viewer})
    chk("người khác không xem được công việc", rv.status_code == 404, rv.status_code)

    seen_partial = False
    for _ in range(240):
        j = c.get(f"/api/jobs/{job}", headers=H).json()
        if j["status"] == "running" and 0 < len(j["results"]) < 3:
            seen_partial = True
        if j["status"] != "running":
            break
        time.sleep(0.25)
    chk("công việc hoàn tất", j["status"] == "done" and j["done"] == 3, j["status"])
    chk("tổng thời gian ≈ 3 lệnh (song song), không phải 3 firewall × 12 lệnh",
        time.time() - t0 < 3 * per * 1.6 + 5, f"{time.time() - t0:.1f}s")
    s2 = {x["firewall"]: x["summary"] for x in j["results"]}
    chk("mỗi firewall: 5 IP mới thêm + 5 IP đã có từ lượt trước",
        all(v["added"] == 5 and v["existed"] == 5 and v["error"] == 0 for v in s2.values()), s2)
    chk("có trạng thái dở dang (hiển thị kết quả từng firewall khi xong)", seen_partial)

    # ---- 3) chặn lại cùng danh sách: nhận ra đã có, không gửi lệnh tạo object nào
    for mk in mocks.values():
        mk.post("/_delay", params={"seconds": 0, "per_request": 0})
        mk.post("/_reset_stats")
    time.sleep(1.5)
    for mk in mocks.values():
        mk.post("/_reset_stats")
    r = c.post("/api/block", json={"firewall_ids": ids, "values": ips, "reason": "t3"}, headers=H).json()
    chk("chặn lại → tất cả 'đã có'", all(x["summary"]["existed"] == 10 for x in r["results"]),
        [x["summary"] for x in r["results"]])
    st = [mk.get("/_stats").json() for mk in mocks.values()]
    chk("không gửi lệnh Set nào khi mọi IP đã có", all(s["set_requests"] == 0 for s in st),
        [s["set_requests"] for s in st])

    # ---- 4) bỏ chặn cũng chạy qua công việc nền
    r = c.post("/api/unblock", json={"firewall_ids": [ids[1]], "targets": ["94.102.49.190"],
                                     "delete_object": True, "reason": "t4"}, headers=H).json()
    chk("bỏ chặn qua công việc nền vẫn trả kết quả", r["status"] == "done" and r["results"][0]["summary"]["removed"] == 1,
        r.get("results"))
finally:
    for pr in procs:
        pr.terminate()

print("FAILS:", fails)
sys.exit(1 if fails else 0)
