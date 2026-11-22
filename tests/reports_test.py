# Chạy: bash tests/run_e2e.sh tests/reports_test.py   (thêm E2E_DATABASE_URL=... để chạy trên PostgreSQL)
# v2.2 — báo cáo thống kê chặn IP 7 / 14 / 30 ngày: Executive Summary + chi tiết, PDF / Excel, gửi email qua SMTP.
import datetime as dt
import email
import email.policy
import io
import json
import os
import subprocess
import sys
import tempfile
import time

import httpx
from openpyxl import load_workbook

sys.path.insert(0, "backend")
from app.core.security import issue_token  # noqa: E402

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=90)
g = httpx.Client(base_url="http://127.0.0.1:4470", timeout=10)
CMD = "ĐỀ XUẤT CỦA SOC: BLOCK IP"
SOC = "11111111-2222-3333-4444-555555555555"
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")


def wait_job(r):
    j = r.json()
    for _ in range(60):
        if j.get("status") != "running":
            return j
        time.sleep(0.5)
        j = c.get(f"/api/jobs/{j['job_id']}", headers=H).json()
    return j


H = {"X-Auth-Token": c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]}
VT = c.post("/api/auth/header", headers={"X-SRB-UPN": "xem@hsc.com.vn"}).json()["token"]
V = {"X-Auth-Token": VT}
O = {"X-Auth-Token": issue_token("truc.dem@hsc.com.vn", role="operator", method="local", name="Trực đêm")}
RT = issue_token("rms.lead@hsc.com.vn", role="reviewer", method="entra-oidc", name="Đại diện")
g.post("/_reset")
c.post("/api/firewalls", headers=H, json={"name": "FW-HCM", "host": "127.0.0.1", "port": 4460,
                                          "username": "apiadmin", "password": "Sophos@123"})

# ------------------------------------------------------------ dữ liệu: 3 IP thủ công, 2 IP tự động, 1 gỡ
wait_job(c.post("/api/block", headers=H, json={"values": ["45.155.204.88", "91.92.109.4", "194.26.29.0/24"],
                                               "reason": "Brute force SSH — ticket #123", "source": "paste"}))
wait_job(c.post("/api/unblock", headers=H, json={"targets": ["91.92.109.4"]}))
c.put("/api/autoblock/settings", headers=H, json={
    "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "client_id": "12345678-1234-1234-1234-123456789abc",
    "client_secret": "graph-secret", "chat_id": "19:mockchat@thread.v2", "soc_senders": [{"id": SOC, "name": "SOC"}],
    "window_enabled": False, "whitelists": [{"name": "Akamai", "entries": "23.32.0.0/11"}], "enabled": True})
time.sleep(1)
g.post("/_post", json={"sender_id": SOC, "name": "SOC", "html": f"<p>{CMD} 195.178.110.102</p><p>{CMD} 185.220.101.45</p>"
                                                                f"<p>{CMD} 23.33.1.1</p>"})
c.post("/api/autoblock/poll", headers=H)
time.sleep(3)
pend = [x for x in c.get("/api/autoblock/requests?view=pending", headers=H).json()["items"]]
wait_job(c.post("/api/autoblock/approve", headers=H, json={"ids": [pend[0]["id"]]}))
time.sleep(2)

# ------------------------------------------------------------ JSON xem trước
r = c.get("/api/reports/summary?days=7", headers=V)
chk("viewer xem được báo cáo", r.status_code == 200, r.text[:200])
j = r.json()
s = j["summary"]
chk("tổng IP duy nhất = 6 (3 thủ công + 2 tự động + 1 Approve)", s["unique_ips"] == 6, s)
chk("phương thức: Approve lệnh SOC tính là thủ công (con người)", s["manual_ips"] == 4 and s["auto_ips"] == 2, s)
chk("tỷ lệ tự động 33%", s["auto_share"] == 33, s)
chk("gỡ chặn trong kỳ = 1, còn đang chặn = 5", s["removed_in_period"] == 1 and s["still_blocked"] == 5, s)
chk("theo ngày: đủ 7 ngày, hôm nay có 6 IP", len(j["daily"]) == 7 and j["daily"][-1]["total"] == 6
    and j["daily"][-1]["date"] == dt.datetime.now(dt.timezone(dt.timedelta(hours=7))).date().isoformat(), j["daily"][-1])
ips = {i["ip"]: i for i in j["ips"]}
chk("danh sách IP: phương thức + người / nguồn + thời gian thực hiện",
    ips["195.178.110.102"]["method_label"] == "Tự động" and "Tự động chặn (Teams)" in ips["195.178.110.102"]["actors"]
    and ips["23.33.1.1"]["method_label"] == "Thủ công" and "Duyệt lệnh SOC (Teams)" in ips["23.33.1.1"]["sources"]
    and ips["45.155.204.88"]["sources"] == ["Dán từ Teams"] and ips["45.155.204.88"]["first"], ips.get("23.33.1.1"))
chk("IP đã gỡ có trạng thái 'Đã gỡ'", ips["91.92.109.4"]["status"] == "Đã gỡ" and ips["45.155.204.88"]["status"] == "Đang chặn")
ab = j["autoblock"]
chk("tự động chặn: 3 lệnh, 2 tự chặn, 1 Approve, 1 whitelist, có thời gian xử lý",
    (ab["requests"], ab["auto"], ab["approved"], ab["whitelist"]) == (3, 2, 1, 1) and ab["latency_avg"] is not None, ab)
ex = j["executive"]
chk("Executive Summary: câu tổng quan + nhận định + cần lưu ý", "đã chặn 6 IP" in ex["headline"]
    and any("Ngày cao điểm" in x for x in ex["highlights"]) and any("whitelist" in x for x in ex["attention"]), ex)
chk("kỳ 14 / 30 ngày", len(c.get("/api/reports/summary?days=14", headers=V).json()["daily"]) == 14
    and len(c.get("/api/reports/summary?days=30", headers=V).json()["daily"]) == 30)
chk("kỳ khác 7/14/30 (không chọn lịch) → 400", c.get("/api/reports/summary?days=5", headers=V).status_code == 400)
TODAY = dt.datetime.now(dt.timezone(dt.timedelta(hours=7))).date()
r = c.get(f"/api/reports/summary?from={TODAY - dt.timedelta(days=2)}&to={TODAY}", headers=V).json()
chk("chọn khoảng ngày trên lịch: 3 ngày, nhãn dd/mm/yyyy – dd/mm/yyyy, đủ 6 IP", len(r["daily"]) == 3
    and r["summary"]["unique_ips"] == 6 and r["label"] == f"{TODAY - dt.timedelta(days=2):%d/%m/%Y} – {TODAY:%d/%m/%Y}", r.get("label"))
r = c.get(f"/api/reports/summary?from={TODAY - dt.timedelta(days=10)}&to={TODAY - dt.timedelta(days=1)}", headers=V).json()
chk("khoảng ngày trước hôm nay: không có IP, headline nêu rõ", r["summary"]["unique_ips"] == 0
    and "không có IP" in r["executive"]["headline"] and len(r["daily"]) == 10, r["executive"]["headline"])
chk("một ngày (from = to)", len(c.get(f"/api/reports/summary?from={TODAY}&to={TODAY}", headers=V).json()["daily"]) == 1)
for q, why in ((f"from={TODAY}&to={TODAY - dt.timedelta(days=1)}", "đến trước từ"),
               (f"from={TODAY + dt.timedelta(days=3)}&to={TODAY + dt.timedelta(days=4)}", "tương lai"),
               (f"from={TODAY - dt.timedelta(days=400)}&to={TODAY}", "quá 366 ngày"), ("from=31/12/2026", "sai định dạng")):
    chk(f"khoảng ngày lỗi ({why}) → 400", c.get(f"/api/reports/summary?{q}", headers=V).status_code == 400)
r = c.get(f"/api/reports/blocks.pdf?from={TODAY - dt.timedelta(days=2)}&to={TODAY}&token={VT}")
chk("PDF theo khoảng ngày: tên file theo ngày bắt đầu – kết thúc", r.status_code == 200
    and f"bao-cao-chan-ip_{TODAY - dt.timedelta(days=2):%Y%m%d}-{TODAY:%Y%m%d}.pdf" in r.headers["content-disposition"],
    r.headers.get("content-disposition"))
chk("vai trò Rà soát không xem được báo cáo", c.get("/api/reports/summary?days=7",
                                                    headers={"X-Auth-Token": RT}).status_code in (401, 403))

# ------------------------------------------------------------ logo header (logo tải lên)
import base64 as _b64  # noqa: E402
from PIL import Image as _PILImage  # noqa: E402
_buf = io.BytesIO()
_PILImage.new("RGB", (240, 80), (0, 70, 140)).save(_buf, "PNG")
LOGO_PNG = _buf.getvalue()
r = c.put("/api/branding/logo", headers=H, json={"data_url": "data:image/png;base64," + _b64.b64encode(LOGO_PNG).decode()})
chk("chuẩn bị: tải logo PNG", r.status_code == 200, r.text[:200])

# ------------------------------------------------------------ PDF
r = c.get(f"/api/reports/blocks.pdf?days=7&token={VT}")
chk("tải PDF (viewer, ?token=)", r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    and r.content[:5] == b"%PDF-" and len(r.content) > 20000, (r.status_code, len(r.content)))
chk("tên file PDF có ngày bắt đầu – kết thúc", 'bao-cao-chan-ip_' in r.headers.get("content-disposition", ""))
pdf_path = os.path.join(tempfile.gettempdir(), "srb_report_test.pdf")
open(pdf_path, "wb").write(r.content)
chk("PDF không token → 401", c.get("/api/reports/blocks.pdf?days=7").status_code == 401)
chk("PDF với token vai trò Rà soát → từ chối", c.get(f"/api/reports/blocks.pdf?days=7&token={RT}").status_code in (401, 403))
try:
    txt = subprocess.run(["pdftotext", "-layout", pdf_path, "-"], capture_output=True, text=True).stdout
except FileNotFoundError:
    txt = None
if txt is not None:
    chk("PDF: trang đầu là Executive Summary, sau đó Nội dung chi tiết + danh sách IP",
        txt.index("Executive Summary") < txt.index("Nội dung chi tiết") < txt.index("195.178.110.102"), txt[:300])
    chk("PDF: tiếng Việt có dấu hiển thị đúng", "Nhận định nổi bật" in txt and "Cần lưu ý" in txt)
r = c.get(f"/api/reports/blocks.pdf?from={TODAY - dt.timedelta(days=365)}&to={TODAY}&token={VT}")
chk("PDF khoảng dài (366 ngày) vẫn dựng được", r.status_code == 200 and r.content[:5] == b"%PDF-", r.status_code)
for d in (14, 30):
    r = c.get(f"/api/reports/blocks.pdf?days={d}&token={VT}")
    chk(f"PDF {d} ngày", r.status_code == 200 and r.content[:5] == b"%PDF-")

r_pdf = c.get(f"/api/reports/blocks.pdf?days=7&token={VT}").content
try:
    _lp = os.path.join(tempfile.gettempdir(), "srb_report_logo.pdf")
    open(_lp, "wb").write(r_pdf)
    imgs = subprocess.run(["pdfimages", "-list", _lp], capture_output=True).stdout.decode()
except FileNotFoundError:
    imgs = None
if imgs is not None:
    chk("PDF có logo ở header (ảnh 240×80 trên trang 1)", any(l.split()[:1] == ["1"] and " 240 " in l and " 80 " in l
                                                            for l in imgs.splitlines()[2:]), imgs[:400])

# ------------------------------------------------------------ Excel
r = c.get(f"/api/reports/blocks.xlsx?days=7&token={VT}")
chk("tải Excel", r.status_code == 200 and "spreadsheetml" in r.headers["content-type"], r.status_code)
wb = load_workbook(io.BytesIO(r.content))
chk("Excel: sheet đầu là Executive Summary, sau đó các sheet chi tiết",
    wb.sheetnames == ["Executive Summary", "Theo ngày", "Danh sách IP", "Chi tiết lượt chặn", "Người thực hiện"],
    wb.sheetnames)
es = [str(x.value) for row in wb["Executive Summary"].iter_rows() for x in row if x.value]
chk("Excel: Executive Summary có tổng quan, nhận định, cần lưu ý, chỉ số",
    any("đã chặn 6 IP" in x for x in es) and "Nhận định nổi bật" in es and "Cần lưu ý / hành động" in es
    and "Chỉ số chính" in es)
chk("Excel có logo ở header sheet Executive Summary", len(wb["Executive Summary"]._images) == 1)
chk("Excel dùng font Inter (HSC Design System)", wb["Danh sách IP"]["A2"].font.name == "Inter"
    and wb["Danh sách IP"]["A1"].fill.fgColor.rgb.endswith("00468C"))
wi = wb["Danh sách IP"]
chk("Excel: danh sách IP đủ 6 dòng, cột thời gian là kiểu ngày giờ", wi.max_row == 7
    and isinstance(wi["B2"].value, dt.datetime) and wi.auto_filter.ref, (wi.max_row, type(wi["B2"].value)))
we = wb["Chi tiết lượt chặn"]
meth = {we.cell(row=i, column=2).value: we.cell(row=i, column=4).value for i in range(2, we.max_row + 1)}
chk("Excel: chi tiết từng lượt có phương thức Thủ công / Tự động", meth.get("195.178.110.102") == "Tự động"
    and meth.get("45.155.204.88") == "Thủ công", meth)

c.delete("/api/branding/logo", headers=H)
r = c.get(f"/api/reports/blocks.pdf?days=7&token={VT}")
chk("chưa có logo → PDF vẫn có biểu tượng mặc định ở header", r.status_code == 200 and r.content[:5] == b"%PDF-")

# ------------------------------------------------------------ gửi email
out = tempfile.mktemp(suffix=".jsonl")
smtp_proc = subprocess.Popen([sys.executable, "mock/mock_smtp.py", "--port", "2526", "--out", out])
time.sleep(1)
try:
    body = {"days": 7, "to": "infra@hsc.com.vn; sep@hsc.com.vn", "formats": ["pdf", "xlsx"], "note": "Báo cáo tuần"}
    chk("viewer không gửi email báo cáo được", c.post("/api/reports/email", headers=V, json=body).status_code == 403)
    r = c.post("/api/reports/email", headers=O, json=body)
    chk("chưa cấu hình SMTP → 400 nêu rõ", r.status_code == 400 and "SMTP" in r.json()["detail"], r.text)
    c.put("/api/settings/smtp", headers=H, json={"host": "127.0.0.1", "port": 2526, "security": "none",
                                                 "from_addr": "soc-rapid-block@hsc.com.vn"})
    r = c.post("/api/reports/email", headers=O, json=body)
    chk("SMTP đang tắt → 400", r.status_code == 400 and "TẮT" in r.json()["detail"], r.text)
    c.put("/api/settings/smtp", headers=H, json={"enabled": True})
    chk("email sai định dạng → 400", c.post("/api/reports/email", headers=O, json={**body, "to": "abc"}).status_code == 400)
    chk("không chọn định dạng → 400", c.post("/api/reports/email", headers=O, json={**body, "formats": []}).status_code == 400)
    r = c.post("/api/reports/email", headers=O, json=body)
    chk("operator gửi báo cáo qua SMTP", r.status_code == 200 and r.json()["sent"]
        and r.json()["to"] == ["infra@hsc.com.vn", "sep@hsc.com.vn"] and len(r.json()["files"]) == 2, r.text[:300])
    time.sleep(1)
    mails = [json.loads(x) for x in open(out, encoding="utf-8") if x.strip()]
    m = email.message_from_string(mails[-1]["data"], policy=email.policy.default) if mails else None
    att = {p.get_filename(): p.get_content_type() for p in m.iter_attachments()} if m else {}
    chk("thư có 2 file đính kèm PDF + Excel", sorted(att.values()) == [
        "application/pdf", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"], att)
    text = m.get_body(preferencelist=("plain",)).get_content() if m else ""
    chk("nội dung thư mở đầu bằng Executive Summary + ghi chú người gửi",
        "EXECUTIVE SUMMARY" in text and "Báo cáo tuần" in text and "Nhận định nổi bật" in text
        and text.index("EXECUTIVE SUMMARY") < text.index("Nhận định nổi bật"), text[:300])
    chk("tiêu đề thư nêu kỳ + số IP", "Báo cáo chặn IP 7 ngày" in str(m["Subject"]) and "6 IP" in str(m["Subject"]))
    r = c.post("/api/reports/email", headers=O, json={**body, "days": None, "date_from": str(TODAY - dt.timedelta(days=2)),
                                                       "date_to": str(TODAY), "formats": ["xlsx"]})
    chk("gửi email báo cáo theo khoảng ngày chọn trên lịch", r.status_code == 200 and r.json()["files"][0].endswith(".xlsx")
        and "Báo cáo chặn IP 3 ngày" in r.json()["subject"], r.text[:200])
    r = c.post("/api/reports/email", headers=O, json={**body, "to": "reject@hsc.com.vn", "formats": ["pdf"]})
    chk("máy chủ từ chối người nhận → 502 + audit lỗi", r.status_code == 502, r.text)
    au = [x for x in c.get("/api/audit?action=report_email", headers=H).json()["rows"]]
    chk("audit report_email (ok + lỗi)", {x["result"] for x in au} == {"ok", "error"}, au[:2])
    au = c.get("/api/audit?action=report_export", headers=H).json()["rows"]
    chk("audit report_export khi tải file", len(au) >= 4 and au[0]["actor"] == "xem@hsc.com.vn")
finally:
    smtp_proc.terminate()

print("\nTỔNG:", "OK" if not fails else f"{fails} lỗi")
sys.exit(1 if fails else 0)
