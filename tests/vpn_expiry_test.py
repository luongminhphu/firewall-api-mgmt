# Chạy: PYTHONPATH=backend python3 tests/vpn_expiry_test.py   (hoặc qua run_e2e.sh)
# Hàm thuần của module VPN B2: bóc tên rule (mọi mẫu thực tế + mẫu lỗi), ưu tiên Schedule hơn tên,
# phân loại trạng thái theo ngày (tham số `today`, không phụ thuộc đồng hồ máy).
import datetime as dt
import sys

sys.path.insert(0, "backend")
from app.modules.vpn.expiry import classify, determine_expiry, parse_rule_name, parse_schedule_end  # noqa: E402

D = dt.date
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# ------------------------------------------------------------- parser
CASES = [
    ("THAM.NQ expire 23/04/2027", "", "THAM.NQ", D(2027, 4, 23), "ok"),
    ("RMS RESEARCH - CHAU.NB expire 19/10/2027", "RMS RESEARCH", "CHAU.NB", D(2027, 10, 19), "ok"),
    ("RMS RESEARCH - NHAN.NDT 30/06/2027", "RMS RESEARCH", "NHAN.NDT", D(2027, 6, 30), "ok"),
    ("HR team testing HRIS - expire 31/12/2026", "HR team testing HRIS", "", D(2026, 12, 31), "ok"),
    ("VPN - RMS RESEARCH GROUP access Factset Server", "RMS RESEARCH", "", None, "none"),
    # biến thể
    ("THAM.NQ expire 3/4/2027", "", "THAM.NQ", D(2027, 4, 3), "ok"),               # d/m/yyyy
    ("tham.nq Expire 23-04-2027", "", "THAM.NQ", D(2027, 4, 23), "ok"),            # chữ thường, dấu -
    ("RMS RESEARCH - CHAU.NB - expire 19.10.2027", "RMS RESEARCH", "CHAU.NB", D(2027, 10, 19), "ok"),
    ("  RMS   RESEARCH -  CHAU.NB   expire   19/10/2027 ", "RMS RESEARCH", "CHAU.NB", D(2027, 10, 19), "ok"),
    ("KETOAN - LE.VAN.A expire 01/01/2027", "KETOAN", "LE.VAN.A", D(2027, 1, 1), "ok"),
    ("Partner ABC access ERP", "Partner ABC", "", None, "none"),
    # lỗi: không đoán
    ("ABC expire 31/02/2027", "ABC", "", None, "invalid"),                          # ngày không tồn tại
    ("THAM.NQ expire 13/13/2027", "", "THAM.NQ", None, "invalid"),
    ("THAM.NQ expire soon", "", "THAM.NQ", None, "invalid"),                         # expire nhưng không có ngày
    ("THAM.NQ expire 23/04/27", "", "THAM.NQ", None, "invalid"),                     # năm 2 chữ số
    ("", "", "", None, "none"),
]
for name, team, code, date, st in CASES:
    p = parse_rule_name(name)
    got = (p["team"], p["user_code"], p["name_date"], p["name_status"])
    chk(f"tên rule: {name!r}", got == (team, code, date, st), got)
chk("12/05/2027 là 12 tháng 5 (dd/mm), không phải 5 tháng 12",
    parse_rule_name("A.B expire 12/05/2027")["name_date"] == D(2027, 5, 12))

# ------------------------------------------------------------- schedule
chk("Schedule OneTime → ngày kết thúc", parse_schedule_end({"type": "OneTime", "end_date": "2027-04-23 23:59:00"})
    == D(2027, 4, 23))
chk("Schedule Recurring → không có hạn", parse_schedule_end({"type": "Recurring", "end_date": ""}) is None)
chk("Schedule ngày hỏng → None", parse_schedule_end({"type": "OneTime", "end_date": "2027-02-30 00:00"}) is None)
e = determine_expiry("RMS RESEARCH - CHAU.NB expire 19/10/2027", {"type": "OneTime", "end_date": "2027-09-30 23:59:00"})
chk("ưu tiên Schedule hơn tên", e["expiry_date"] == D(2027, 9, 30) and e["expiry_source"] == "schedule", e)
chk("Schedule và tên lệch → cờ lệch thời hạn", e["expiry_mismatch"] is True)
e = determine_expiry("THAM.NQ expire 23/04/2027", {"type": "OneTime", "end_date": "2027-04-23 23:59:00"})
chk("Schedule trùng tên → không lệch", e["expiry_source"] == "schedule" and not e["expiry_mismatch"])
e = determine_expiry("THAM.NQ expire 23/04/2027", {"type": "Recurring"})
chk("Schedule Recurring → dùng ngày trong tên", e["expiry_date"] == D(2027, 4, 23) and e["expiry_source"] == "name")
e = determine_expiry("ABC expire 31/02/2027", {"type": "OneTime", "end_date": "2027-03-01 00:00:00"})
chk("tên hỏng nhưng có Schedule → dùng Schedule", e["expiry_source"] == "schedule" and e["name_status"] == "invalid")
chk("không ngày, không schedule → none", determine_expiry("VPN - X access Y", None)["expiry_source"] == "none")

# ------------------------------------------------------------- phân loại
T = D(2026, 11, 18)


def cls(expiry, *, src="name", name_status="ok", enabled=True, gone=False, th=30):
    return classify(expiry_date=expiry, expiry_source=src if expiry else "none", name_status=name_status,
                    enabled=enabled, accounts_gone=gone, today=T, threshold_days=th)


chk("còn hạn (> 30 ngày)", cls(D(2027, 4, 23))["status"] == "active")
chk("sắp hết hạn (≤ 30 ngày)", cls(D(2026, 12, 18))["status"] == "expiring" and cls(D(2026, 12, 18))["days_left"] == 30)
chk("31 ngày → còn hạn", cls(D(2026, 12, 19))["status"] == "active")
chk("hết hạn hôm nay vẫn tính sắp hết hạn (0 ngày)", cls(T)["status"] == "expiring" and cls(T)["days_left"] == 0)
chk("hôm qua → đã hết hạn nhưng rule vẫn bật", cls(D(2026, 11, 17))["status"] == "expired_enabled")
chk("hết hạn + rule tắt → đã hết hạn (đã tắt)", cls(D(2025, 1, 1), enabled=False)["status"] == "expired_disabled")
chk("ngưỡng cấu hình được (7 ngày)", cls(D(2026, 12, 1), th=7)["status"] == "active"
    and cls(D(2026, 11, 25), th=7)["status"] == "expiring")
chk("không có hạn", cls(None)["status"] == "no_expiry")
chk("không đọc được tên", cls(None, name_status="invalid")["status"] == "unreadable")
r = cls(D(2025, 1, 1), gone=True)
chk("user không còn → ưu tiên, vẫn giữ cờ hết hạn", r["status"] == "user_gone" and "expired_enabled" in r["flags"], r)
print("FAILS:", fails)
sys.exit(1 if fails else 0)
