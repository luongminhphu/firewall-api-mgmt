"""Thời hạn truy cập VPN (B2) — hàm thuần, không DB / mạng: bóc tên rule, xác định hạn, phân loại trạng thái.

Quy ước tên rule đang vận hành ở HSC (docs/architecture.md §5.4):
    "THAM.NQ expire 23/04/2027"
    "RMS RESEARCH - CHAU.NB expire 19/10/2027"
    "RMS RESEARCH - NHAN.NDT 30/06/2027"            (thiếu chữ expire)
    "HR team testing HRIS - expire 31/12/2026"
    "VPN - RMS RESEARCH GROUP access Factset Server" (không có ngày)
Ngày luôn hiểu là dd/mm/yyyy (chấp nhận / . - làm dấu phân cách, ngày/tháng 1–2 chữ số). Ngày không hợp lệ
(31/02/2027) KHÔNG được đoán → trạng thái "Không đọc được tên" (nếu không có Schedule bù lại).
Hạn = hết ngày theo giờ Việt Nam.
"""
from __future__ import annotations

import datetime as dt
import re

VN_TZ = dt.timezone(dt.timedelta(hours=7))

DATE_RE = re.compile(r"(?<!\d)(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})(?!\d)")
EXPIRE_RE = re.compile(r"\b(?:expire[sd]?|exp|hết hạn|het han)\b\.?", re.I)
CODE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+\b")  # CHAU.NB, NHAN.NDT
PREFIX_RE = re.compile(r"^\s*VPN\s*-\s*", re.I)
TEAM_CUT_RE = re.compile(r"\s+(?:GROUP\b|access\b|truy cập\b)", re.I)

# Trạng thái — thứ tự kiểm tra = độ ưu tiên hiển thị
STATUSES = {
    "unreadable": "Không đọc được tên",
    "user_gone": "User không còn / bị khóa",
    "expired_enabled": "Đã hết hạn nhưng rule vẫn bật",
    "expired_disabled": "Đã hết hạn (rule đã tắt)",
    "expiring": "Sắp hết hạn",
    "active": "Còn hạn",
    "no_expiry": "Không có hạn",
}


def parse_rule_name(name: str) -> dict:
    """→ {team, user_code, name_date (date|None), name_status: ok | none | invalid, name_date_raw}."""
    raw = re.sub(r"\s+", " ", (name or "").strip())
    m = None
    for m in DATE_RE.finditer(raw):  # lấy ngày CUỐI CÙNG trong tên
        pass
    name_date, status, date_raw = None, "none", ""
    subject = raw
    if m:
        date_raw = m.group(0)
        d, mo, y = (int(x) for x in m.groups())
        try:
            name_date = dt.date(y, mo, d)
            status = "ok"
        except ValueError:
            status = "invalid"
        subject = raw[:m.start()] + raw[m.end():]
    elif EXPIRE_RE.search(raw):
        status = "invalid"  # có chữ expire nhưng không có ngày đọc được
    subject = EXPIRE_RE.sub(" ", subject)
    subject = re.sub(r"\s+", " ", subject).strip(" -–—:")
    subject = PREFIX_RE.sub("", subject)
    code_m = CODE_RE.search(subject)
    user_code = code_m.group(0).upper() if code_m else ""
    segments = [s.strip(" -–—") for s in re.split(r"\s[-–—]\s", subject) if s.strip(" -–—")]
    if len(segments) > 1:
        team = segments[0] if not CODE_RE.search(segments[0]) else ""
    else:
        team = "" if user_code else (segments[0] if segments else "")
    team = TEAM_CUT_RE.split(team, maxsplit=1)[0].strip() if team else ""
    return {"team": team, "user_code": user_code, "name_date": name_date, "name_status": status,
            "name_date_raw": date_raw}


def parse_schedule_end(schedule: dict | None) -> dt.date | None:
    """Ngày kết thúc của Schedule kiểu OneTime ('2027-04-23 23:59:00'); Recurring / không có → None."""
    if not schedule or (schedule.get("type") or "").lower() != "onetime":
        return None
    raw = (schedule.get("end_date") or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def determine_expiry(name: str, schedule: dict | None) -> dict:
    """Ưu tiên ngày kết thúc Schedule; không có thì bóc từ tên. Lệch nhau → expiry_mismatch."""
    p = parse_rule_name(name)
    sched_end = parse_schedule_end(schedule)
    if sched_end:
        expiry, source = sched_end, "schedule"
    elif p["name_date"]:
        expiry, source = p["name_date"], "name"
    else:
        expiry, source = None, "none"
    mismatch = bool(sched_end and p["name_date"] and sched_end != p["name_date"])
    return {**p, "schedule_end": sched_end, "expiry_date": expiry, "expiry_source": source,
            "expiry_mismatch": mismatch}


def today_vn(now: dt.datetime | None = None) -> dt.date:
    return (now or dt.datetime.now(dt.timezone.utc)).astimezone(VN_TZ).date()


def classify(*, expiry_date: dt.date | None, expiry_source: str, name_status: str, enabled: bool,
             accounts_gone: bool, today: dt.date, threshold_days: int) -> dict:
    """Phân loại một rule. accounts_gone: mọi tài khoản liên kết đã bị xóa/khóa trên firewall.

    Trả {status, label, days_left, flags[]} — flags gồm MỌI điều kiện đúng (status chỉ là cái ưu tiên nhất).
    """
    days = (expiry_date - today).days if expiry_date else None
    flags = []
    if name_status == "invalid" and expiry_source != "schedule":
        flags.append("unreadable")
    if accounts_gone:
        flags.append("user_gone")
    if days is not None and days < 0:
        flags.append("expired_enabled" if enabled else "expired_disabled")
    elif days is not None and days <= threshold_days:
        flags.append("expiring")
    elif days is not None:
        flags.append("active")
    if expiry_date is None and "unreadable" not in flags:
        flags.append("no_expiry")
    status = next(s for s in STATUSES if s in flags) if flags else "no_expiry"
    return {"status": status, "label": STATUSES[status], "days_left": days, "flags": flags}
