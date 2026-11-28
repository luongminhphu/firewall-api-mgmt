"""Lập kế hoạch thông báo VPN — hàm thuần (test theo ngày, không DB / mạng) + cấu hình người nhận.

Idempotent nhờ dedupe_key (UNIQUE trong email_outbox):
  - Sắp hết hạn: vpn_expiring:<fw>:<rule>:<ngày hạn>:<mốc>  — mỗi mốc nhắc (30/14/7/1 ngày) gửi MỘT lần;
    app tắt vài ngày thì chỉ gửi mốc hiện tại; đổi hạn → khóa mới (nhắc lại theo hạn mới).
  - Hết hạn nhưng rule vẫn bật: vpn_expired_enabled:<fw>:<rule>:<ngày hạn>:<năm-tuần ISO> — nhắc Infra mỗi tuần.
Người nhận: sắp hết hạn → đại diện team (nhập tay) + Infra; hết hạn còn bật → Infra.
Nội dung chỉ có tên rule, team, mã user, tài khoản, ngày, đích — không có dữ liệu bí mật.
"""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.errors import AppError
from ...core.models import AppSetting, VpnTeamContact
from .smtp import parse_emails

KEY = "notify.settings"
DEFAULTS = {"enabled": False, "infra_emails": [], "reminder_days": [30, 14, 7, 1], "expired_weekly": True,
            "alert_fw_down": True, "fw_down_minutes": 15, "alert_drift": True}


def _fmt(d: str | None) -> str:
    return "/".join(reversed(d.split("-"))) if d else "—"


def bucket(days_left: int, reminder_days: list[int]) -> int | None:
    """Mốc nhắc hiện tại: mốc nhỏ nhất ≥ số ngày còn lại (vd còn 10 ngày, mốc 30/14/7/1 → 14)."""
    eligible = [b for b in reminder_days if b >= days_left]
    return min(eligible) if eligible and days_left >= 0 else None


def plan(rules: list[dict], cfg: dict, contacts: dict[str, list[str]], today: dt.date,
         app_url: str = "") -> list[dict]:
    """rules: kết quả modules.vpn.rules.list_rules()['rules'] (đã phân loại theo `today`)."""
    out = []
    infra = cfg.get("infra_emails") or []
    year, week, _ = today.isocalendar()
    for r in rules:
        flags = set(r.get("flags") or [])
        base = f"{r['firewall_id']}:{r['rule_name'].lower()}:{r['expiry_date']}"
        accts = ", ".join(a["username"] for a in r.get("accounts") or []) or ", ".join(r.get("identities") or []) or "—"
        detail = (f"Rule: {r['rule_name']}\nFirewall: {r['firewall']} · Rule Group {r['group_name']}\n"
                  f"Team: {r['team'] or '—'} · mã user: {r['user_code'] or '—'}\nTài khoản: {accts}\n"
                  f"Hạn truy cập: {_fmt(r['expiry_date'])} (theo {'Schedule' if r['expiry_source'] == 'schedule' else 'tên rule'})\n"
                  f"Đích: {', '.join(r['dst_zones'] + r['dst_networks']) or '—'} · dịch vụ: {', '.join(r['services']) or '—'}\n")
        foot = ("\nSOC Rapid Block chỉ ĐỌC cấu hình — không tự gia hạn, tắt hay xóa rule. Gia hạn / thu hồi do Infra "
                "thực hiện trên firewall." + (f"\nXem chi tiết: {app_url}/#vpn" if app_url else "")
                + "\n\n(Email tự động — vui lòng không trả lời.)\n")
        if "expiring" in flags and r["days_left"] is not None:
            b = bucket(r["days_left"], cfg["reminder_days"])
            to = sorted(set(contacts.get((r["team"] or "").lower(), [])) | set(infra))
            if b is not None and to:
                when = "hôm nay" if r["days_left"] == 0 else f"sau {r['days_left']} ngày"
                out.append({
                    "dedupe_key": f"vpn_expiring:{base}:{b}", "kind": "vpn_expiring", "to": to,
                    "subject": f"[VPN] Hết hạn {when}: {r['rule_name']}",
                    "body": f"Quyền truy cập VPN sẽ hết hạn {when} ({_fmt(r['expiry_date'])}).\n\n{detail}"
                            "\nNếu cần tiếp tục truy cập, đại diện team gửi yêu cầu gia hạn cho Infra trước ngày hết hạn.\n" + foot,
                    "ref": {"firewall_id": r["firewall_id"], "rule": r["rule_name"], "bucket": b},
                })
        if "expired_enabled" in flags and cfg.get("expired_weekly") and infra:
            out.append({
                "dedupe_key": f"vpn_expired_enabled:{base}:{year}-W{week:02d}", "kind": "vpn_expired_enabled",
                "to": sorted(set(infra)),
                "subject": f"[VPN] Đã hết hạn nhưng rule vẫn bật: {r['rule_name']}",
                "body": f"Rule VPN đã hết hạn từ {_fmt(r['expiry_date'])} ({-r['days_left']} ngày) nhưng vẫn đang BẬT "
                        f"trên firewall.\n\n{detail}\nĐề nghị Infra tắt hoặc gia hạn rule (nhắc lại mỗi tuần tới khi xử lý).\n"
                        + foot,
                "ref": {"firewall_id": r["firewall_id"], "rule": r["rule_name"]},
            })
    return out


# ----------------------------------------------------------------- cấu hình
def get_cfg(db: Session) -> dict:
    cfg = dict(DEFAULTS)
    row = db.get(AppSetting, KEY)
    if row and row.value:
        try:
            cfg.update({k: v for k, v in json.loads(row.value).items() if k in DEFAULTS})
        except ValueError:
            pass
    cfg["updated_by"] = row.updated_by if row else ""
    cfg["updated_at"] = row.updated_at.isoformat() if row and row.updated_at else None
    return cfg


def update_cfg(db: Session, data: dict, *, actor: str, client_ip: str) -> dict:
    cfg = {k: v for k, v in get_cfg(db).items() if k in DEFAULTS}
    if data.get("enabled") is not None:
        cfg["enabled"] = bool(data["enabled"])
    if data.get("expired_weekly") is not None:
        cfg["expired_weekly"] = bool(data["expired_weekly"])
    for k in ("alert_fw_down", "alert_drift"):
        if data.get(k) is not None:
            cfg[k] = bool(data[k])
    if data.get("fw_down_minutes") is not None:
        m = data["fw_down_minutes"]
        if isinstance(m, bool) or not isinstance(m, int) or not 5 <= m <= 1440:
            raise AppError(400, "Ngưỡng mất kết nối là số phút nguyên từ 5 đến 1440")
        cfg["fw_down_minutes"] = m
    if data.get("infra_emails") is not None:
        cfg["infra_emails"] = parse_emails(data["infra_emails"])
    if data.get("reminder_days") is not None:
        days = data["reminder_days"]
        if not isinstance(days, list) or not days or len(days) > 6 or \
                not all(isinstance(d, int) and 0 <= d <= 365 for d in days):
            raise AppError(400, "Mốc nhắc là 1–6 số ngày, mỗi số từ 0 đến 365 (vd 30, 14, 7, 1)")
        cfg["reminder_days"] = sorted(set(days), reverse=True)
    if cfg["enabled"] and not cfg["infra_emails"]:
        raise AppError(400, "Cần ít nhất một email Infra trước khi bật thông báo")
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value = json.dumps(cfg)
    row.updated_by = actor
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    audit(db, action="settings_cud", fw=None, target="notify", result="ok", actor=actor, client_ip=client_ip,
          message=f"Thông báo {'bật' if cfg['enabled'] else 'tắt'} · Infra {len(cfg['infra_emails'])} địa chỉ · "
                  f"mốc {cfg['reminder_days']}")
    db.commit()
    return get_cfg(db)


def split_members(v: str | None) -> list[str]:
    return [m for m in (v or "").split(",") if m]


def member_map(db: Session) -> dict[str, str]:
    """username (lowercase) → team_key của group chứa user đó."""
    return {m.lower(): c.team_key for c in db.scalars(select(VpnTeamContact)) for m in split_members(c.members)}


def suggest_groups(db: Session) -> list[dict]:
    """Gợi ý group VPN từ team bóc trong tên rule (vd "RMS RESEARCH - CHAU.NB …"): user của các rule đó là thành viên.

    - Team chưa là group → gợi ý group mới (kèm user chưa thuộc group nào).
    - Team đã là group nhưng còn user của rule chưa được gán → gợi ý bổ sung thành viên.
    - User đã thuộc group KHÁC không được gợi ý chuyển (một user ≤ 1 group) — liệt kê ở `taken` để Infra biết.
    Chỉ đọc; không ghi gì — Infra chọn gợi ý, rà lại thành viên, nhập đại diện rồi mới lưu.
    """
    from ..vpn import rules as vpn_rules  # tránh vòng import notify ↔ vpn

    groups = {c.team_key: c for c in db.scalars(select(VpnTeamContact))}
    owner = member_map(db)
    found: dict[str, dict] = {}
    for r in vpn_rules.list_rules(db)["rules"]:
        team = (r.get("team") or "").strip()
        if not team:
            continue
        g = found.setdefault(team.lower(), {"team": team, "rules": [], "users": {}})
        g["rules"].append(r["rule_name"])
        for a in r.get("accounts") or []:
            g["users"].setdefault(a["username"].lower(), a["username"])
    out = []
    for key, g in found.items():
        existing = key in groups
        new, taken = [], []
        for k, u in sorted(g["users"].items()):
            if owner.get(k) == key:
                continue  # đã ở đúng group
            if k in owner:
                taken.append({"username": u, "group": groups[owner[k]].team if owner[k] in groups else owner[k]})
            else:
                new.append(u)
        if existing and not new:
            continue  # group đã đủ thành viên theo rule
        out.append({"team": groups[key].team if existing else g["team"], "team_key": key, "existing": existing,
                    "rules": sorted(g["rules"], key=str.lower), "users": new, "taken": taken})
    return sorted(out, key=lambda x: (x["existing"], x["team"].lower()))


def get_contacts(db: Session) -> list[dict]:
    return [{"id": c.id, "team": c.team, "emails": [e for e in c.emails.split(",") if e], "note": c.note,
             "members": split_members(c.members),
             "updated_by": c.updated_by, "updated_at": c.updated_at.isoformat() if c.updated_at else None}
            for c in db.scalars(select(VpnTeamContact).order_by(VpnTeamContact.team_key))]


def contacts_map(db: Session) -> dict[str, list[str]]:
    return {c.team_key: [e for e in c.emails.split(",") if e] for c in db.scalars(select(VpnTeamContact))}


def replace_contacts(db: Session, items: list[dict], *, actor: str, client_ip: str) -> list[dict]:
    """Ghi lại toàn bộ danh sách đại diện team (nhập tay)."""
    clean: dict[str, dict] = {}
    for it in items:
        team = str(it.get("team") or "").strip()
        if not team:
            continue
        if len(team) > 160 or "\n" in team:
            raise AppError(400, f"Tên team không hợp lệ: {team[:60]}")
        emails = parse_emails(it.get("emails") or [])
        if not emails:
            raise AppError(400, f"Team '{team}' cần ít nhất một email đại diện")
        raw = it.get("members") or []
        raw = raw.replace(";", ",").replace("\n", ",").split(",") if isinstance(raw, str) else raw
        members: dict[str, str] = {}
        for m in raw:
            m = str(m).strip()
            if not m:
                continue
            if len(m) > 255 or any(ch in m for ch in ",\r\n"):
                raise AppError(400, f"Tên user VPN không hợp lệ: {m[:60]}")
            members.setdefault(m.lower(), m)
        if len(members) > 2000:
            raise AppError(400, f"Group '{team}' có quá nhiều user (tối đa 2000)")
        clean[team.lower()] = {"team": team, "emails": emails, "note": str(it.get("note") or "")[:500],
                               "members": list(members.values())}
    owner: dict[str, str] = {}
    for v in clean.values():  # một user chỉ thuộc một group — đại diện rà soát được xác định duy nhất
        for m in v["members"]:
            if m.lower() in owner:
                raise AppError(400, f"User '{m}' đang nằm ở 2 group: {owner[m.lower()]} và {v['team']}")
            owner[m.lower()] = v["team"]
    now = dt.datetime.now(dt.timezone.utc)
    existing = {c.team_key: c for c in db.scalars(select(VpnTeamContact))}
    for key, c in existing.items():
        if key not in clean:
            db.delete(c)
    for key, v in clean.items():
        c = existing.get(key) or VpnTeamContact(team_key=key)
        c.team, c.emails, c.note, c.members = v["team"], ",".join(v["emails"]), v["note"], ",".join(v["members"])
        c.updated_by, c.updated_at = actor, now
        db.add(c)
    audit(db, action="settings_cud", fw=None, target="team_contacts", result="ok", actor=actor, client_ip=client_ip,
          message=f"{len(clean)} group VPN có đại diện · {len(owner)} user VPN được gán group")
    db.commit()
    return get_contacts(db)
