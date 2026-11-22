"""Thời hạn truy cập VPN qua firewall rule (B2, CHỈ ĐỌC — KHÔNG tắt/sửa/xóa rule trên firewall).

Đồng bộ: FirewallRuleGroup (chỉ group trong cấu hình ∩ whitelist) → FirewallRule trong group → Schedule tham chiếu.
Mỗi rule: hạn (Schedule > tên), team, mã user; so với lần trước → lịch sử (vpn_rule_changes, chuỗi băm).
Đọc: phân loại trạng thái theo ngày hôm nay + ngưỡng; liên kết rule ↔ tài khoản qua identity, dự phòng mã user.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import time

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ...core import hashchain, jobs
from ...core.audit import audit
from ...core.config import settings
from ...core.models import Firewall, VpnAccount, VpnRule, VpnRuleChange, VpnSync
from ...integrations.sophos import SophosAuthError, SophosError
from ..firewalls.service import client_for
from . import expiry
from . import settings as vpn_settings

log = logging.getLogger("vpn.rules")

DETAIL_KEYS = ("src_zones", "src_networks", "identities", "match_identity", "dst_zones", "dst_networks",
               "services", "ip_family", "position_text")
# nhóm trường → loại thay đổi ghi vào lịch sử
CHANGE_GROUPS = [
    ("expiry_changed", ("expiry_date", "expiry_source", "schedule_name")),
    ("destination_changed", ("dst_zones", "dst_networks")),
    ("identity_changed", ("identities",)),
    ("service_changed", ("services",)),
    ("status_changed", ("enabled",)),
]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _d(v: dt.date | None) -> str | None:
    return v.isoformat() if v else None


def _iso(t: dt.datetime | None) -> str | None:
    if t is None:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).isoformat()


# ----------------------------------------------------------------- đồng bộ
def build_records(groups: list[dict], rules: list[dict], schedules: list[dict], wanted_groups: list[str]) -> list[dict]:
    """Ghép rule thuộc các group cần đọc + hạn (hàm thuần)."""
    by_name = {r["name"]: r for r in rules}
    sched = {s["name"]: s for s in schedules}
    out, seen = [], set()
    for g in groups:
        if g["name"] not in wanted_groups:
            continue
        for pos, rname in enumerate(g["rules"], start=1):
            r = by_name.get(rname)
            if r is None or rname.lower() in seen:
                continue
            seen.add(rname.lower())
            e = expiry.determine_expiry(rname, sched.get(r["schedule"]))
            out.append({
                "rule_name": rname, "rule_key": rname.lower(), "group_name": g["name"], "position": pos,
                "enabled": r["enabled"], "action": r["action"], "policy_type": r["policy_type"],
                "log_traffic": r["log_traffic"], "description": r["description"], "schedule_name": r["schedule"],
                "src_zones": r["src_zones"], "src_networks": r["src_networks"], "identities": r["identities"],
                "match_identity": r["match_identity"], "dst_zones": r["dst_zones"], "dst_networks": r["dst_networks"],
                "services": r["services"], "ip_family": r["ip_family"], "position_text": r["position"],
                "schedule_end": e["schedule_end"], "team": e["team"], "user_code": e["user_code"],
                "name_date": e["name_date"], "name_status": e["name_status"], "expiry_date": e["expiry_date"],
                "expiry_source": e["expiry_source"], "expiry_mismatch": e["expiry_mismatch"],
            })
    return out


def _snapshot(rec: dict) -> dict:
    """Nội dung dùng để so sánh / ghi lịch sử (không chứa thời điểm đồng bộ)."""
    return {
        "enabled": rec["enabled"], "action": rec["action"], "expiry_date": _d(rec["expiry_date"]),
        "expiry_source": rec["expiry_source"], "schedule_name": rec["schedule_name"],
        "dst_zones": rec["dst_zones"], "dst_networks": rec["dst_networks"], "identities": rec["identities"],
        "services": rec["services"], "src_zones": rec["src_zones"], "src_networks": rec["src_networks"],
        "log_traffic": rec["log_traffic"], "description": rec["description"],
    }


def _hash(snap: dict) -> str:
    return hashlib.sha256(json.dumps(snap, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _row_snapshot(r: VpnRule) -> dict:
    det = json.loads(r.detail_json or "{}")
    return {
        "enabled": r.enabled, "action": r.action, "expiry_date": _d(r.expiry_date), "expiry_source": r.expiry_source,
        "schedule_name": r.schedule_name, "dst_zones": det.get("dst_zones", []),
        "dst_networks": det.get("dst_networks", []), "identities": det.get("identities", []),
        "services": det.get("services", []), "src_zones": det.get("src_zones", []),
        "src_networks": det.get("src_networks", []), "log_traffic": r.log_traffic, "description": r.description,
    }


def diff_changes(before: dict, after: dict) -> list[tuple[str, dict, dict]]:
    """→ [(loại, trước, sau)] theo nhóm trường; khác nhưng không thuộc nhóm nào → rule_changed."""
    out, covered = [], set()
    for kind, keys in CHANGE_GROUPS:
        covered.update(keys)
        if any(before.get(k) != after.get(k) for k in keys):
            out.append((kind, {k: before.get(k) for k in keys}, {k: after.get(k) for k in keys}))
    rest = [k for k in after if k not in covered and before.get(k) != after.get(k)]
    if rest:
        out.append(("rule_changed", {k: before.get(k) for k in rest}, {k: after.get(k) for k in rest}))
    return out


def _apply(r: VpnRule, rec: dict, now: dt.datetime) -> None:
    r.rule_name = rec["rule_name"]
    r.group_name = rec["group_name"]
    r.position = rec["position"]
    r.enabled = rec["enabled"]
    r.action = rec["action"][:32]
    r.policy_type = rec["policy_type"][:32]
    r.log_traffic = rec["log_traffic"]
    r.detail_json = json.dumps({k: rec[k] for k in DETAIL_KEYS}, ensure_ascii=False)
    r.schedule_name = rec["schedule_name"][:160]
    r.schedule_end = rec["schedule_end"]
    r.description = rec["description"]
    r.team = rec["team"][:160]
    r.user_code = rec["user_code"][:80]
    r.name_date = rec["name_date"]
    r.name_status = rec["name_status"]
    r.expiry_date = rec["expiry_date"]
    r.expiry_source = rec["expiry_source"]
    r.expiry_mismatch = rec["expiry_mismatch"]
    r.content_hash = _hash(_snapshot(rec))
    r.last_seen_at = now
    r.removed_at = None


def _upsert(db: Session, fw: Firewall, records: list[dict], now: dt.datetime, actor: str) -> dict:
    rows = {r.rule_key: r for r in db.scalars(select(VpnRule).where(VpnRule.firewall_id == fw.id))}
    first_time = not rows
    changes: list[VpnRuleChange] = []
    c = {"total": len(records), "new": 0, "changed": 0, "removed": 0}

    def ev(rule_name, kind, before=None, after=None):
        changes.append(VpnRuleChange(ts=now, firewall_id=fw.id, firewall_name=fw.name, rule_name=rule_name,
                                     change_type=kind, actor=actor,
                                     before_json=json.dumps(before, ensure_ascii=False) if before is not None else "",
                                     after_json=json.dumps(after, ensure_ascii=False) if after is not None else ""))

    seen = set()
    for rec in records:
        seen.add(rec["rule_key"])
        r = rows.get(rec["rule_key"])
        snap = _snapshot(rec)
        if r is None:
            r = VpnRule(firewall_id=fw.id, rule_key=rec["rule_key"], first_seen_at=now)
            db.add(r)
            c["new"] += 1
            if not first_time:
                ev(rec["rule_name"], "rule_added", None, snap)
        elif r.removed_at is not None:
            c["new"] += 1
            ev(rec["rule_name"], "rule_added", None, snap)
        elif r.content_hash != _hash(snap):
            found = diff_changes(_row_snapshot(r), snap)
            if found:
                c["changed"] += 1
            for kind, b, a in found:
                ev(rec["rule_name"], kind, b, a)
        _apply(r, rec, now)
    for key, r in rows.items():
        if key not in seen and r.removed_at is None:
            r.removed_at = now
            c["removed"] += 1
            ev(r.rule_name, "rule_removed", _row_snapshot(r), None)
    if first_time and records:
        ev("", "baseline", None, {"rules": len(records), "groups": sorted({x["group_name"] for x in records})})
    db.flush()
    if changes:
        hashchain.append(db, VpnRuleChange, changes)  # commit trong khóa chuỗi băm
    c["events"] = len(changes)
    return c


def _save_sync(db: Session, fw_id: int, *, status: str, error: str = "", summary: dict | None = None,
               ms: int = 0) -> None:
    row = db.scalar(select(VpnSync).where(VpnSync.firewall_id == fw_id, VpnSync.kind == "rules"))
    if row is None:
        row = VpnSync(firewall_id=fw_id, kind="rules")
        db.add(row)
    row.synced_at = _now()
    row.status, row.error = status, error[:2000]
    if summary is not None:
        row.summary_json = json.dumps(summary)
    row.duration_ms = ms


def sync_firewall(db: Session, fw: Firewall, *, actor: str = "he-thong", client_ip: str = "") -> dict:
    base = {"firewall_id": fw.id, "firewall": fw.name}
    wanted = vpn_settings.get(db)["rule_groups"]
    with jobs.lock(f"vpn-rules:{fw.id}", blocking=False) as got:
        if not got:
            return {**base, "ok": False, "error": "Đang có lượt đồng bộ rule khác cho firewall này"}
        t0 = time.monotonic()
        try:
            t = settings.VPN_SCAN_TIMEOUT
            with client_for(fw) as cli:
                groups = cli.get_rule_groups(timeout=t)
                if not any(g["name"] in wanted for g in groups):
                    raise SophosError(f"Không thấy Rule Group {', '.join(wanted)} trên firewall {fw.name}", "526")
                rules = cli.get_firewall_rules(timeout=t)
                schedules = cli.get_schedules(timeout=t)
        except (SophosError, SophosAuthError, ValueError) as exc:
            ms = int((time.monotonic() - t0) * 1000)
            _save_sync(db, fw.id, status="error", error=str(exc), ms=ms)
            audit(db, action="vpn_sync", fw=fw, target="rules", result="error", message=str(exc), actor=actor,
                  client_ip=client_ip, code=getattr(exc, "code", ""))
            db.commit()
            return {**base, "ok": False, "error": str(exc)}
        records = build_records(groups, rules, schedules, wanted)
        summary = _upsert(db, fw, records, _now(), actor)
        ms = int((time.monotonic() - t0) * 1000)
        _save_sync(db, fw.id, status="ok", summary=summary, ms=ms)
        audit(db, action="vpn_sync", fw=fw, target="rules", result="ok", actor=actor, client_ip=client_ip,
              message=f"{summary['total']} rule · mới {summary['new']} · đổi {summary['changed']} · "
                      f"mất {summary['removed']}")
        db.commit()
        return {**base, "ok": True, "summary": summary, "ms": ms}


# --------------------------------------------------------------------- đọc
def _accounts_by_fw(db: Session) -> dict[int, list[VpnAccount]]:
    out: dict[int, list[VpnAccount]] = {}
    for a in db.scalars(select(VpnAccount)):
        out.setdefault(a.firewall_id, []).append(a)
    return out


def link_accounts(identities: list[str], user_code: str, accounts: list[VpnAccount]) -> tuple[list[VpnAccount], bool]:
    """Tài khoản liên kết với rule + cờ 'mọi user của rule đã không còn / bị khóa'.

    Ưu tiên identity (user hoặc nhóm), dự phòng mã user trong tên (CHAU.NB ↔ chau.nb@…).
    """
    if not accounts:
        return [], False  # chưa đồng bộ tài khoản → không kết luận
    idents = {i.lower() for i in identities}
    linked = [a for a in accounts if a.username_key in idents
              or idents & {g.lower() for g in json.loads(a.groups_json or "[]")}]
    if not linked and user_code:
        code = user_code.lower()
        linked = [a for a in accounts if a.username_key.split("@")[0] == code]
    user_like = [i for i in idents if "@" in i]
    missing_users = [i for i in user_like if i not in {a.username_key for a in accounts}]
    gone = (bool(linked) and all(a.removed_at is not None or a.status.lower() != "active" for a in linked)) or \
           (not linked and bool(missing_users))
    return linked, gone


def rule_dict(r: VpnRule, fw_name: str, cls: dict, linked: list[VpnAccount]) -> dict:
    det = json.loads(r.detail_json or "{}")
    return {
        "id": r.id, "firewall_id": r.firewall_id, "firewall": fw_name, "rule_name": r.rule_name,
        "group_name": r.group_name, "position": r.position, "enabled": r.enabled, "action": r.action,
        "policy_type": r.policy_type, "log_traffic": r.log_traffic, "description": r.description,
        "src_zones": det.get("src_zones", []), "src_networks": det.get("src_networks", []),
        "identities": det.get("identities", []), "dst_zones": det.get("dst_zones", []),
        "dst_networks": det.get("dst_networks", []), "services": det.get("services", []),
        "schedule_name": r.schedule_name, "schedule_end": _d(r.schedule_end), "team": r.team,
        "user_code": r.user_code, "name_date": _d(r.name_date), "name_status": r.name_status,
        "expiry_date": _d(r.expiry_date), "expiry_source": r.expiry_source, "expiry_mismatch": r.expiry_mismatch,
        "status": cls["status"], "status_label": cls["label"], "days_left": cls["days_left"], "flags": cls["flags"],
        "accounts": [{"username": a.username, "display_name": a.display_name, "status": a.status,
                      "removed_at": _iso(a.removed_at)} for a in linked],
        "first_seen_at": _iso(r.first_seen_at), "last_seen_at": _iso(r.last_seen_at), "removed_at": _iso(r.removed_at),
    }


def list_rules(db: Session, *, firewall_id: int | None = None, status: str = "", team: str = "", q: str = "",
               date_from: dt.date | None = None, date_to: dt.date | None = None, include_removed: bool = False,
               today: dt.date | None = None) -> dict:
    today = today or expiry.today_vn()
    cfg = vpn_settings.get(db)
    th = cfg["expiring_days"]
    names = {f.id: f.name for f in db.scalars(select(Firewall))}
    accounts = _accounts_by_fw(db)
    stmt = select(VpnRule).order_by(VpnRule.firewall_id, VpnRule.position)
    if firewall_id:
        stmt = stmt.where(VpnRule.firewall_id == firewall_id)
    fw_scope = vpn_settings.scope_ids(db)
    if fw_scope is not None:  # chỉ firewall có VPN — áp dụng cả dashboard, email nhắc hạn, rà soát
        stmt = stmt.where(VpnRule.firewall_id.in_(fw_scope))
    if not include_removed:
        stmt = stmt.where(VpnRule.removed_at.is_(None))
    all_rows, teams = [], set()
    for r in db.scalars(stmt):
        linked, gone = link_accounts(json.loads(r.detail_json or "{}").get("identities", []), r.user_code,
                                     accounts.get(r.firewall_id, []))
        cls = expiry.classify(expiry_date=r.expiry_date, expiry_source=r.expiry_source, name_status=r.name_status,
                              enabled=r.enabled, accounts_gone=gone, today=today, threshold_days=th)
        all_rows.append(rule_dict(r, names.get(r.firewall_id, f"#{r.firewall_id}"), cls, linked))
        if r.team:
            teams.add(r.team)
    summary = {s: 0 for s in expiry.STATUSES}
    summary["mismatch"] = 0
    todo = {"expired_enabled", "user_gone", "expiring", "unreadable"}
    summary["todo"] = 0
    for x in all_rows:
        summary[x["status"]] += 1
        summary["mismatch"] += 1 if x["expiry_mismatch"] else 0
        # việc cần xử lý đếm theo MỌI cờ của rule (vd user không còn + hết hạn vẫn bật) để ô số khớp chip trên dòng
        for f in ("expired_enabled", "user_gone"):
            if f in x.get("flags", []) and x["status"] != f:
                summary[f] += 1
        summary["todo"] += 1 if (todo & ({x["status"]} | set(x.get("flags", []))) or x["expiry_mismatch"]) else 0
    rows = all_rows
    if status:  # nhiều giá trị, phân cách dấu phẩy; "mismatch" = cờ Lệch thời hạn
        wanted = set(status.split(","))
        rows = [x for x in rows if x["status"] in wanted or ("mismatch" in wanted and x["expiry_mismatch"])
                or wanted & {"expired_enabled", "user_gone"} & set(x.get("flags", []))]
    if team:
        rows = [x for x in rows if x["team"].lower() == team.lower()]
    if date_from:
        rows = [x for x in rows if x["expiry_date"] and x["expiry_date"] >= date_from.isoformat()]
    if date_to:
        rows = [x for x in rows if x["expiry_date"] and x["expiry_date"] <= date_to.isoformat()]
    if q:
        needle = q.lower().strip()
        rows = [x for x in rows if needle in " ".join([x["rule_name"], x["team"], x["user_code"], x["description"],
                                                         " ".join(x["identities"]), " ".join(x["dst_networks"])]).lower()]
    return {"rules": rows, "total": len(rows), "summary": summary, "teams": sorted(teams, key=str.lower),
            "today": today.isoformat(), "expiring_days": th, "statuses": expiry.STATUSES}


def changes(db: Session, *, firewall_id: int | None = None, rule_name: str = "", limit: int = 200) -> list[dict]:
    stmt = select(VpnRuleChange).order_by(desc(VpnRuleChange.id)).limit(limit)
    if firewall_id:
        stmt = stmt.where(VpnRuleChange.firewall_id == firewall_id)
    if rule_name:
        stmt = stmt.where(VpnRuleChange.rule_name == rule_name)
    return [{"id": c.id, "ts": _iso(c.ts), "firewall_id": c.firewall_id, "firewall": c.firewall_name,
             "rule_name": c.rule_name, "change_type": c.change_type, "actor": c.actor,
             "before": json.loads(c.before_json) if c.before_json else None,
             "after": json.loads(c.after_json) if c.after_json else None} for c in db.scalars(stmt)]


def sync_status(db: Session) -> list[dict]:
    names = {f.id: f.name for f in db.scalars(select(Firewall))}
    fw_scope = vpn_settings.scope_ids(db)
    return [{"firewall_id": s.firewall_id, "firewall": names.get(s.firewall_id, f"#{s.firewall_id}"),
             "synced_at": _iso(s.synced_at), "status": s.status, "error": s.error,
             "summary": json.loads(s.summary_json or "{}"), "duration_ms": s.duration_ms}
            for s in db.scalars(select(VpnSync).where(VpnSync.kind == "rules").order_by(VpnSync.firewall_id))
            if fw_scope is None or s.firewall_id in fw_scope]
