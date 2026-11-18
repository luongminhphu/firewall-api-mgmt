"""Rà soát quyền truy cập VPN định kỳ (ISO/IEC 27001:2022 A.5.18) — docs/architecture.md §15.

- Đợt rà soát chụp ảnh rule VPN + tài khoản mồ côi tại lúc mở (bằng chứng không đổi theo đồng bộ sau).
- Đại diện team (vpn_team_contacts) quyết định mục thuộc team mình; còn lại (không team / team chưa có đại diện /
  tài khoản mồ côi) thuộc Infra (quản trị viên). Quản trị viên quyết định thay được — ghi rõ on_behalf.
- Mọi quyết định + mở/đóng đợt ghi review_decisions nối chuỗi băm.
- App vẫn CHỈ ĐỌC firewall: "Thu hồi" chỉ tạo danh sách cho Infra.
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core import hashchain
from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import (
    AppSetting, ReviewCampaign, ReviewDecision, ReviewItem, VpnAccount, VpnRule, VpnTeamContact,
)
from ..notify import outbox, planner
from ..vpn import expiry
from ..vpn import rules as vpn_rules

log = logging.getLogger("review")
SETTINGS_KEY = "review.settings"
DEFAULTS = {"auto_quarterly": True, "due_days": 14, "remind_days": 3}
DECISIONS = {"keep": "Còn cần", "revoke": "Thu hồi", "change": "Cần điều chỉnh"}
LABELS = {**DECISIONS, "pending": "Chưa quyết định", "no_response": "Không phản hồi"}
AUTO_OPEN_WINDOW_DAYS = 15  # chỉ tự mở trong 15 ngày đầu quý (triển khai giữa quý không tự mở bất ngờ)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime | None) -> str | None:
    return None if t is None else (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).isoformat()


def quarter_key(d: dt.date) -> tuple[str, str, dt.date]:
    q = (d.month - 1) // 3 + 1
    return f"{d.year}-Q{q}", f"Rà soát quyền VPN Q{q}/{d.year}", dt.date(d.year, 3 * (q - 1) + 1, 1)


# ------------------------------------------------------------------ cấu hình
def get_settings(db: Session) -> dict:
    cfg = dict(DEFAULTS)
    row = db.get(AppSetting, SETTINGS_KEY)
    if row and row.value:
        try:
            cfg.update({k: v for k, v in json.loads(row.value).items() if k in DEFAULTS})
        except ValueError:
            pass
    return cfg


def update_settings(db: Session, data: dict, *, actor: str, client_ip: str) -> dict:
    cfg = get_settings(db)
    if data.get("auto_quarterly") is not None:
        cfg["auto_quarterly"] = bool(data["auto_quarterly"])
    for k, lo, hi in (("due_days", 1, 90), ("remind_days", 0, 30)):
        if data.get(k) is not None:
            if not isinstance(data[k], int) or not lo <= data[k] <= hi:
                raise AppError(400, f"{k} phải từ {lo} đến {hi} ngày")
            cfg[k] = data[k]
    row = db.get(AppSetting, SETTINGS_KEY) or AppSetting(key=SETTINGS_KEY)
    row.value, row.updated_by, row.updated_at = json.dumps(cfg), actor, _now()
    db.merge(row)
    audit(db, action="settings_cud", fw=None, target="review", result="ok", actor=actor, client_ip=client_ip,
          message=f"Rà soát {'tự mở hằng quý' if cfg['auto_quarterly'] else 'mở tay'} · hạn {cfg['due_days']} ngày")
    db.commit()
    return cfg


# ------------------------------------------------------------------ người rà soát
def contact_teams(db: Session, email: str) -> set[str]:
    """team_key mà `email` là đại diện."""
    e = (email or "").lower()
    return {c.team_key for c in db.scalars(select(VpnTeamContact)) if e and e in c.emails.split(",")}


def is_contact(db: Session, email: str) -> bool:
    return bool(contact_teams(db, email))


def _log(db: Session, rows: list[ReviewDecision]) -> None:
    hashchain.append(db, ReviewDecision, rows)  # commit trong khóa chuỗi băm


# ------------------------------------------------------------------ mở đợt
def open_campaign(db: Session, *, actor: str, client_ip: str = "", period_key: str | None = None,
                  name: str | None = None, today: dt.date | None = None) -> ReviewCampaign:
    today = today or expiry.today_vn()
    if db.scalar(select(ReviewCampaign).where(ReviewCampaign.status == "open")):
        raise AppError(409, "Đang có một đợt rà soát chưa đóng — đóng đợt đó trước khi mở đợt mới")
    if period_key is None:
        period_key = f"manual-{_now():%Y%m%d%H%M%S}"
        name = name or f"Rà soát quyền VPN {today:%d/%m/%Y}"
    if db.scalar(select(ReviewCampaign).where(ReviewCampaign.period_key == period_key)):
        raise AppError(409, f"Đợt rà soát {period_key} đã tồn tại")
    cfg = get_settings(db)
    camp = ReviewCampaign(period_key=period_key, name=name or period_key, status="open",
                          due_date=today + dt.timedelta(days=cfg["due_days"]), created_by=actor, created_at=_now())
    db.add(camp)
    db.flush()
    contacts = {c.team_key for c in db.scalars(select(VpnTeamContact))}
    rules = vpn_rules.list_rules(db, today=today)["rules"]
    linked: set[tuple[int, str]] = set()
    items = []
    for r in rules:
        team_key = (r["team"] or "").lower()
        for a in r["accounts"]:
            linked.add((r["firewall_id"], a["username"].lower()))
        snap = {k: r[k] for k in ("rule_name", "firewall", "group_name", "team", "user_code", "enabled",
                                  "expiry_date", "expiry_source", "status", "status_label", "days_left", "identities",
                                  "dst_zones", "dst_networks", "services", "schedule_name", "src_zones",
                                  "src_networks", "description")}
        snap["accounts"] = [a["username"] for a in r["accounts"]]
        items.append(ReviewItem(campaign_id=camp.id, kind="rule", firewall_id=r["firewall_id"],
                                firewall_name=r["firewall"], ref_key=r["rule_name"].lower()[:255],
                                title=r["rule_name"][:255], team=r["team"],
                                scope=team_key if team_key in contacts else "infra",
                                snapshot_json=json.dumps(snap, ensure_ascii=False)))
    names = {i.firewall_id: i.firewall_name for i in items}
    for a in db.scalars(select(VpnAccount).where(VpnAccount.removed_at.is_(None))):
        if not (a.has_sslvpn or a.has_ipsec) or (a.firewall_id, a.username_key) in linked:
            continue
        snap = {"username": a.username, "display_name": a.display_name, "groups": json.loads(a.groups_json or "[]"),
                "has_sslvpn": a.has_sslvpn, "has_ipsec": a.has_ipsec, "status": a.status,
                "sslvpn_policy": a.sslvpn_policy}
        items.append(ReviewItem(campaign_id=camp.id, kind="orphan_account", firewall_id=a.firewall_id,
                                firewall_name=names.get(a.firewall_id, f"#{a.firewall_id}"), ref_key=a.username_key,
                                title=a.username[:255], team="", scope="infra",
                                snapshot_json=json.dumps(snap, ensure_ascii=False)))
    db.add_all(items)
    audit(db, action="review", fw=None, target=camp.period_key, result="ok", actor=actor, client_ip=client_ip,
          message=f"Mở đợt rà soát '{camp.name}' · {len(items)} mục · hạn {camp.due_date:%d/%m/%Y}")
    db.flush()
    _log(db, [ReviewDecision(ts=_now(), campaign_id=camp.id, decision="open", actor=actor,
                             comment=f"{len(items)} mục; hạn {camp.due_date.isoformat()}")])
    _notify_open(db, camp)
    return camp


def _scope_counts(db: Session, cid: int, decision: str | None = None) -> dict[str, int]:
    stmt = select(ReviewItem.scope, func.count()).where(ReviewItem.campaign_id == cid).group_by(ReviewItem.scope)
    if decision:
        stmt = stmt.where(ReviewItem.decision == decision)
    return dict(db.execute(stmt).all())


def _link() -> str:
    return f"\nMở app: {settings.APP_BASE_URL.rstrip('/')}/#review\n" if settings.APP_BASE_URL else ""


def _notify_open(db: Session, camp: ReviewCampaign) -> None:
    contacts = {c.team_key: (c.team, [e for e in c.emails.split(",") if e]) for c in db.scalars(select(VpnTeamContact))}
    infra = planner.get_cfg(db).get("infra_emails") or []
    msgs = []
    for scope, n in _scope_counts(db, camp.id).items():
        if scope == "infra":
            to, who = infra, "Infra"
        else:
            team, to = contacts.get(scope, (scope, []))
            who = f"đại diện team {team}"
        if not to:
            continue
        msgs.append({"dedupe_key": f"review_open:{camp.id}:{scope}", "kind": "review_open", "to": to,
                     "subject": f"[Rà soát VPN] {camp.name}: {n} quyền cần xác nhận trước {camp.due_date:%d/%m/%Y}",
                     "body": f"Kính gửi {who},\n\nĐợt '{camp.name}' (ISO 27001 — rà soát quyền truy cập) đã mở. Có {n} "
                             f"quyền truy cập VPN cần bạn xác nhận: Còn cần / Thu hồi / Cần điều chỉnh.\n"
                             f"Hạn hoàn thành: {camp.due_date:%d/%m/%Y}.\n{_link()}\nĐăng nhập bằng tài khoản Microsoft "
                             "công ty, mở tab 'Rà soát'.\n\n(Email tự động — vui lòng không trả lời.)\n",
                     "ref": {"campaign_id": camp.id, "scope": scope}})
    outbox.enqueue(db, msgs)


# ------------------------------------------------------------------ quyết định
def decide(db: Session, item_id: int, decision: str, comment: str, *, p: dict, client_ip: str = "") -> dict:
    item = db.get(ReviewItem, item_id)
    if item is None:
        raise AppError(404, "Không tìm thấy mục rà soát")
    camp = db.get(ReviewCampaign, item.campaign_id)
    if camp.status != "open":
        raise AppError(409, "Đợt rà soát đã đóng — không sửa được quyết định")
    if decision not in DECISIONS:
        raise AppError(400, "Quyết định chỉ nhận: keep (còn cần), revoke (thu hồi), change (cần điều chỉnh)")
    comment = (comment or "").strip()
    if decision in ("revoke", "change") and len(comment) < 5:
        raise AppError(400, "Thu hồi / điều chỉnh cần ghi lý do (tối thiểu 5 ký tự)")
    mine = item.scope in contact_teams(db, p["user"])
    is_admin = p["role"] == "admin"
    if not (mine or is_admin):
        raise AppError(403, "Mục này không thuộc team bạn đại diện")
    on_behalf = is_admin and not mine and item.scope != "infra"
    item.decision, item.comment = decision, comment[:2000]
    item.decided_by, item.decided_at, item.on_behalf = p["user"], _now(), on_behalf
    audit(db, action="review", fw=None, target=item.title[:255], result=decision, actor=p["user"], client_ip=client_ip,
          message=f"{camp.name}: {LABELS[decision]}{' (Infra quyết định thay)' if on_behalf else ''}"
                  + (f" — {comment}" if comment else ""))
    db.flush()
    _log(db, [ReviewDecision(ts=_now(), campaign_id=camp.id, item_id=item.id, item_title=item.title,
                             decision=decision, comment=comment[:2000], actor=p["user"], on_behalf=on_behalf)])
    return item_dict(item)


# ------------------------------------------------------------------ đóng đợt
def close_campaign(db: Session, cid: int, *, actor: str, client_ip: str = "") -> dict:
    camp = db.get(ReviewCampaign, cid)
    if camp is None:
        raise AppError(404, "Không tìm thấy đợt rà soát")
    if camp.status != "open":
        raise AppError(409, "Đợt rà soát đã đóng")
    now = _now()
    pending = list(db.scalars(select(ReviewItem).where(ReviewItem.campaign_id == cid, ReviewItem.decision == "pending")))
    logs = []
    for it in pending:
        it.decision, it.decided_at, it.decided_by = "no_response", now, ""
        logs.append(ReviewDecision(ts=now, campaign_id=cid, item_id=it.id, item_title=it.title,
                                   decision="no_response", actor=actor))
    camp.status, camp.closed_by, camp.closed_at = "closed", actor, now
    s = summary(db, cid)
    logs.append(ReviewDecision(ts=now, campaign_id=cid, decision="close", actor=actor,
                               comment=json.dumps(s["totals"], ensure_ascii=False)))
    audit(db, action="review", fw=None, target=camp.period_key, result="ok", actor=actor, client_ip=client_ip,
          message=f"Đóng đợt '{camp.name}' · {json.dumps(s['totals'], ensure_ascii=False)}")
    db.flush()
    _log(db, logs)
    infra = planner.get_cfg(db).get("infra_emails") or []
    t = s["totals"]
    if infra:
        outbox.enqueue(db, [{"dedupe_key": f"review_closed:{cid}", "kind": "review_closed", "to": infra,
                             "subject": f"[Rà soát VPN] Đã đóng {camp.name}: {t['revoke']} thu hồi, {t['change']} điều chỉnh",
                             "body": f"Đợt '{camp.name}' đã đóng bởi {actor}.\nCòn cần: {t['keep']} · Thu hồi: {t['revoke']} · "
                                     f"Cần điều chỉnh: {t['change']} · Không phản hồi: {t['no_response']}.\n\n"
                                     "Danh sách cần thu hồi / điều chỉnh: xuất CSV trong tab Rà soát. App không tự sửa "
                                     f"firewall — Infra xử lý trên Sophos.\n{_link()}\n(Email tự động.)\n",
                             "ref": {"campaign_id": cid}}])
    return campaign_dict(camp, db)


# ------------------------------------------------------------------ lập lịch
def tick(today: dt.date | None = None) -> dict:
    """Vòng định kỳ: tự mở đợt đầu quý (nếu bật), nhắc mục chưa quyết định, báo quá hạn."""
    from ...core.db import SessionLocal

    today = today or expiry.today_vn()
    out = {"opened": None, "reminders": 0, "overdue": 0}
    with SessionLocal() as db:
        cfg = get_settings(db)
        key, name, q_start = quarter_key(today)
        has_data = db.scalar(select(func.count()).select_from(VpnAccount)) or \
            db.scalar(select(func.count()).select_from(VpnRule))  # chưa đồng bộ VPN lần nào → không mở đợt rỗng
        if cfg["auto_quarterly"] and has_data and (today - q_start).days < AUTO_OPEN_WINDOW_DAYS \
                and not db.scalar(select(ReviewCampaign).where(ReviewCampaign.period_key == key)) \
                and not db.scalar(select(ReviewCampaign).where(ReviewCampaign.status == "open")):
            camp = open_campaign(db, actor="he-thong", period_key=key, name=name, today=today)
            out["opened"] = camp.period_key
        contacts = {c.team_key: [e for e in c.emails.split(",") if e] for c in db.scalars(select(VpnTeamContact))}
        infra = planner.get_cfg(db).get("infra_emails") or []
        for camp in db.scalars(select(ReviewCampaign).where(ReviewCampaign.status == "open")):
            left = (camp.due_date - today).days
            msgs = []
            if 0 <= left <= cfg["remind_days"]:
                for scope, n in _scope_counts(db, camp.id, "pending").items():
                    to = infra if scope == "infra" else contacts.get(scope, [])
                    if to:
                        msgs.append({"dedupe_key": f"review_remind:{camp.id}:{scope}", "kind": "review_remind", "to": to,
                                     "subject": f"[Rà soát VPN] Còn {n} quyền chưa xác nhận — hạn {camp.due_date:%d/%m/%Y}",
                                     "body": f"Đợt '{camp.name}' còn {n} quyền truy cập VPN chưa được xác nhận. Hạn hoàn thành "
                                             f"{camp.due_date:%d/%m/%Y} (còn {left} ngày).\n{_link()}\n(Email tự động.)\n",
                                     "ref": {"campaign_id": camp.id, "scope": scope}})
            elif left < 0 and infra:
                pend = _scope_counts(db, camp.id, "pending")
                if pend:
                    lines = "\n".join(f"- {s}: {n} mục" for s, n in sorted(pend.items()))
                    msgs.append({"dedupe_key": f"review_overdue:{camp.id}", "kind": "review_overdue", "to": infra,
                                 "subject": f"[Rà soát VPN] Quá hạn: {camp.name} còn {sum(pend.values())} mục chưa xác nhận",
                                 "body": f"Đợt '{camp.name}' đã quá hạn {camp.due_date:%d/%m/%Y}. Mục chưa xác nhận theo "
                                         f"phạm vi:\n{lines}\n\nĐề nghị Infra nhắc trực tiếp hoặc đóng đợt (mục chưa quyết "
                                         f"định sẽ ghi 'Không phản hồi').\n{_link()}\n(Email tự động.)\n",
                                 "ref": {"campaign_id": camp.id}})
            q = outbox.enqueue(db, msgs)
            out["reminders" if left >= 0 else "overdue"] += q
    return out


# ------------------------------------------------------------------ đọc
def item_dict(it: ReviewItem) -> dict:
    return {"id": it.id, "campaign_id": it.campaign_id, "kind": it.kind, "firewall_id": it.firewall_id,
            "firewall": it.firewall_name, "title": it.title, "team": it.team, "scope": it.scope,
            "snapshot": json.loads(it.snapshot_json or "{}"), "decision": it.decision,
            "decision_label": LABELS.get(it.decision, it.decision), "comment": it.comment,
            "decided_by": it.decided_by, "decided_at": _iso(it.decided_at), "on_behalf": it.on_behalf}


def summary(db: Session, cid: int) -> dict:
    rows = db.execute(select(ReviewItem.scope, ReviewItem.decision, func.count()).where(ReviewItem.campaign_id == cid)
                      .group_by(ReviewItem.scope, ReviewItem.decision)).all()
    totals = {k: 0 for k in ("pending", "keep", "revoke", "change", "no_response")}
    scopes: dict[str, dict] = {}
    for scope, dec, n in rows:
        totals[dec] = totals.get(dec, 0) + n
        sc = scopes.setdefault(scope, {k: 0 for k in totals})
        sc[dec] = sc.get(dec, 0) + n
    names = {c.team_key: c.team for c in db.scalars(select(VpnTeamContact))}
    by_scope = [{"scope": s, "name": "Infra" if s == "infra" else names.get(s, s), **c,
                 "total": sum(c.values())} for s, c in sorted(scopes.items(), key=lambda x: (x[0] != "infra", x[0]))]
    return {"totals": {**totals, "total": sum(totals.values())}, "by_scope": by_scope}


def campaign_dict(c: ReviewCampaign, db: Session) -> dict:
    return {"id": c.id, "period_key": c.period_key, "name": c.name, "status": c.status,
            "due_date": c.due_date.isoformat(), "created_by": c.created_by, "created_at": _iso(c.created_at),
            "closed_by": c.closed_by, "closed_at": _iso(c.closed_at), **summary(db, c.id)}


def campaigns(db: Session) -> list[dict]:
    return [campaign_dict(c, db) for c in db.scalars(select(ReviewCampaign).order_by(ReviewCampaign.id.desc()))]


def items(db: Session, cid: int, *, scopes: set[str] | None = None, decision: str = "", q: str = "") -> list[dict]:
    stmt = select(ReviewItem).where(ReviewItem.campaign_id == cid).order_by(ReviewItem.scope, ReviewItem.kind,
                                                                            ReviewItem.title)
    if scopes is not None:
        stmt = stmt.where(ReviewItem.scope.in_(scopes or {"__none__"}))
    if decision:
        stmt = stmt.where(ReviewItem.decision == decision)
    rows = [item_dict(i) for i in db.scalars(stmt)]
    if q:
        n = q.lower().strip()
        rows = [r for r in rows if n in json.dumps(r, ensure_ascii=False).lower()]
    return rows
