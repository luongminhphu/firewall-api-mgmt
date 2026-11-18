"""Tài khoản VPN (B1, CHỈ ĐỌC): đọc User / UserGroup / SSL VPN / IPsec remote access, upsert theo (firewall, user).

- Không ghi gì lên firewall (policy.py chỉ cho Get các entity này).
- Dữ liệu đã lọc allowlist ở integrations/sophos/sanitize.py — không có mật khẩu/hash/khóa.
- Tài khoản mất khỏi firewall: removed_at = thời điểm phát hiện (không xóa); xuất hiện lại: removed_at = NULL.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core import jobs
from ...core.audit import audit
from ...core.config import settings
from ...core.models import Firewall, VpnAccount, VpnSync
from ...integrations.sophos import SophosAuthError, SophosError
from ..firewalls.service import client_for

log = logging.getLogger("vpn.accounts")
NO_POLICY = {"", "no policy applied", "none"}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime | None) -> str | None:
    if t is None:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).isoformat()


def compute_access(users: list[dict], groups: list[dict], ssl: list[dict], ipsec: list[dict]) -> list[dict]:
    """Ghép quyền VPN cho từng user (hàm thuần — test được không cần firewall).

    has_sslvpn: user có SSL VPN policy riêng, hoặc thuộc nhóm có policy, hoặc user/nhóm là thành viên tunnel policy.
    has_ipsec : user/nhóm nằm trong AllowedUser của kết nối IPsec kiểu RemoteAccess.
    """
    low = str.lower
    members_of = {low(g["name"]): {low(m) for m in g["members"]} for g in groups}
    group_policy = {low(g["name"]) for g in groups if low(g.get("sslvpn_policy") or "") not in NO_POLICY}
    ssl_members = {low(m) for p in ssl for m in p["members"]}
    ipsec_allowed = {low(u) for c in ipsec if low(c.get("connection_type") or "") == "remoteaccess"
                     for u in c["allowed_users"]}
    out = []
    for u in users:
        key = low(u["username"])
        ugroups = sorted({g for g, mem in members_of.items() if key in mem} |
                         ({low(u["group"])} if u.get("group") else set()))
        names = {low(g["name"]): g["name"] for g in groups}
        out.append({
            **u,
            "username_key": key,
            "groups": [names.get(g, g) for g in ugroups],
            "has_sslvpn": (low(u.get("sslvpn_policy") or "") not in NO_POLICY or key in ssl_members
                           or any(g in ssl_members or g in group_policy for g in ugroups)),
            "has_ipsec": key in ipsec_allowed or any(g in ipsec_allowed for g in ugroups),
        })
    return out


def _fetch(fw: Firewall) -> list[dict]:
    t = settings.VPN_SCAN_TIMEOUT
    with client_for(fw) as cli:
        users = cli.get_users(timeout=t)
        groups = cli.get_user_groups(timeout=t)
        ssl = cli.get_sslvpn_policies(timeout=t)
        ipsec = cli.get_ipsec_connections(timeout=t)
    return compute_access(users, groups, ssl, ipsec)


def _upsert(db: Session, fw: Firewall, accounts: list[dict], now: dt.datetime) -> dict:
    rows = {r.username_key: r for r in db.scalars(select(VpnAccount).where(VpnAccount.firewall_id == fw.id))}
    seen: set[str] = set()
    c = {"total": len(accounts), "new": 0, "updated": 0, "removed": 0, "restored": 0}
    for a in accounts:
        key = a["username_key"]
        if key in seen:
            continue
        seen.add(key)
        r = rows.get(key)
        if r is None:
            r = VpnAccount(firewall_id=fw.id, username_key=key, first_seen_at=now)
            db.add(r)
            c["new"] += 1
        else:
            if r.removed_at is not None:
                c["restored"] += 1
            c["updated"] += 1
        r.username = a["username"]
        r.display_name = a["display_name"][:255]
        r.user_type = a["user_type"][:32]
        r.email = (a["emails"][0] if a["emails"] else "")[:255]
        r.groups_json = json.dumps(a["groups"], ensure_ascii=False)
        r.sslvpn_policy = a["sslvpn_policy"][:160]
        r.status = a["status"][:32]
        r.has_sslvpn = bool(a["has_sslvpn"])
        r.has_ipsec = bool(a["has_ipsec"])
        r.description = a["description"]
        r.last_seen_at = now
        r.removed_at = None
    for key, r in rows.items():
        if key not in seen and r.removed_at is None:
            r.removed_at = now
            c["removed"] += 1
    return c


def _save_sync(db: Session, fw_id: int, *, status: str, error: str = "", summary: dict | None = None,
               ms: int = 0) -> None:
    row = db.scalar(select(VpnSync).where(VpnSync.firewall_id == fw_id, VpnSync.kind == "accounts"))
    if row is None:
        row = VpnSync(firewall_id=fw_id, kind="accounts")
        db.add(row)
    row.synced_at = _now()
    row.status, row.error = status, error[:2000]
    if summary is not None:
        row.summary_json = json.dumps(summary)
    row.duration_ms = ms


def sync_firewall(db: Session, fw: Firewall, *, actor: str = "he-thong", client_ip: str = "") -> dict:
    """Đồng bộ tài khoản của MỘT firewall. Không ném lỗi firewall ra ngoài — ghi vào kết quả + vpn_sync."""
    base = {"firewall_id": fw.id, "firewall": fw.name}
    with jobs.lock(f"vpn-sync:{fw.id}", blocking=False) as got:
        if not got:
            return {**base, "ok": False, "error": "Đang có lượt đồng bộ khác cho firewall này"}
        t0 = time.monotonic()
        try:
            accounts = _fetch(fw)
        except (SophosError, SophosAuthError, ValueError) as exc:
            ms = int((time.monotonic() - t0) * 1000)
            _save_sync(db, fw.id, status="error", error=str(exc), ms=ms)
            audit(db, action="vpn_sync", fw=fw, target="accounts", result="error", message=str(exc),
                  actor=actor, client_ip=client_ip, code=getattr(exc, "code", ""))
            db.commit()
            return {**base, "ok": False, "error": str(exc)}
        summary = _upsert(db, fw, accounts, _now())
        ms = int((time.monotonic() - t0) * 1000)
        _save_sync(db, fw.id, status="ok", summary=summary, ms=ms)
        audit(db, action="vpn_sync", fw=fw, target="accounts", result="ok", actor=actor, client_ip=client_ip,
              message=(f"{summary['total']} tài khoản · mới {summary['new']} · mất {summary['removed']} · "
                       f"xuất hiện lại {summary['restored']}"))
        db.commit()
        return {**base, "ok": True, "summary": summary, "ms": ms}


def sync_all() -> list[dict]:
    """Lượt định kỳ (core.jobs.every): mọi firewall đang bật."""
    from ...core.db import SessionLocal

    out = []
    with SessionLocal() as db:
        for fw in db.scalars(select(Firewall).where(Firewall.enabled.is_(True))).all():
            out.append(sync_firewall(db, fw))
    return out


# --------------------------------------------------------------------- đọc
def account_dict(r: VpnAccount, fw_name: str) -> dict:
    return {
        "id": r.id, "firewall_id": r.firewall_id, "firewall": fw_name, "username": r.username,
        "display_name": r.display_name, "user_type": r.user_type, "email": r.email,
        "groups": json.loads(r.groups_json or "[]"), "sslvpn_policy": r.sslvpn_policy, "status": r.status,
        "enabled": r.status.lower() == "active", "has_sslvpn": r.has_sslvpn, "has_ipsec": r.has_ipsec,
        "has_vpn": r.has_sslvpn or r.has_ipsec, "description": r.description,
        "first_seen_at": _iso(r.first_seen_at), "last_seen_at": _iso(r.last_seen_at),
        "removed_at": _iso(r.removed_at),
    }


def list_accounts(db: Session, *, firewall_id: int | None = None, q: str = "", scope: str = "vpn",
                  state: str = "present") -> list[dict]:
    stmt = select(VpnAccount).order_by(VpnAccount.username_key)
    if firewall_id:
        stmt = stmt.where(VpnAccount.firewall_id == firewall_id)
    if state == "present":
        stmt = stmt.where(VpnAccount.removed_at.is_(None))
    elif state == "removed":
        stmt = stmt.where(VpnAccount.removed_at.is_not(None))
    if scope == "vpn":
        stmt = stmt.where(VpnAccount.has_sslvpn.is_(True) | VpnAccount.has_ipsec.is_(True))
    names = {f.id: f.name for f in db.scalars(select(Firewall))}
    rows = [account_dict(r, names.get(r.firewall_id, f"#{r.firewall_id}")) for r in db.scalars(stmt)]
    if q:
        needle = q.lower().strip()
        rows = [r for r in rows if needle in " ".join(
            [r["username"], r["display_name"], r["email"], " ".join(r["groups"]), r["sslvpn_policy"]]).lower()]
    return rows


def sync_status(db: Session) -> list[dict]:
    names = {f.id: f.name for f in db.scalars(select(Firewall))}
    out = []
    for s in db.scalars(select(VpnSync).where(VpnSync.kind == "accounts").order_by(VpnSync.firewall_id)):
        out.append({"firewall_id": s.firewall_id, "firewall": names.get(s.firewall_id, f"#{s.firewall_id}"),
                    "synced_at": _iso(s.synced_at), "status": s.status, "error": s.error,
                    "summary": json.loads(s.summary_json or "{}"), "duration_ms": s.duration_ms})
    return out
