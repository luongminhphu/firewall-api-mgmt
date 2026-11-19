"""Một lượt đồng bộ VPN cho một firewall: tài khoản (B1) rồi rule thời hạn (B2) — rule liên kết với tài khoản vừa đọc."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ...core.models import Firewall
from . import accounts, rules

KINDS = ("all", "accounts", "rules")


def sync_firewall(db: Session, fw: Firewall, *, kind: str = "all", actor: str = "he-thong",
                  client_ip: str = "") -> dict:
    out: dict = {"firewall_id": fw.id, "firewall": fw.name, "ok": True}
    errors = []
    if kind in ("all", "accounts"):
        a = accounts.sync_firewall(db, fw, actor=actor, client_ip=client_ip)
        out["summary"] = a.get("summary")  # tài khoản — giữ khóa của v1.8.0
        if not a["ok"]:
            errors.append(f"Tài khoản: {a['error']}")
    if kind in ("all", "rules"):
        r = rules.sync_firewall(db, fw, actor=actor, client_ip=client_ip)
        out["rules"] = r.get("summary")
        if not r["ok"]:
            errors.append(f"Rule: {r['error']}")
    if errors:
        out["ok"] = False
        out["error"] = " · ".join(errors)
    return out


def sync_all() -> list[dict]:
    """Lượt định kỳ (core.jobs.every, một pod/vòng): firewall đang bật thuộc phạm vi VPN (Cài đặt › VPN)."""
    from ...core.db import SessionLocal
    from . import settings as vpn_settings

    with SessionLocal() as db:
        return [sync_firewall(db, fw) for fw in vpn_settings.sync_firewalls(db)]
