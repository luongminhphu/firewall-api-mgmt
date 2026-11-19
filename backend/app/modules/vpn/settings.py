"""Cấu hình module VPN (quản trị viên): ngưỡng "sắp hết hạn", Rule Group được đọc.

Lưu ở app_settings['vpn.settings'] (JSON). Rule Group chỉ được chọn trong VPN_RULE_GROUPS_ALLOWED (policy.py) —
giá trị lạ trong DB/env bị bỏ qua. Phase 5 bổ sung người nhận thông báo / đại diện team vào cùng chỗ.
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import AppSetting, Firewall
from ...integrations.sophos.policy import VPN_RULE_GROUPS_ALLOWED

log = logging.getLogger("vpn.settings")
KEY = "vpn.settings"


def _allowed_groups(values) -> list[str]:
    out = [g for g in dict.fromkeys(str(v).strip() for v in values) if g in VPN_RULE_GROUPS_ALLOWED]
    return out


def defaults() -> dict:
    groups = _allowed_groups(settings.VPN_RULE_GROUPS.split(",")) or list(VPN_RULE_GROUPS_ALLOWED[:1])
    # firewall_ids: firewall có cấu hình VPN cần đồng bộ; rỗng = mọi firewall đang bật (hành vi cũ)
    return {"expiring_days": max(1, min(365, settings.VPN_EXPIRING_DAYS)), "rule_groups": groups, "firewall_ids": []}


def get(db: Session) -> dict:
    cur = defaults()
    row = db.get(AppSetting, KEY)
    if row and row.value:
        try:
            saved = json.loads(row.value)
        except ValueError:
            saved = {}
        if isinstance(saved.get("expiring_days"), int):
            cur["expiring_days"] = max(1, min(365, saved["expiring_days"]))
        groups = _allowed_groups(saved.get("rule_groups") or [])
        if groups:
            cur["rule_groups"] = groups
        if isinstance(saved.get("firewall_ids"), list):
            cur["firewall_ids"] = sorted({int(i) for i in saved["firewall_ids"] if isinstance(i, int)})
    return {**cur, "allowed_rule_groups": list(VPN_RULE_GROUPS_ALLOWED),
            "updated_by": row.updated_by if row else "", "updated_at": row.updated_at.isoformat()
            if row and row.updated_at else None}


def update(db: Session, data: dict, *, actor: str, client_ip: str) -> dict:
    cur = get(db)
    new = {"expiring_days": cur["expiring_days"], "rule_groups": cur["rule_groups"], "firewall_ids": cur["firewall_ids"]}
    if data.get("expiring_days") is not None:
        days = data["expiring_days"]
        if not isinstance(days, int) or not 1 <= days <= 365:
            raise AppError(400, "Ngưỡng 'sắp hết hạn' phải là số ngày từ 1 đến 365")
        new["expiring_days"] = days
    if data.get("rule_groups") is not None:
        wanted = [str(g).strip() for g in data["rule_groups"]]
        bad = [g for g in wanted if g not in VPN_RULE_GROUPS_ALLOWED]
        if bad or not wanted:
            raise AppError(400, f"Rule Group chỉ được chọn trong danh sách cho phép: {', '.join(VPN_RULE_GROUPS_ALLOWED)}"
                                + (f" (không chấp nhận: {', '.join(b[:60] for b in bad)})" if bad else ""))
        new["rule_groups"] = _allowed_groups(wanted)
    if data.get("firewall_ids") is not None:
        ids = sorted({int(i) for i in data["firewall_ids"]})
        known = set(db.scalars(select(Firewall.id).where(Firewall.id.in_(ids)))) if ids else set()
        if set(ids) - known:
            raise AppError(400, f"Firewall không tồn tại: {', '.join(map(str, sorted(set(ids) - known)))}")
        new["firewall_ids"] = ids
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value = json.dumps(new, ensure_ascii=False)
    row.updated_by = actor
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    audit(db, action="settings_cud", fw=None, target="vpn", result="ok", actor=actor, client_ip=client_ip,
          message=f"Ngưỡng sắp hết hạn {new['expiring_days']} ngày · Rule Group {', '.join(new['rule_groups'])}"
                  f" · firewall có VPN: {', '.join(map(str, new['firewall_ids'])) or 'mọi firewall đang bật'}")
    db.commit()
    return get(db)


def scope_ids(db: Session) -> set[int] | None:
    """Firewall thuộc phạm vi VPN (đã chọn trong cấu hình); None = chưa chọn → mọi firewall."""
    ids = get(db)["firewall_ids"]
    return set(ids) if ids else None


def sync_firewalls(db: Session, wanted: list[int] | None = None) -> list[Firewall]:
    """Firewall cần đồng bộ VPN: đang bật ∩ phạm vi VPN (∩ danh sách người dùng chọn, nếu có)."""
    scope = scope_ids(db)
    stmt = select(Firewall).where(Firewall.enabled.is_(True)).order_by(Firewall.id)
    fws = [f for f in db.scalars(stmt) if scope is None or f.id in scope]
    if wanted:
        outside = [i for i in wanted if scope is not None and i not in scope]
        if outside:
            raise AppError(400, "Firewall chưa được chọn là có VPN (Cài đặt › VPN): "
                                + ", ".join(map(str, outside)))
        fws = [f for f in fws if f.id in set(wanted)]
    return fws
