"""F2 — email drift (sửa SCANPORT GROUP trực tiếp trên WebAdmin) CHỈ khi thời điểm drift ngoài giờ hành chính.

Con trỏ AppSetting `alerts.drift` {"cursor": id} (khóa riêng, không đụng `alerts.state` của job fw-health) luôn tiến
kể cả khi cảnh báo tắt → bật lại không xả lịch sử. Mỗi batch_id một email, dedupe `drift:<batch_id>`.
"""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import func
from sqlalchemy.orm import Session

from ...core.config import settings
from ...core.models import AppSetting, GroupChange
from ..autoblock import settings as ab_settings
from . import outbox, planner

KEY = "alerts.drift"
MAX_LINES = 50
VN = dt.timezone(dt.timedelta(hours=7))


def _mail(batch_id: str, rows: list[GroupChange], reason: str, to: list[str]) -> dict:
    first = rows[0]
    ts = first.ts if first.ts.tzinfo else first.ts.replace(tzinfo=dt.timezone.utc)
    lines = [f"{'+' if r.change_type == 'drift_add' else '−'} {r.value or r.object_name}"
             + (f" ({r.object_name})" if r.value and r.object_name and r.value != r.object_name else "") for r in rows]
    more = f"\n… và {len(lines) - MAX_LINES} dòng khác" if len(lines) > MAX_LINES else ""
    link = (f"\nXem Lịch sử thay đổi: {settings.APP_BASE_URL.rstrip('/')}/#changes?type=drift&fw={first.firewall_id}"
            if settings.APP_BASE_URL else "")
    body = (f"Phát hiện thay đổi trực tiếp trên WebAdmin, không qua SOC Rapid Block.\n\n"
            f"Firewall: {first.firewall_name}\nGroup: {first.group_name}\n"
            f"Thời điểm: {ts.astimezone(VN).strftime('%H:%M %d/%m/%Y')} (giờ VN) — {reason}\n\n"
            "Thay đổi (+ thêm / − bớt):\n" + "\n".join(lines[:MAX_LINES]) + more + "\n\n"
            "Nếu không phải thay đổi đã lên kế hoạch, kiểm tra ngay trên WebAdmin." + link
            + "\n\n(Email tự động — vui lòng không trả lời.)\n")
    return {"dedupe_key": f"drift:{batch_id}", "kind": "drift", "to": to,
            "subject": f"[Firewall] Thay đổi ngoài giờ trên {first.group_name}: {first.firewall_name}",
            "body": body, "ref": {"firewall_id": first.firewall_id, "batch_id": batch_id}}


def run(db: Session) -> int:
    """Một bước của run_cycle. Trả số email đã xếp hàng."""
    row = db.get(AppSetting, KEY)
    try:
        cursor = json.loads(row.value)["cursor"] if row and row.value else None
    except (ValueError, KeyError, TypeError):
        cursor = None
    if not isinstance(cursor, int):  # lần đầu (hoặc hỏng): đặt mốc, không gửi lịch sử
        cursor = None
    top = db.scalar(func.max(GroupChange.id)) or 0
    if cursor is None:
        new_cursor, rows = top, []
    else:
        rows = db.query(GroupChange).filter(GroupChange.id > cursor,
                                            GroupChange.change_type.in_(("drift_add", "drift_remove"))
                                            ).order_by(GroupChange.id).all()
        new_cursor = max([cursor] + [r.id for r in rows])
    queued = 0
    cfg = planner.get_cfg(db)
    infra = cfg.get("infra_emails") or []
    if rows and cfg.get("alert_drift") and infra:
        ab = ab_settings.get(db)
        batches: dict[str, list[GroupChange]] = {}
        for r in rows:
            batches.setdefault(r.batch_id, []).append(r)
        msgs = []
        for bid, rs in batches.items():
            ts = rs[0].ts if rs[0].ts.tzinfo else rs[0].ts.replace(tzinfo=dt.timezone.utc)
            reason = ab_settings.window_reason({**ab, "window_enabled": True}, ts)
            if reason:  # "" = giờ hành chính: team network sửa trực tiếp là bình thường
                msgs.append(_mail(bid, rs, reason, infra))
        queued = outbox.enqueue(db, msgs)
    r = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    r.value = json.dumps({"cursor": new_cursor})
    r.updated_by, r.updated_at = "system", dt.datetime.now(dt.timezone.utc)
    db.merge(r)
    db.commit()
    return queued
