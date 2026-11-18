"""Hàng đợi email (outbox) + worker gửi.

- enqueue: chèn theo dedupe_key (đã có → bỏ qua) → chạy lại kế hoạch bao nhiêu lần cũng không gửi trùng.
- deliver: gửi các thư đến hạn; lỗi → thử lại lùi dần (5 phút × 2^n, tối đa 6 giờ); quá MAX_ATTEMPTS → failed.
  SMTP chưa cấu hình / đang tắt → thư nằm chờ (không tính là lỗi, không tốn lượt thử).
- run_cycle: (nếu bật) lập kế hoạch từ rule VPN hiện tại → enqueue → deliver. Chạy định kỳ qua core.jobs.every
  (mỗi vòng một pod) và bằng nút "Chạy ngay" (quản trị viên).
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.models import EmailOutbox
from ..vpn import expiry
from ..vpn import rules as vpn_rules
from . import planner, smtp

log = logging.getLogger("notify")
MAX_ATTEMPTS = 8


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return None if t is None else (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc))


def enqueue(db: Session, msgs: list[dict]) -> int:
    if not msgs:
        return 0
    keys = {m["dedupe_key"] for m in msgs}
    have = set(db.scalars(select(EmailOutbox.dedupe_key).where(EmailOutbox.dedupe_key.in_(keys))))
    added = 0
    now = _now()
    for m in msgs:
        if m["dedupe_key"] in have:
            continue
        try:
            with db.begin_nested():  # pod khác chèn cùng khóa → IntegrityError chỉ hủy dòng này
                db.add(EmailOutbox(dedupe_key=m["dedupe_key"][:255], kind=m["kind"], to_addrs=",".join(m["to"]),
                                   subject=m["subject"][:255], body=m["body"],
                                   ref_json=json.dumps(m.get("ref", {}), ensure_ascii=False),
                                   status="pending", attempts=0, next_attempt_at=now, created_at=now))
            added += 1
            have.add(m["dedupe_key"])
        except IntegrityError:
            continue
    db.commit()
    return added


def deliver(db: Session, limit: int = 50) -> dict:
    cfg = smtp.get(db)
    if not (cfg["enabled"] and cfg["configured"]):
        pending = db.query(EmailOutbox).filter(EmailOutbox.status == "pending").count()
        return {"sent": 0, "failed": 0, "retry": 0, "pending": pending,
                "note": "SMTP chưa cấu hình hoặc đang tắt — thư nằm chờ trong hàng đợi"}
    now = _now()
    due = list(db.scalars(select(EmailOutbox).where(EmailOutbox.status == "pending",
                                                     EmailOutbox.next_attempt_at <= now)
                          .order_by(EmailOutbox.id).limit(limit)))
    c = {"sent": 0, "failed": 0, "retry": 0}
    for m in due:
        m.attempts += 1
        try:
            smtp.send(db, [a for a in m.to_addrs.split(",") if a], m.subject, m.body)
            m.status, m.sent_at, m.last_error = "sent", _now(), ""
            c["sent"] += 1
        except smtp.MailError as exc:
            m.last_error = str(exc)[:2000]
            if m.attempts >= MAX_ATTEMPTS:
                m.status = "failed"
                c["failed"] += 1
            else:
                m.next_attempt_at = _now() + min(dt.timedelta(hours=6), dt.timedelta(minutes=5) * 2 ** (m.attempts - 1))
                c["retry"] += 1
            log.warning("Gửi email #%s lỗi (lần %s): %s", m.id, m.attempts, exc)
        db.commit()
    c["pending"] = db.query(EmailOutbox).filter(EmailOutbox.status == "pending").count()
    return c


def plan_now(db: Session, today: dt.date | None = None) -> dict:
    cfg = planner.get_cfg(db)
    if not cfg["enabled"]:
        return {"planned": 0, "queued": 0, "note": "Thông báo đang tắt"}
    today = today or expiry.today_vn()
    rules = vpn_rules.list_rules(db, today=today)["rules"]
    msgs = planner.plan(rules, cfg, planner.contacts_map(db), today)
    return {"planned": len(msgs), "queued": enqueue(db, msgs)}


def run_cycle(today: dt.date | None = None) -> dict:
    from ...core.db import SessionLocal

    with SessionLocal() as db:
        p = plan_now(db, today)
        d = deliver(db)
    return {**p, **d}


def list_outbox(db: Session, status: str = "", limit: int = 200) -> list[dict]:
    stmt = select(EmailOutbox).order_by(EmailOutbox.id.desc()).limit(limit)
    if status:
        stmt = stmt.where(EmailOutbox.status == status)
    iso = lambda t: _aware(t).isoformat() if t else None  # noqa: E731
    return [{"id": m.id, "kind": m.kind, "to": [a for a in m.to_addrs.split(",") if a], "subject": m.subject,
             "status": m.status, "attempts": m.attempts, "created_at": iso(m.created_at), "sent_at": iso(m.sent_at),
             "next_attempt_at": iso(m.next_attempt_at), "last_error": m.last_error,
             "ref": json.loads(m.ref_json or "{}")} for m in db.scalars(stmt)]
