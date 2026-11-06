"""Nhật ký thay đổi Object Group (change log) + phát hiện thay đổi ngoài app (drift).

- Mỗi IP được thêm/bớt khỏi group sinh một dòng `GroupChange`, gom theo `batch_id`.
- Các dòng nối nhau bằng chuỗi băm SHA-256 (prev_hash -> row_hash): xóa/sửa một dòng
  bất kỳ sẽ làm `verify_chain()` báo đứt chuỗi tại đúng vị trí đó.
- `GroupSnapshot` lưu thành viên group lần gần nhất app nhìn thấy. Khi đọc lại group,
  phần chênh lệch không do app tạo ra được ghi là `drift_add` / `drift_remove`
  (thay đổi trực tiếp trên WebAdmin firewall hoặc công cụ khác).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
import uuid

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .db import Firewall, GroupChange, GroupSnapshot

_chain_lock = threading.Lock()

EXTERNAL_ACTOR = "ngoai-app"
EXTERNAL_NAME = "Thay đổi ngoài app (trực tiếp trên firewall)"


VN_TZ = dt.timezone(dt.timedelta(hours=7))


def iso_utc(ts: dt.datetime | None) -> str | None:
    if ts is None:
        return None
    ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
    return ts.isoformat()


def vn_time(ts_iso: str | None) -> str:
    if not ts_iso:
        return ""
    return dt.datetime.fromisoformat(ts_iso).astimezone(VN_TZ).strftime("%d/%m/%Y %H:%M:%S")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_batch() -> str:
    return uuid.uuid4().hex[:16]


def _last_hash(db: Session) -> str:
    row = db.scalars(select(GroupChange).order_by(desc(GroupChange.id)).limit(1)).first()
    return row.row_hash if row else ""


def record(
    db: Session,
    *,
    fw: Firewall,
    group: str,
    change_type: str,
    items: list[tuple[str, str]],
    count_before: int,
    count_after: int,
    who: dict | None = None,
    reason: str = "",
    source: str = "",
    client_ip: str = "",
    batch_id: str | None = None,
) -> str:
    """Ghi một lô thay đổi. `items` = [(object_name, value)]. Trả về batch_id."""
    who = who or {}
    batch_id = batch_id or new_batch()
    if not items and change_type not in ("baseline", "create_group"):
        return batch_id
    rows = items or [("", "")]
    with _chain_lock:
        prev = _last_hash(db)
        ts = _now()
        for obj, value in rows:
            ch = GroupChange(
                ts=ts, batch_id=batch_id,
                actor=who.get("user", ""), actor_name=who.get("name", ""),
                auth_method=who.get("method", ""),
                firewall_id=fw.id, firewall_name=fw.name, group_name=group,
                change_type=change_type, object_name=obj or "", value=value or "",
                count_before=count_before, count_after=count_after,
                reason=(reason or "")[:2000], source=source or "", client_ip=client_ip or "",
                prev_hash=prev,
            )
            ch.row_hash = hashlib.sha256(ch.hash_payload().encode()).hexdigest()
            prev = ch.row_hash
            db.add(ch)
        # Commit ngay trong khóa: từ v1.6 có luồng quét cache chạy nền song song với thao tác
        # người dùng; nếu nhả khóa trước khi commit, hai phiên có thể đọc cùng prev_hash → đứt chuỗi.
        db.commit()
    return batch_id


# --------------------------------------------------------------- snapshots
def get_snapshot(db: Session, fw_id: int, group: str) -> GroupSnapshot | None:
    return db.scalars(
        select(GroupSnapshot).where(GroupSnapshot.firewall_id == fw_id, GroupSnapshot.group_name == group)
    ).first()


def save_snapshot(db: Session, fw_id: int, group: str, members: dict[str, str]) -> None:
    snap = get_snapshot(db, fw_id, group)
    if not snap:
        snap = GroupSnapshot(firewall_id=fw_id, group_name=group)
    old = json.loads(snap.members_json or "{}") if snap.id else {}
    # Giữ lại giá trị IP đã biết nếu lần này không có chi tiết
    merged = {k: (v or old.get(k, "")) for k, v in members.items()}
    snap.members_json = json.dumps(merged, ensure_ascii=False, sort_keys=True)
    snap.taken_at = _now()
    db.add(snap)


def detect_drift(
    db: Session,
    fw: Firewall,
    group: str,
    current: dict[str, str],
    *,
    resolve_values=None,
) -> dict:
    """So sánh thành viên hiện tại với snapshot. Ghi drift nếu có, rồi cập nhật snapshot.

    `current` = {object_name: value|""}. `resolve_values(names)` (tùy chọn) trả về
    {name: value} để điền IP cho object mới xuất hiện.
    """
    snap = get_snapshot(db, fw.id, group)
    if not snap:
        record(db, fw=fw, group=group, change_type="baseline", items=[],
               count_before=len(current), count_after=len(current),
               who={"user": "he-thong", "name": "Ghi nhận trạng thái ban đầu", "method": "system"},
               reason=f"Bắt đầu theo dõi group với {len(current)} object")
        save_snapshot(db, fw.id, group, current)
        return {"baseline": True, "added": [], "removed": []}

    old = json.loads(snap.members_json or "{}")
    added = sorted(set(current) - set(old))
    removed = sorted(set(old) - set(current))
    if added and resolve_values:
        try:
            vals = resolve_values(added) or {}
            for n in added:
                current[n] = current.get(n) or vals.get(n, "")
        except Exception:  # noqa: BLE001 — drift vẫn ghi được dù không lấy được IP
            pass
    who = {"user": EXTERNAL_ACTOR, "name": EXTERNAL_NAME, "method": "drift"}
    before = len(old)
    batch = new_batch()
    if added:
        record(db, fw=fw, group=group, change_type="drift_add",
               items=[(n, current.get(n, "")) for n in added],
               count_before=before, count_after=before + len(added), who=who,
               reason="Phát hiện thay đổi trực tiếp trên firewall, không qua SOC Rapid Block",
               batch_id=batch)
        before += len(added)
    if removed:
        record(db, fw=fw, group=group, change_type="drift_remove",
               items=[(n, old.get(n, "")) for n in removed],
               count_before=before, count_after=before - len(removed), who=who,
               reason="Phát hiện thay đổi trực tiếp trên firewall, không qua SOC Rapid Block",
               batch_id=batch)
    save_snapshot(db, fw.id, group, current)
    return {"baseline": False, "added": added, "removed": removed}


# ------------------------------------------------------------------ query
def verify_chain(db: Session) -> dict:
    prev = ""
    count = 0
    for ch in db.scalars(select(GroupChange).order_by(GroupChange.id)).yield_per(500):
        count += 1
        if ch.prev_hash != prev:
            return {"ok": False, "checked": count, "broken_at": ch.id,
                    "message": f"Chuỗi băm đứt tại bản ghi #{ch.id}: có bản ghi trước đó bị xóa hoặc chèn"}
        expect = hashlib.sha256(ch.hash_payload().encode()).hexdigest()
        if expect != ch.row_hash:
            return {"ok": False, "checked": count, "broken_at": ch.id,
                    "message": f"Bản ghi #{ch.id} đã bị sửa sau khi ghi"}
        prev = ch.row_hash
    return {"ok": True, "checked": count, "broken_at": None,
            "message": f"Toàn vẹn: {count} bản ghi, chuỗi băm khớp"}


def query_batches(
    db: Session,
    *,
    firewall_id: int | None = None,
    group: str = "",
    change_type: str = "",
    actor: str = "",
    q: str = "",
    date_from: dt.datetime | None = None,
    date_to: dt.datetime | None = None,
    limit_batches: int = 100,
) -> list[dict]:
    stmt = select(GroupChange)
    if firewall_id:
        stmt = stmt.where(GroupChange.firewall_id == firewall_id)
    if group:
        stmt = stmt.where(GroupChange.group_name == group)
    if change_type == "drift":
        stmt = stmt.where(GroupChange.change_type.in_(("drift_add", "drift_remove")))
    elif change_type:
        stmt = stmt.where(GroupChange.change_type == change_type)
    if actor:
        stmt = stmt.where(GroupChange.actor.ilike(f"%{actor}%"))
    if q:
        like = f"%{q.strip()}%"
        # Tìm theo IP/object: trả về toàn bộ lô có chứa IP đó
        hit = select(GroupChange.batch_id).where(
            (GroupChange.value.ilike(like)) | (GroupChange.object_name.ilike(like))
            | (GroupChange.reason.ilike(like))
        )
        stmt = stmt.where(GroupChange.batch_id.in_(hit))
    if date_from:
        stmt = stmt.where(GroupChange.ts >= date_from)
    if date_to:
        stmt = stmt.where(GroupChange.ts < date_to)
    stmt = stmt.order_by(desc(GroupChange.id)).limit(limit_batches * 60)

    batches: dict[str, dict] = {}
    order: list[str] = []
    for ch in db.scalars(stmt).all():
        b = batches.get(ch.batch_id)
        if not b:
            if len(order) >= limit_batches:
                continue
            b = {
                "batch_id": ch.batch_id, "ts": iso_utc(ch.ts),
                "actor": ch.actor, "actor_name": ch.actor_name, "auth_method": ch.auth_method,
                "firewall_id": ch.firewall_id, "firewall_name": ch.firewall_name,
                "group_name": ch.group_name, "reason": ch.reason, "source": ch.source,
                "client_ip": ch.client_ip, "kinds": set(), "added": [], "removed": [],
                "count_before": ch.count_before, "count_after": ch.count_after,
            }
            batches[ch.batch_id] = b
            order.append(ch.batch_id)
        b["kinds"].add(ch.change_type)
        item = {"object": ch.object_name, "value": ch.value, "id": ch.id}
        if ch.change_type in ("add", "drift_add"):
            b["added"].append(item)
        elif ch.change_type in ("remove", "drift_remove"):
            b["removed"].append(item)
        b["count_before"] = min(b["count_before"], ch.count_before)
    out = []
    for bid in order:
        b = batches[bid]
        kinds = b.pop("kinds")
        b["kind"] = (
            "drift" if kinds & {"drift_add", "drift_remove"}
            else "baseline" if kinds == {"baseline"}
            else "create_group" if "create_group" in kinds and not (b["added"] or b["removed"])
            else "change"
        )
        b["added"].sort(key=lambda x: x["id"])
        b["removed"].sort(key=lambda x: x["id"])
        out.append(b)
    return out
