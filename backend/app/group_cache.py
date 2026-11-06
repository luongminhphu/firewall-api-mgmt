"""Cache thành viên IP Host Group theo firewall (v1.6).

- Đọc: trả cache trong DB ngay (vài ms) thay vì gọi Sophos API mỗi lần mở tab.
- Ghi: sau mỗi lần thêm/xóa IP thành công, đánh dấu dirty và quét lại nền để cache khớp firewall.
- Quá TTL: vẫn trả cache, kèm quét lại nền (stale-while-revalidate).
- Nhiều replica: cache nằm trong PostgreSQL; refreshing_since là khóa mềm tránh quét trùng.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import changelog
from .config import settings
from .db import Firewall, GroupCache, SessionLocal
from .policy import BLOCK_GROUP
from .service import _host_value, client_for
from .sophos import SophosAuthError, SophosError

log = logging.getLogger("group_cache")
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()
STALE_LOCK = dt.timedelta(minutes=5)  # khóa mềm quá 5 phút coi như hết hạn (pod chết giữa chừng)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    if t is None:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _lock(fw_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(fw_id, threading.Lock())


def _member(name: str, d: dict) -> dict:
    value = d.get("ip_address") or d.get("start_ip") or ""
    if d.get("host_type") == "IPRange" and d.get("start_ip"):
        value = f"{d['start_ip']} - {d.get('end_ip', '')}"
    elif d.get("host_type") == "Network" and d.get("subnet"):
        try:
            value = str(ipaddress.ip_network(f"{d['ip_address']}/{d['subnet']}", strict=False))
        except ValueError:
            value = f"{d['ip_address']}/{d['subnet']}"
    return {"object": name, "host_type": d.get("host_type", ""), "value": value,
            "description": d.get("description", "")}


def get_row(db: Session, fw_id: int) -> GroupCache | None:
    return db.scalar(select(GroupCache).where(GroupCache.firewall_id == fw_id))


def scan(db: Session, fw: Firewall, group: str = BLOCK_GROUP) -> GroupCache:
    """Quét group trên firewall và ghi cache. Lỗi firewall được ghi vào cache (status=error), không xóa dữ liệu cũ."""
    t0 = time.monotonic()
    row = get_row(db, fw.id) or GroupCache(firewall_id=fw.id, group_name=group, data_json="{}")
    if row.id is None:
        db.add(row)
    try:
        cli = client_for(fw)
        g = cli.get_group(group)
        if not g:
            data = {"exists": False, "description": "", "ip_family": "", "total": 0, "members": []}
        else:
            details = {h["name"]: h for h in cli.get_hosts(g["hosts"])} if g["hosts"] else {}
            members = [_member(n, details.get(n, {})) for n in g["hosts"]]
            data = {"exists": True, "group": g["name"], "description": g.get("description", ""),
                    "ip_family": g.get("ip_family", ""), "total": len(g["hosts"]), "members": members}
            try:  # phát hiện thay đổi ngoài app như trước
                changelog.detect_drift(db, fw, g["name"], {n: _host_value(details.get(n, {})) for n in g["hosts"]})
            except Exception:  # noqa: BLE001
                log.exception("detect_drift lỗi trên %s", fw.name)
        row.group_name = group
        row.data_json = json.dumps(data, ensure_ascii=False)
        row.status, row.error = "ok", ""
        row.scanned_at = _now()
        row.dirty = False
    except (SophosError, SophosAuthError, ValueError) as exc:
        row.status, row.error = "error", str(exc)[:1000]
    row.scan_ms = int((time.monotonic() - t0) * 1000)
    row.refreshing_since = None
    db.commit()
    return row


def _claim(db: Session, fw_id: int) -> bool:
    """Khóa mềm trong DB (giữa các replica). True nếu được quyền quét."""
    row = get_row(db, fw_id)
    if row is None:
        return True
    rs = _aware(row.refreshing_since)
    if rs and _now() - rs < STALE_LOCK:
        return False
    row.refreshing_since = _now()
    db.commit()
    return True


def refresh_now(fw_id: int, *, force: bool = False) -> None:
    """Quét lại một firewall với session riêng (dùng cho background task/khởi động)."""
    lk = _lock(fw_id)
    if not lk.acquire(blocking=force):
        return  # đang có lượt quét khác trong pod này
    try:
        with SessionLocal() as db:
            fw = db.get(Firewall, fw_id)
            if fw is None or not fw.enabled:
                return
            if not force and not _claim(db, fw_id):
                return
            scan(db, fw)
    except Exception:  # noqa: BLE001
        log.exception("Quét cache firewall %s lỗi", fw_id)
    finally:
        lk.release()


def mark_dirty(db: Session, fw_ids: list[int]) -> None:
    for fid in fw_ids:
        row = get_row(db, fid)
        if row is not None:
            row.dirty = True
    db.commit()


def drop(db: Session, fw_id: int) -> None:
    row = get_row(db, fw_id)
    if row is not None:
        db.delete(row)
        db.commit()


def meta(row: GroupCache | None, fw: Firewall | None = None) -> dict:
    if row is None:
        return {"cached": False, "scanned_at": None, "age_s": None, "stale": True, "dirty": False,
                "refreshing": False, "status": "none", "error": ""}
    sa = _aware(row.scanned_at)
    age = int((_now() - sa).total_seconds()) if sa else None
    rs = _aware(row.refreshing_since)
    return {
        "cached": sa is not None,
        "scanned_at": sa.isoformat() if sa else None,
        "age_s": age,
        "stale": age is None or age > settings.GROUP_CACHE_TTL_MINUTES * 60,
        "dirty": bool(row.dirty),
        "refreshing": bool(rs and _now() - rs < STALE_LOCK),
        "status": row.status,
        "error": row.error or "",
        "scan_ms": row.scan_ms,
    }


def data(row: GroupCache | None) -> dict:
    if row is None:
        return {}
    try:
        return json.loads(row.data_json or "{}")
    except ValueError:
        return {}


def can_force(row: GroupCache | None) -> bool:
    """Giới hạn quét tay: tối thiểu GROUP_CACHE_MIN_REFRESH_SECONDS giữa 2 lần (tránh dồn API firewall)."""
    if row is None or row.scanned_at is None:
        return True
    return (_now() - _aware(row.scanned_at)).total_seconds() >= settings.GROUP_CACHE_MIN_REFRESH_SECONDS


def warmup() -> None:
    """Khởi động: quét nền các firewall chưa có cache."""
    with SessionLocal() as db:
        ids = [f.id for f in db.scalars(select(Firewall).where(Firewall.enabled.is_(True)))]
        have = {r.firewall_id for r in db.scalars(select(GroupCache))}
    for fid in ids:
        if fid not in have:
            refresh_now(fid)
