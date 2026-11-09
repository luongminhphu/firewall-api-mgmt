"""Cache thành viên IP Host Group theo firewall (v1.6).

- Đọc: trả cache trong DB ngay (vài ms) thay vì gọi Sophos API mỗi lần mở tab.
- Ghi: sau mỗi lần thêm/xóa IP thành công, đánh dấu dirty và quét NHẸ ngay (đọc group theo tên, chi tiết từ
  cache/tên object) — vài trăm ms kể cả firewall có hàng chục nghìn object.
- Định kỳ (v1.6.1): quét ĐẦY ĐỦ khi quá TTL (mặc định 24h) hoặc tới GROUP_CACHE_DAILY_AT; firewall chậm có
  timeout riêng GROUP_SCAN_TIMEOUT, quá chậm thì vẫn cập nhật danh sách thành viên (details_mode=partial).
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
from .service import _host_value, client_for, resolve_hosts
from .sophos import SophosAuthError, SophosError

log = logging.getLogger("group_cache")
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()
# Khóa mềm quá hạn coi như pod chết giữa chừng; phải dài hơn một lượt quét đầy đủ chậm nhất.
STALE_LOCK = dt.timedelta(seconds=max(300, settings.GROUP_SCAN_TIMEOUT + settings.API_TIMEOUT + 60))
_attempts: dict[int, float] = {}  # lần thử quét gần nhất (monotonic) — để giãn cách thử lại firewall lỗi
VN_TZ = dt.timezone(dt.timedelta(hours=7))  # Asia/Ho_Chi_Minh, không có giờ mùa hè


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


def _scan_members(cli, group: str, mode: str, known: dict[str, dict], hints: dict[str, dict] | None):
    """Trả (g, details_by_name, details_mode, note). Không bao giờ đọc toàn bộ IP Host ở chế độ lite."""
    g = cli.get_group(group)
    if not g:
        return None, {}, "full", ""
    hosts = g["hosts"]
    note = ""
    if mode == "full" and hosts:
        try:
            wanted = set(hosts)
            det = {h["name"]: h for h in cli.get_hosts(timeout=settings.GROUP_SCAN_TIMEOUT) if h["name"] in wanted}
            missing = [n for n in hosts if n not in det]
            if missing:  # object vừa bị xóa giữa hai lệnh — suy từ tên
                more, _ = resolve_hosts(cli, missing, known)
                det.update(more)
            return g, det, "full", ""
        except SophosError as exc:
            # Firewall quá chậm khi trả toàn bộ IP Host: vẫn cập nhật danh sách thành viên (nhẹ), giữ chi tiết cũ.
            note = (f"Đọc chi tiết toàn bộ IP Host quá chậm ({exc}). Danh sách thành viên vẫn mới nhất; "
                    "ghi chú/giá trị lấy từ lần quét trước hoặc suy từ tên object. "
                    f"Có thể tăng GROUP_SCAN_TIMEOUT (hiện {settings.GROUP_SCAN_TIMEOUT} giây).")
            log.warning("Quét đầy đủ %s lỗi, chuyển sang quét nhẹ: %s", group, exc)
    merged_known = dict(known)
    for k, v in (hints or {}).items():
        merged_known.setdefault(k, v)
    det, unresolved = resolve_hosts(cli, hosts, merged_known)
    mode_out = "partial" if (note or unresolved) else "lite"
    if unresolved and not note:
        note = f"{len(unresolved)} object chưa đọc được chi tiết (tên không phải IP/CIDR)."
    return g, det, mode_out, note


def scan(db: Session, fw: Firewall, group: str = BLOCK_GROUP, *, mode: str = "full",
         hints: dict[str, dict] | None = None) -> GroupCache:
    """Quét group và ghi cache.

    mode="full": đọc group + toàn bộ IP Host (timeout GROUP_SCAN_TIMEOUT) — chạy định kỳ / bấm Quét lại.
    mode="lite": đọc group (lọc theo tên, nhẹ) + chi tiết từ cache/tên object — chạy ngay sau mỗi lần chặn/bỏ chặn.
    Lỗi firewall ghi vào cache (status=error) nhưng không xóa dữ liệu cũ.
    """
    t0 = time.monotonic()
    row = get_row(db, fw.id) or GroupCache(firewall_id=fw.id, group_name=group, data_json="{}")
    if row.id is None:
        db.add(row)
    old = data(row)
    known = {d["name"]: d for d in old.get("details", []) if isinstance(d, dict) and d.get("name")}
    try:
        cli = client_for(fw)
        g, det, details_mode, note = _scan_members(cli, group, mode, known, hints)
        now_iso = _now().isoformat()
        if not g:
            new = {"exists": False, "description": "", "ip_family": "", "total": 0, "members": [], "details": [],
                   "details_mode": "full", "full_scanned_at": now_iso, "note": ""}
        else:
            members = [_member(n, det.get(n, {})) for n in g["hosts"]]
            new = {"exists": True, "group": g["name"], "description": g.get("description", ""),
                   "ip_family": g.get("ip_family", ""), "total": len(g["hosts"]), "members": members,
                   "details": [{**det[n], "name": n} for n in g["hosts"] if n in det and not det[n].get("derived")],
                   "details_mode": details_mode, "note": note,
                   # Mốc quét đầy đủ gần nhất quyết định TTL; quét nhẹ sau thao tác không làm "trẻ" lại mốc này
                   "full_scanned_at": now_iso if details_mode == "full" else old.get("full_scanned_at")}
            try:  # phát hiện thay đổi ngoài app như trước
                changelog.detect_drift(db, fw, g["name"], {n: _host_value(det.get(n, {})) for n in g["hosts"]})
            except Exception:  # noqa: BLE001
                log.exception("detect_drift lỗi trên %s", fw.name)
        row.group_name = group
        row.data_json = json.dumps(new, ensure_ascii=False)
        row.status, row.error = "ok", ""
        row.scanned_at = _now()
        row.dirty = False
    except (SophosError, SophosAuthError, ValueError) as exc:
        row.status, row.error = "error", str(exc)[:1000]
    _attempts[fw.id] = time.monotonic()
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


def refresh_now(fw_id: int, *, force: bool = False, mode: str = "full", hints: dict[str, dict] | None = None) -> None:
    """Quét lại một firewall với session riêng (dùng cho background task / lập lịch / khởi động)."""
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
            row = get_row(db, fw_id)
            if row is not None and force:
                row.refreshing_since = _now()  # để giao diện thấy "Đang quét lại"
                db.commit()
            scan(db, fw, mode=mode, hints=hints)
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
    d = data(row)
    full_at = _full_at(d)
    full_age = int((_now() - full_at).total_seconds()) if full_at else None
    return {
        "cached": sa is not None,
        "scanned_at": sa.isoformat() if sa else None,
        "age_s": age,
        "full_scanned_at": full_at.isoformat() if full_at else None,
        "full_age_s": full_age,
        "details_mode": d.get("details_mode", "full") if d else "",
        "note": d.get("note", "") if d else "",
        "ttl_minutes": settings.GROUP_CACHE_TTL_MINUTES,
        "next_full_scan_at": _next_full(full_at).isoformat() if sa else None,
        "stale": full_age is None or full_age > settings.GROUP_CACHE_TTL_MINUTES * 60,
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


def _full_at(d: dict) -> dt.datetime | None:
    v = d.get("full_scanned_at") if d else None
    if not v:
        return None
    try:
        return _aware(dt.datetime.fromisoformat(v))
    except ValueError:
        return None


def _daily_at() -> tuple[int, int] | None:
    v = settings.GROUP_CACHE_DAILY_AT
    if not v:
        return None
    try:
        hh, mm = (int(x) for x in v.split(":", 1))
        if 0 <= hh < 24 and 0 <= mm < 60:
            return hh, mm
    except ValueError:
        pass
    log.warning("GROUP_CACHE_DAILY_AT='%s' không hợp lệ (cần HH:MM) — bỏ qua", v)
    return None


def _last_daily_slot(now: dt.datetime) -> dt.datetime | None:
    """Mốc giờ quét hằng ngày gần nhất đã qua (giờ Việt Nam)."""
    hm = _daily_at()
    if not hm:
        return None
    local = now.astimezone(VN_TZ)
    slot = local.replace(hour=hm[0], minute=hm[1], second=0, microsecond=0)
    if slot > local:
        slot -= dt.timedelta(days=1)
    return slot.astimezone(dt.timezone.utc)


def _next_full(full_at: dt.datetime | None) -> dt.datetime:
    """Thời điểm dự kiến quét đầy đủ kế tiếp (TTL hoặc mốc hằng ngày, cái nào tới trước)."""
    now = _now()
    if full_at is None:
        return now
    due = full_at + dt.timedelta(minutes=settings.GROUP_CACHE_TTL_MINUTES)
    slot = _last_daily_slot(now)
    if slot is not None:
        if full_at < slot:
            return now
        due = min(due, slot + dt.timedelta(days=1))
    return max(due, now)


def due_for_full(row: GroupCache | None, now: dt.datetime | None = None) -> bool:
    """Firewall có cần quét đầy đủ định kỳ không (TTL hoặc mốc giờ hằng ngày)."""
    now = now or _now()
    if row is None or row.scanned_at is None:
        return True
    if row.status == "error":
        last = _attempts.get(row.firewall_id)
        return last is None or time.monotonic() - last >= settings.GROUP_CACHE_ERROR_RETRY_MINUTES * 60
    full_at = _full_at(data(row))
    if full_at is None or now - full_at >= dt.timedelta(minutes=settings.GROUP_CACHE_TTL_MINUTES):
        return True
    slot = _last_daily_slot(now)
    return slot is not None and full_at < slot


def run_due(now: dt.datetime | None = None) -> list[int]:
    """Một vòng lập lịch: quét đầy đủ các firewall đến hạn. Trả danh sách id đã quét."""
    with SessionLocal() as db:
        fws = list(db.scalars(select(Firewall).where(Firewall.enabled.is_(True))))
        due = [f.id for f in fws if due_for_full(get_row(db, f.id), now)]
    for fid in due:
        refresh_now(fid, mode="full")
    return due


def scheduler_loop(stop: threading.Event | None = None) -> None:
    """Luồng nền: khởi động quét các firewall chưa có cache/quá hạn, sau đó kiểm tra mỗi GROUP_CACHE_CHECK_MINUTES."""
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            done = run_due()
            if done:
                log.info("Đã quét đầy đủ định kỳ %d firewall: %s", len(done), done)
        except Exception:  # noqa: BLE001
            log.exception("Vòng lập lịch cache lỗi")
        stop.wait(max(60, settings.GROUP_CACHE_CHECK_MINUTES * 60))


def warmup() -> None:
    """Tương thích v1.6.0: một vòng run_due."""
    run_due()
