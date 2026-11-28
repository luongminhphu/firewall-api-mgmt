"""Job fw-health: thăm dò từng firewall (Get SCANPORT GROUP, chỉ đọc) → cập nhật trạng thái + cảnh báo F1.

State (AppSetting `alerts.state`, mục `fw`): {fw_id: {status, down_since, alerted, next_probe_at}}.
Trạng thái so với lần PROBE trước (không so last_status — luồng chặn cũng ghi last_status).
Chỉ enqueue email (không deliver — outbox.deliver có khóa riêng, chu kỳ notify gửi).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging

from sqlalchemy.orm import Session

from ...core import jobs
from ...core.audit import audit
from ...core.config import settings
from ...core.db import SessionLocal
from ...core.models import AppSetting, Firewall
from ...integrations.sophos import SophosAuthError
from ...integrations.sophos.policy import BLOCK_GROUP
from ..firewalls.service import client_for, mark_status
from ..ipblock import group_cache
from . import outbox, planner

log = logging.getLogger("notify.health")
STATE_KEY = "alerts.state"
AUTH_BACKOFF = dt.timedelta(minutes=60)  # sai mật khẩu: giãn chu kỳ để không khoá tài khoản API
VN = dt.timezone(dt.timedelta(hours=7))


def load_state(db: Session) -> dict:
    row = db.get(AppSetting, STATE_KEY)
    try:
        st = json.loads(row.value) if row and row.value else {}
    except ValueError:
        st = {}
    return st if isinstance(st, dict) else {}


def save_state(db: Session, st: dict) -> None:
    row = db.get(AppSetting, STATE_KEY) or AppSetting(key=STATE_KEY)
    row.value = json.dumps(st)
    row.updated_by = "system"
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)


def _iso(t: dt.datetime | None) -> str | None:
    return t.isoformat() if t else None


def _parse(v: str | None) -> dt.datetime | None:
    """State hỏng / thiếu múi giờ không được làm kẹt firewall: sai định dạng → None, naive → UTC."""
    try:
        t = dt.datetime.fromisoformat(v) if v else None
    except (TypeError, ValueError):
        return None
    return t.replace(tzinfo=dt.timezone.utc) if t and t.tzinfo is None else t


def _fingerprint(fw: Firewall) -> str:
    """Đổi host / port / tài khoản / mật khẩu → hết giãn chu kỳ auth_error (admin vừa sửa thì probe ngay)."""
    return hashlib.sha256(f"{fw.host}|{fw.port}|{fw.username}|{fw.password_enc}".encode()).hexdigest()[:16]


def probe_group(fw: Firewall) -> dict | None:
    """Một lượt Get nhẹ; trả group đọc được (có `hosts`) để T-02 so với cache. Lỗi → ném."""
    with client_for(fw) as cli:
        return cli.get_group(BLOCK_GROUP)


def _mail(kind: str, fw: Firewall, down_since: dt.datetime, to: list[str], now: dt.datetime, msg: str = "") -> dict:
    when = lambda t: t.astimezone(VN).strftime("%H:%M %d/%m/%Y")  # noqa: E731
    link = f"{settings.APP_BASE_URL.rstrip('/')}/#firewalls" if settings.APP_BASE_URL else ""
    head = f"Firewall: {fw.name}" + (f" · Site {fw.site}" if fw.site else "") + f"\nĐịa chỉ: {fw.host}:{fw.port}\n"
    foot = (f"\nXem chi tiết: {link}" if link else "") + "\n\n(Email tự động — vui lòng không trả lời.)\n"
    if kind == "fw_down":
        mins = int((now - down_since).total_seconds() // 60)
        subj = f"[Firewall] Mất kết nối XML API: {fw.name}"
        body = (f"SOC Rapid Block không kết nối được XML API của firewall suốt {mins} phút "
                f"(từ {when(down_since)}).\n\n{head}Lỗi gần nhất: {msg[:500] or '—'}\n\n"
                "Trong thời gian này không thể chặn / bỏ chặn IP trên firewall này. Infra vui lòng kiểm tra mạng, "
                "dịch vụ API và tài khoản API." + foot)
    else:
        subj = f"[Firewall] Đã kết nối lại: {fw.name}"
        body = (f"Firewall đã kết nối lại XML API lúc {when(now)} "
                f"(mất kết nối từ {when(down_since)}).\n\n{head}" + foot)
    return {"dedupe_key": f"{kind}:{fw.id}:{down_since.isoformat()}", "kind": kind, "to": to, "subject": subj,
            "body": body, "ref": {"firewall_id": fw.id}}


def _sync_drift(db: Session, fw: Firewall, group: dict) -> None:
    """D1b: tập thành viên probe thấy khác cache → quét nhẹ ngay (drift ≈ lúc sửa). Lỗi chỉ log."""
    try:
        row = group_cache.get_row(db, fw.id)
        if row is None:  # chưa quét lần nào: để lượt quét đầy đủ tạo baseline
            return
        cached = {m.get("object") for m in group_cache.data(row).get("members", [])}
        if set(group.get("hosts") or []) == cached and not row.dirty:  # dirty: lượt quét trước bị raced, chưa so
            return
        with jobs.lock(f"gc-scan:{fw.id}", blocking=False) as got:
            if got:  # khoá fw-write do scan tự lấy
                group_cache.scan(db, fw, mode="lite")
            else:  # đang có lượt quét khác của cùng firewall
                log.info("fw-health: %s đang có lượt quét cache, hoãn quét drift", fw.name)
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("fw-health: quét drift %s lỗi", fw.name)


def probe_fw(db: Session, fw: Firewall, st: dict, cfg: dict, now: dt.datetime) -> dict | None:
    """Thăm dò một firewall, cập nhật st['fw'][id], mark_status, audit, enqueue. Trả group đọc được (hoặc None)."""
    fs = st.setdefault("fw", {})
    cur = fs.get(str(fw.id)) or {}
    fp = _fingerprint(fw)
    nxt = _parse(cur.get("next_probe_at"))
    backoff = bool(nxt and nxt > now and cur.get("cfg") == fp and cur.get("status") == "auth_error")
    group, msg, status = None, "", "ok"
    if backoff:  # đang giãn chu kỳ: không gọi firewall (tránh khoá tài khoản API) nhưng vẫn xét ngưỡng email
        status, msg = "auth_error", cur.get("msg") or "Sai thông tin đăng nhập API"
    else:
        try:
            group = probe_group(fw)
            msg = "Kết nối XML API thành công"
        except SophosAuthError as exc:
            status, msg = "auth_error", str(exc)
        except Exception as exc:  # noqa: BLE001 — SophosError, ValueError, MasterKeyMissing...: một firewall không dừng vòng
            status, msg = "error", str(exc)
        msg = msg[:500]
        mark_status(db, fw, status, msg)
    prev = cur.get("status") or "ok"  # chưa có state = coi như ổn: lần đầu lỗi vẫn ghi audit
    if status != prev:
        audit(db, action="fw_health", fw=fw, target=f"{fw.host}:{fw.port}", result="ok" if status == "ok" else "error",
              code=status, message=msg, actor="system")
    new = {"status": status, "down_since": cur.get("down_since"), "alerted": bool(cur.get("alerted")), "cfg": fp,
           "msg": msg if status != "ok" else "",
           "next_probe_at": (cur.get("next_probe_at") if backoff
                             else _iso(now + AUTH_BACKOFF) if status == "auth_error" else None)}
    infra = cfg.get("infra_emails") or []
    if status == "ok":
        since = _parse(new["down_since"])
        if since and new["alerted"] and infra:
            outbox.enqueue(db, [_mail("fw_up", fw, since, infra, now)])
        new["down_since"], new["alerted"] = None, False
    else:
        since = _parse(new["down_since"]) or now  # chưa có / state hỏng → tính từ lượt này
        new["down_since"] = _iso(since)
        if (cfg.get("alert_fw_down") and infra and not new["alerted"]
                and now - since >= dt.timedelta(minutes=cfg["fw_down_minutes"])):
            outbox.enqueue(db, [_mail("fw_down", fw, since, infra, now, msg)])
            new["alerted"] = True
    fs[str(fw.id)] = new
    save_state(db, st)
    db.commit()
    if group is not None:  # None = group không tồn tại, không phải tập rỗng
        _sync_drift(db, fw, group)
    return group


def probe_all(now: dt.datetime | None = None) -> None:
    """Chạy bởi jobs.every. `now` chỉ để test."""
    now = now or dt.datetime.now(dt.timezone.utc)
    with SessionLocal() as db:
        cfg = planner.get_cfg(db)
        fws = list(db.query(Firewall).filter(Firewall.enabled.is_(True)).order_by(Firewall.id))
        ids = {str(f.id) for f in fws}
        st = load_state(db)
        if set(st.get("fw", {})) - ids:  # firewall đã tắt / xoá → bỏ state
            st["fw"] = {k: v for k, v in st["fw"].items() if k in ids}
            save_state(db, st)
            db.commit()
        for fw in fws:
            try:
                st = load_state(db)  # nạp lại: commit từng firewall, tránh ghi đè mục khác
                probe_fw(db, fw, st, cfg, now)
            except Exception:  # noqa: BLE001
                db.rollback()
                log.exception("fw-health: firewall id=%s lỗi ngoài dự kiến", fw.id)
