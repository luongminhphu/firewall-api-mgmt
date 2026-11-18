"""Tự động chặn IP từ group chat Teams — luồng xử lý.

Mỗi chu kỳ (quản trị viên chọn trên giao diện, mặc định 5 phút; một pod/vòng):
  1. Đọc tin MỚI của group chat qua Microsoft Graph (chỉ tin tạo sau thời điểm bật bộ đọc).
  2. Bỏ qua: tin không phải của tài khoản SOC trong danh sách · tin ĐÃ SỬA · tin đã xóa · tin hệ thống.
  3. Bóc dòng "ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>" (parser.py). IP sai / thuộc safe-list / IP nội bộ → không chặn.
  4. Quyết định cho từng IP:
       công tắc khẩn cấp TẮT              → chờ duyệt
       ngoài khung giờ tự động (18h–8h)   → chờ duyệt
       ngưỡng đã ngắt / vượt N IP/giờ     → ngắt ngưỡng: chờ duyệt + email cảnh báo nhóm Admin
       còn lại                            → TỰ CHẶN (luồng chặn sẵn có: job nền, policy guard, SCANPORT GROUP)
  5. Chờ duyệt → email nhóm Admin. 08:00 hằng ngày → email danh sách ca đêm (18:00 hôm trước – 08:00).

Mọi bước ghi vào autoblock_events (chuỗi băm) + audit_logs (qua luồng chặn chung).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core import hashchain, jobs
from ...core.audit import audit
from ...core.config import settings
from ...core.db import SessionLocal
from ...core.errors import AppError
from ...core.models import AppUser, AutoBlockEvent, AutoBlockEvidence, AutoBlockMessage, AutoBlockRequest, Firewall
from ..ipblock.service import block_on_firewall, normalize_entries, unblock_on_firewall
from ..notify import outbox
from . import graph, parser, reply
from . import settings as cfgmod

log = logging.getLogger("autoblock")
ACTOR = "autoblock"  # tác nhân ghi trong audit / lịch sử thay đổi khi app tự chặn
WHO = {"user": ACTOR, "name": "Tự động chặn (Teams)", "method": "autoblock"}
ACTIVE = ("blocking", "blocked", "pending", "approved")
# đọc chồng nhỏ (độ trễ nhất quán phía Graph); msg_id UNIQUE chống xử lý lại
OVERLAP = dt.timedelta(seconds=max(0, settings.AUTOBLOCK_OVERLAP_SECONDS))


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return None if t is None else (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc))


def _ts(v: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


def _vn(t: dt.datetime | None) -> str:
    return _aware(t).astimezone(cfgmod.VN_TZ).strftime("%d/%m/%Y %H:%M") if t else ""


def event(db: Session, ev: str, *, ip: str = "", request_id: int | None = None, actor: str = ACTOR,
          detail: str = "") -> None:
    hashchain.append(db, AutoBlockEvent, [AutoBlockEvent(ts=_now(), request_id=request_id, ip=ip, event=ev,
                                                         actor=actor[:160], detail=detail[:2000])])


# ------------------------------------------------------------------ người nhận
def admin_emails(db: Session, cfg: dict) -> list[str]:
    if cfg.get("admin_emails"):
        return cfg["admin_emails"]
    rows = db.scalars(select(AppUser).where(AppUser.is_admin.is_(True), AppUser.enabled.is_(True)))
    return sorted({u.username for u in rows if "@" in u.username})


def _link() -> str:
    return f"{settings.APP_BASE_URL}/#autoblock" if settings.APP_BASE_URL else "tab Tự động chặn của SOC Rapid Block"


def _mail(db: Session, cfg: dict, key: str, kind: str, subject: str, body: str, *, urgent: bool = False) -> None:
    to = admin_emails(db, cfg)
    if not to:
        log.warning("Không có email nhóm Admin để gửi '%s'", subject)
        return
    outbox.enqueue(db, [{"dedupe_key": key, "kind": kind, "to": to, "subject": subject, "body": body}])
    if urgent:
        try:
            outbox.deliver(db)  # cảnh báo gửi ngay, không chờ chu kỳ NOTIFY_INTERVAL_SECONDS
        except Exception:  # noqa: BLE001 — SMTP lỗi: thư vẫn nằm trong hàng đợi, sẽ thử lại
            log.exception("Gửi cảnh báo tự động chặn lỗi")


# ------------------------------------------------------------------ đọc tin
def due(now: dt.datetime | None = None) -> bool:
    """Đến chu kỳ đọc chưa (poll_seconds do quản trị viên chọn; mốc lưu DB nên đúng cả khi nhiều pod)."""
    with SessionLocal() as db:
        cfg = cfgmod.raw(db)
        if not cfg["enabled"]:
            return False
        last = _ts(cfgmod.state(db).get("last_poll_at", ""))
    return last is None or ((now or _now()) - last).total_seconds() >= cfg["poll_seconds"] - 5


def tick() -> dict | None:
    """Bộ lập lịch gọi mỗi 30 giây; chỉ đọc Teams khi đủ chu kỳ."""
    return poll() if due() else None


def poll() -> dict:
    with jobs.lock("autoblock:poll", blocking=False) as got:
        if not got:
            return {"skipped": "busy"}
        with SessionLocal() as db:
            return _poll(db)


def _poll(db: Session) -> dict:
    cfg = cfgmod.raw(db)
    if not cfg["enabled"] or not cfgmod.configured(cfg):
        return {"skipped": "disabled"}
    st = cfgmod.state(db)
    now = _now()
    start_at = _ts(st.get("start_at")) or now
    cursor = _ts(st.get("cursor")) or start_at
    since = max(start_at, cursor - OVERLAP)
    st["last_poll_at"] = now.isoformat()
    try:
        msgs, truncated, filtered = graph.changed_since(cfg, since)
    except (graph.GraphError, ValueError, KeyError) as exc:
        st.update(last_ok=False, last_error=str(exc)[:300])
        cfgmod.save_state(db, st)
        db.commit()
        log.warning("Đọc Teams lỗi: %s", exc)
        return {"ok": False, "error": str(exc)}
    soc = {s["id"]: s["name"] for s in cfg["soc_senders"]}
    stats = {"messages": 0, "commands": 0, "auto": 0, "pending": 0, "invalid": 0, "duplicate": 0}
    auto_reqs: list[AutoBlockRequest] = []
    pending_reqs: list[AutoBlockRequest] = []
    for m in msgs:
        created = graph._parse_ts(m.get("createdDateTime"))
        # mốc đọc lần sau theo GIỜ CỦA GRAPH (lastModifiedDateTime lớn nhất), không theo đồng hồ máy app
        modified = graph._parse_ts(m.get("lastModifiedDateTime")) or created
        if modified:
            cursor = max(cursor, modified)
        if created is None or created <= start_at:
            continue  # tin gửi trước lúc bật / đổi Chat ID (kể cả vừa được sửa / thả cảm xúc) — không xử lý
        if db.scalar(select(AutoBlockMessage.id).where(AutoBlockMessage.msg_id == str(m.get("id"))[:64])):
            _follow_up(db, m)  # tin đã xử lý quay lại: có thể vừa bị xóa / sửa → ghi mốc thời gian làm bằng chứng
            continue
        stats["messages"] += 1
        _handle_message(db, cfg, st, soc, m, created, stats, auto_reqs, pending_reqs)
    st.update(cursor=cursor.isoformat(), last_ok=True, last_error="", last_fetched=len(msgs),
              last_truncated=truncated, server_filter=filtered)
    if truncated:
        log.warning("Đọc Teams: quá nhiều tin mới trong một chu kỳ — chưa đọc hết, sẽ đọc tiếp ở chu kỳ sau")
    cfgmod.save_state(db, st)
    db.commit()
    if auto_reqs:
        execute_block(db, auto_reqs, actor=ACTOR, who=WHO)
    try:
        reply.retry_failed(db)  # báo Teams chưa gửi được ở lượt trước
    except Exception:  # noqa: BLE001
        log.exception("Thử lại trả lời Teams lỗi")
    if pending_reqs:
        ips = ", ".join(r.ip for r in pending_reqs)
        _mail(db, cfg, f"autoblock_pending:{pending_reqs[0].id}", "autoblock_pending",
              f"[SOC Rapid Block] {len(pending_reqs)} IP chờ duyệt chặn",
              f"SOC đề xuất chặn {len(pending_reqs)} IP nhưng app chưa tự chặn:\n\n"
              + "\n".join(f"- {r.ip} · {r.sender_name} · {r.pending_reason}" for r in pending_reqs)
              + f"\n\nDuyệt / từ chối tại {_link()}.\nIP: {ips}")
    _maybe_digest(db, cfg, st)
    return {"ok": True, **stats}


def snapshot(db: Session, cfg: dict, row: AutoBlockMessage, m: dict, text: str, cmds: list[dict]) -> AutoBlockEvidence:
    """Chụp bằng chứng tin chứa lệnh BLOCK IP (nguyên văn Graph + SHA-256), nối chuỗi băm, COMMIT ngay —
    trước khi chặn, để bằng chứng tồn tại độc lập với việc người gửi xóa / sửa tin sau đó."""
    raw = json.dumps(m, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    user = ((m.get("from") or {}).get("user") or {})
    ev = AutoBlockEvidence(
        captured_at=_now(), message_id=row.id, msg_id=row.msg_id, chat_id=cfg.get("chat_id", "")[:255],
        sender_id=row.sender_id, sender_name=row.sender_name, sender_type=str(user.get("userIdentityType") or "")[:32],
        teams_created_at=graph._parse_ts(m.get("createdDateTime")),
        teams_modified_at=graph._parse_ts(m.get("lastModifiedDateTime")), status=row.status,
        commands=json.dumps([{"line": c["raw"], "ip": c["ip"] or c["value"], "error": c["error"]} for c in cmds],
                            ensure_ascii=False),
        text=text[:20000], raw_json=raw, sha256=hashlib.sha256(raw.encode()).hexdigest())
    hashchain.append(db, AutoBlockEvidence, [ev])
    return ev


def _follow_up(db: Session, m: dict) -> None:
    """Tin đã xử lý được Graph trả lại (lastModifiedDateTime đổi): ghi nhận nếu bị XÓA / SỬA trên Teams.
    Bản chụp bằng chứng gốc KHÔNG đổi; chỉ thêm mốc thời gian + sự kiện chuỗi băm."""
    row = db.scalars(select(AutoBlockMessage).where(AutoBlockMessage.msg_id == str(m.get("id"))[:64])).first()
    if row is None:
        return
    has_ev = db.scalar(select(func.count()).select_from(AutoBlockEvidence).where(AutoBlockEvidence.message_id == row.id))
    now = _now()
    deleted, edited = graph._parse_ts(m.get("deletedDateTime")), graph._parse_ts(m.get("lastEditedDateTime"))
    changed = False
    if deleted and not row.deleted_at:
        row.deleted_at, row.deleted_seen_at, changed = deleted, now, True
        if has_ev:
            event(db, "msg_deleted_after", detail=(f"Tin {row.msg_id} của {row.sender_name} (gửi {_vn(row.created_at)}) "
                                                   f"đã bị XÓA trên Teams lúc {_vn(deleted)} — bản chụp bằng chứng giữ nguyên"))
    if edited and not row.edited_at and not row.deleted_at:
        row.edited_at, row.edited_seen_at, changed = edited, now, True
        if has_ev:
            event(db, "msg_edited_after", detail=(f"Tin {row.msg_id} của {row.sender_name} (gửi {_vn(row.created_at)}) "
                                                  f"đã bị SỬA trên Teams lúc {_vn(edited)} sau khi app xử lý"))
    if changed:
        db.commit()


def _handle_message(db: Session, cfg: dict, st: dict, soc: dict, m: dict, created: dt.datetime, stats: dict,
                    auto_reqs: list, pending_reqs: list) -> None:
    user = ((m.get("from") or {}).get("user") or {})
    sid, name = str(user.get("id") or "").lower(), str(user.get("displayName") or "")[:160]
    body = m.get("body") or {}
    text = parser.html_to_text(body.get("content", ""), body.get("contentType", "html"))
    cmds = parser.find_commands(text)
    row = AutoBlockMessage(msg_id=str(m.get("id"))[:64], sender_id=sid[:64], sender_name=name, created_at=created,
                           received_at=_now(), status="processed",
                           body_hash=hashlib.sha256(text.encode()).hexdigest())
    if sid:
        seen = st.setdefault("seen_senders", {})
        e = seen.get(sid) or {"name": name, "count": 0}
        e.update(name=name or e["name"], count=e["count"] + 1, last=created.isoformat())
        seen[sid] = e
        if len(seen) > 30:  # chỉ giữ 30 người gửi gần nhất (để quản trị viên chọn tài khoản SOC)
            for k in sorted(seen, key=lambda k: seen[k].get("last", ""))[: len(seen) - 30]:
                seen.pop(k)
    if m.get("messageType") not in (None, "message") or not sid:
        row.status = "ignored_type"
    elif m.get("deletedDateTime"):
        row.status = "ignored_deleted"
    elif sid not in soc:
        row.status = "ignored_sender"
        if cmds:  # có người ngoài danh sách SOC gửi lệnh — ghi lại để điều tra
            event(db, "ignored_sender", ip=",".join(c["value"] for c in cmds)[:64],
                  detail=f"{name} ({sid}) gửi lệnh nhưng không thuộc danh sách tài khoản SOC")
    elif m.get("lastEditedDateTime"):
        row.status = "ignored_edited"
        if cmds:
            event(db, "ignored_edited", ip=",".join(c["value"] for c in cmds)[:64],
                  detail=f"Tin của {name} đã bị sửa — bỏ qua theo quy định (SOC cần gửi tin mới)")
    elif not cmds:
        row.status = "no_command"
    if row.status != "processed":
        db.add(row)
        db.flush()
        if cmds:  # lệnh bị bỏ qua (người lạ, tin đã sửa…) cũng chụp lại để điều tra
            snapshot(db, cfg, row, m, text, cmds)
        return
    row.excerpt = text[:2000] if cmds else ""
    db.add(row)
    db.flush()
    if cmds:
        snapshot(db, cfg, row, m, text, cmds)
    for c in cmds:
        stats["commands"] += 1
        _handle_command(db, cfg, st, row, c, stats, auto_reqs, pending_reqs)


def _handle_command(db: Session, cfg: dict, st: dict, msg: AutoBlockMessage, c: dict, stats: dict,
                    auto_reqs: list, pending_reqs: list) -> None:
    now = _now()
    req = AutoBlockRequest(message_id=msg.id, ip=(c["ip"] or c["value"])[:64], sender_name=msg.sender_name,
                           created_at=now, requested_at=msg.created_at, status="pending", mode="pending")
    sent = _aware(msg.created_at) or now  # thời điểm SOC gửi lệnh (createdDateTime của Graph)
    lag = now - sent
    if not c["ip"]:
        req.status, req.mode, req.note = "invalid", "invalid", c["error"]
    else:
        ok, bad = normalize_entries([c["ip"]])
        if not ok:
            req.status, req.mode, req.note = "invalid", "invalid", (bad[0].get("reason") if bad else "") or "IP không hợp lệ"
    if req.status == "invalid":
        stats["invalid"] += 1
        db.add(req)
        db.flush()
        event(db, "invalid", ip=req.ip, request_id=req.id, detail=req.note)
        return
    dup = db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.ip == req.ip,
                                                    AutoBlockRequest.status.in_(ACTIVE)).limit(1)).first()
    if dup is not None or any(r.ip == req.ip for r in auto_reqs + pending_reqs):
        req.status, req.mode, req.note = "duplicate", "duplicate", f"Đã có yêu cầu #{dup.id if dup else ''} cho IP này"
        stats["duplicate"] += 1
        db.add(req)
        db.flush()
        return
    reason = ""
    hit = cfgmod.whitelist_hit(cfg, req.ip)
    if hit:  # IP của HSC / Akamai / đối tác…: không bao giờ tự chặn, chờ quản trị viên Approve
        req.needs_admin, req.whitelist = True, f"{hit[0]}: {hit[1]}"[:160]
        reason = f"Thuộc whitelist {hit[0]} ({hit[1]}) — chờ quản trị viên Approve"
    elif not cfg["auto_enabled"]:
        reason = "Công tắc tự động chặn đang TẮT"
    elif lag > cfgmod.stale_after(cfg):
        reason = (f"Lệnh cũ: SOC gửi lúc {_vn(sent)}, app đọc trễ {int(lag.total_seconds() // 60)} phút "
                  f"(> {int(cfgmod.stale_after(cfg).total_seconds() // 60)} phút) — chờ duyệt")
    elif not cfgmod.in_window(cfg, sent):  # khung giờ theo LÚC SOC GỬI, không theo lúc app đọc
        reason = f"Ngoài khung giờ tự động — trong giờ hành chính ({cfgmod.schedule_text(cfg)})"
    elif st.get("breaker_tripped_at"):
        reason = f"Đã vượt ngưỡng {cfg['hourly_limit']} IP/giờ — chờ quản trị viên mở lại"
    else:
        used = auto_count_last_hour(db)  # gồm cả IP vừa quyết định trong lượt này (đã flush)
        if used >= cfg["hourly_limit"]:
            reason = f"Vượt ngưỡng {cfg['hourly_limit']} IP/giờ"
            _trip(db, cfg, st, used)
    if reason:
        req.pending_reason = reason
        stats["pending"] += 1
        db.add(req)
        db.flush()
        pending_reqs.append(req)
        event(db, "pending", ip=req.ip, request_id=req.id, detail=f"{msg.sender_name}: {reason}")
    else:
        req.mode, req.status = "auto", "blocking"
        stats["auto"] += 1
        db.add(req)
        db.flush()
        auto_reqs.append(req)
        event(db, "auto_block", ip=req.ip, request_id=req.id, detail=f"Lệnh của {msg.sender_name}")


def auto_count_last_hour(db: Session) -> int:
    since = _now() - dt.timedelta(hours=1)
    return db.scalar(select(func.count()).select_from(AutoBlockRequest).where(
        AutoBlockRequest.mode == "auto", AutoBlockRequest.created_at >= since)) or 0


def _trip(db: Session, cfg: dict, st: dict, used: int) -> None:
    now = _now()
    st.update(breaker_tripped_at=now.isoformat(),
              breaker_reason=f"{used} IP tự chặn trong 60 phút, vượt ngưỡng {cfg['hourly_limit']} IP/giờ")
    cfgmod.save_state(db, st)
    event(db, "breaker_tripped", detail=st["breaker_reason"])
    audit(db, action="autoblock_switch", fw=None, target="autoblock", result="error", actor=ACTOR,
          message=f"Ngắt ngưỡng: {st['breaker_reason']} — mọi lệnh tiếp theo chuyển sang chờ duyệt")
    db.commit()
    _mail(db, cfg, f"autoblock_breaker:{now.isoformat()}", "autoblock_breaker",
          f"[SOC Rapid Block] CẢNH BÁO: tự động chặn vượt ngưỡng {cfg['hourly_limit']} IP/giờ",
          f"Lúc {_vn(now)}, số IP SOC đề xuất chặn tự động đã vượt ngưỡng {cfg['hourly_limit']} IP/giờ.\n\n"
          "App đã NGỪNG tự chặn: mọi lệnh tiếp theo chuyển sang CHỜ DUYỆT cho tới khi quản trị viên mở lại.\n"
          "Kiểm tra group chat Teams (có thể có tin giả mạo / tài khoản SOC bị lộ) và danh sách vừa chặn tại "
          f"{_link()}.", urgent=True)


def reset_breaker(db: Session, *, actor: str, client_ip: str) -> dict:
    st = cfgmod.state(db)
    was = st.get("breaker_tripped_at")
    st.update(breaker_tripped_at="", breaker_reason="")
    cfgmod.save_state(db, st)
    audit(db, action="autoblock_switch", fw=None, target="autoblock", result="ok", actor=actor, client_ip=client_ip,
          message="Mở lại tự động chặn sau khi ngắt ngưỡng")
    db.commit()
    if was:
        event(db, "breaker_reset", actor=actor)
    return status(db)


def set_switch(db: Session, on: bool, *, actor: str, client_ip: str) -> dict:
    cfgmod.set_switch(db, on, actor=actor, client_ip=client_ip)
    event(db, "switch_on" if on else "switch_off", actor=actor)
    return status(db)


# ------------------------------------------------------------------ chặn / gỡ
def _targets(db: Session, cfg: dict) -> list[int]:
    stmt = select(Firewall.id).where(Firewall.enabled.is_(True))
    if cfg.get("firewall_ids"):
        stmt = stmt.where(Firewall.id.in_(cfg["firewall_ids"]))
    return list(db.scalars(stmt))


def _reason(r: AutoBlockRequest, actor: str) -> str:
    how = "Tự động" if actor == ACTOR else f"Duyệt bởi {actor}"
    return f"{how} — {parser.PREFIX} {r.ip} · {r.sender_name} (Teams) · yêu cầu #{r.id}"[:255]


def execute_block(db: Session, reqs: list[AutoBlockRequest], *, actor: str, who: dict) -> str | None:
    """Chặn các IP trên firewall đích bằng luồng chặn chung (job nền). Trả job_id."""
    cfg = cfgmod.raw(db)
    fw_ids = _targets(db, cfg)
    ids = [r.id for r in reqs]
    if not fw_ids:
        for r in reqs:
            r.status, r.note = "failed", "Không có firewall nào đang bật"
        db.commit()
        return None
    entries = [{"value": r.ip, "kind": "IP"} for r in reqs]
    reason = _reason(reqs[0], actor) if len(reqs) == 1 else f"{'Tự động' if actor == ACTOR else 'Duyệt bởi ' + actor} — {parser.PREFIX} (Teams) · {len(reqs)} IP"[:255]

    def work(s: Session, fw: Firewall) -> dict:
        return block_on_firewall(s, fw, entries, reason=reason, source="teams-auto", actor=actor, who=who)

    def on_done(results: list[dict]) -> dict:
        _finish(ids, results, "block")
        from ..ipblock.router import _after_write

        _after_write([r["firewall_id"] for r in results if r.get("summary", {}).get("added")])
        return {}

    job_id = jobs.submit("autoblock", actor, fw_ids, work, on_done=on_done,
                         meta={"entries": entries, "rejected": [], "dry_run": False, "autoblock_ids": ids})
    for r in reqs:
        r.job_id = job_id
    db.commit()
    return job_id


def _finish(ids: list[int], results: list[dict], kind: str) -> None:
    ok_res = ("added", "existed") if kind == "block" else ("removed", "not_found")
    with SessionLocal() as db:
        for r in db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.id.in_(ids))):
            per = []
            for fw in results:
                row = next((x for x in fw.get("rows", []) if x.get("value") == r.ip), None)
                res = row["result"] if row else "error"
                per.append({"firewall": fw.get("firewall"), "result": res,
                            "message": (row or {}).get("message") or fw.get("error", "")})
            good = bool(per) and all(p["result"] in ok_res for p in per)
            r.result_json = json.dumps(per, ensure_ascii=False)
            if kind == "block":
                r.status = "blocked" if good else "failed"
                if good:
                    r.blocked_at = _now()
                    reply.send(db, r)  # "INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>" vào group chat
            else:
                r.status = "unblocked" if good else "blocked"
                if not good:
                    r.note = "Gỡ chặn chưa thành công trên mọi firewall — thử lại"
            db.commit()
            ev = {"block": ("blocked", "block_failed"), "unblock": ("unblocked", "unblock_failed")}[kind][0 if good else 1]
            event(db, ev, ip=r.ip, request_id=r.id,
                  detail="; ".join(f"{p['firewall']}: {p['result']}" for p in per)[:2000])


def approve(db: Session, ids: list[int], *, p: dict, client_ip: str) -> str | None:
    reqs = list(db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.id.in_(ids),
                                                          AutoBlockRequest.status == "pending")))
    if not reqs:
        raise AppError(409, "Không có yêu cầu nào đang chờ duyệt trong danh sách đã chọn")
    wl = [r.ip for r in reqs if r.needs_admin]
    if wl and p.get("role") != "admin":
        raise AppError(403, f"IP thuộc whitelist chỉ quản trị viên được Approve: {', '.join(wl)}")
    now = _now()
    for r in reqs:
        r.status, r.decided_by, r.decided_at = "blocking", p["user"], now
        audit(db, action="autoblock_decision", fw=None, target=r.ip, result="ok", actor=p["user"],
              client_ip=client_ip, message=f"Approve chặn yêu cầu #{r.id}"
              + (f" — IP thuộc whitelist {r.whitelist}" if r.whitelist else ""))
    db.commit()
    for r in reqs:
        event(db, "approved", ip=r.ip, request_id=r.id, actor=p["user"],
              detail=f"IP thuộc whitelist {r.whitelist}" if r.whitelist else "")
    return execute_block(db, reqs, actor=p["user"], who=p)


def reject(db: Session, ids: list[int], *, p: dict, client_ip: str, note: str = "") -> int:
    reqs = list(db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.id.in_(ids),
                                                          AutoBlockRequest.status == "pending")))
    now = _now()
    for r in reqs:
        r.status, r.decided_by, r.decided_at, r.note = "rejected", p["user"], now, note[:500]
        audit(db, action="autoblock_decision", fw=None, target=r.ip, result="ok", actor=p["user"],
              client_ip=client_ip, message=f"Từ chối chặn yêu cầu #{r.id}" + (f": {note[:200]}" if note else ""))
    db.commit()
    for r in reqs:
        event(db, "rejected", ip=r.ip, request_id=r.id, actor=p["user"], detail=note[:500])
    return len(reqs)


def unblock(db: Session, ids: list[int], *, p: dict, client_ip: str) -> str:
    reqs = list(db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.id.in_(ids),
                                                          AutoBlockRequest.status.in_(("blocked", "failed")))))
    if not reqs:
        raise AppError(409, "Không có IP nào đang bị chặn trong danh sách đã chọn")
    cfg = cfgmod.raw(db)
    fw_ids = _targets(db, cfg)
    if not fw_ids:
        raise AppError(400, "Không có firewall nào đang bật")
    now = _now()
    for r in reqs:
        r.status, r.unblocked_by, r.unblocked_at = "unblocking", p["user"], now
    db.commit()
    rid = [r.id for r in reqs]
    targets = [r.ip for r in reqs]
    reason = f"Gỡ chặn tự động (Teams) bởi {p['user']} · {len(reqs)} IP"[:255]

    def work(s: Session, fw: Firewall) -> dict:
        return unblock_on_firewall(s, fw, targets, delete_object=False, reason=reason, actor=p["user"],
                                   client_ip=client_ip, who=p)

    def on_done(results: list[dict]) -> dict:
        _finish(rid, results, "unblock")
        from ..ipblock.router import _after_write

        _after_write([r["firewall_id"] for r in results if r.get("summary", {}).get("removed")])
        return {}

    return jobs.submit("unblock", p["user"], fw_ids, work, on_done=on_done,
                       meta={"targets": targets, "autoblock_ids": rid})


# ------------------------------------------------------------------ báo cáo
def to_dict(r: AutoBlockRequest) -> dict:
    try:
        res = json.loads(r.result_json) if r.result_json else []
    except ValueError:
        res = []
    return {"id": r.id, "ip": r.ip, "sender": r.sender_name, "created_at": _aware(r.created_at).isoformat(),
            "requested_at": _aware(r.requested_at).isoformat() if r.requested_at else None,
            "mode": r.mode, "status": r.status, "pending_reason": r.pending_reason, "note": r.note,
            "needs_admin": bool(r.needs_admin), "whitelist": r.whitelist,
            "reply_status": r.reply_status, "reply_attempts": r.reply_attempts,
            "replied_at": _aware(r.replied_at).isoformat() if r.replied_at else None,
            "blocked_at": _aware(r.blocked_at).isoformat() if r.blocked_at else None,
            "job_id": r.job_id, "results": res, "decided_by": r.decided_by,
            "decided_at": _aware(r.decided_at).isoformat() if r.decided_at else None,
            "unblocked_by": r.unblocked_by,
            "unblocked_at": _aware(r.unblocked_at).isoformat() if r.unblocked_at else None}


def list_requests(db: Session, *, view: str = "all", status_: str = "", limit: int = 500) -> dict:
    stmt = select(AutoBlockRequest)
    start = end = None
    if view == "night":
        start, end = cfgmod.off_hours_span(cfgmod.raw(db))
        start, end = start.astimezone(dt.timezone.utc), end.astimezone(dt.timezone.utc)  # cột lưu UTC
        stmt = stmt.where(func.coalesce(AutoBlockRequest.requested_at, AutoBlockRequest.created_at) >= start,
                          func.coalesce(AutoBlockRequest.requested_at, AutoBlockRequest.created_at) < end,
                          AutoBlockRequest.mode == "auto")
    elif view == "pending":
        stmt = stmt.where(AutoBlockRequest.status == "pending")
    if status_:
        stmt = stmt.where(AutoBlockRequest.status == status_)
    rows = list(db.scalars(stmt.order_by(AutoBlockRequest.id.desc()).limit(limit)))
    out = {"items": [to_dict(r) for r in rows]}
    if start:
        out["night"] = {"start": start.astimezone(cfgmod.VN_TZ).isoformat(), "end": end.astimezone(cfgmod.VN_TZ).isoformat()}
    return out


def status(db: Session) -> dict:
    cfg = cfgmod.raw(db)
    st = cfgmod.state(db)
    start, end = cfgmod.off_hours_span(cfg)
    pending = db.scalar(select(func.count()).select_from(AutoBlockRequest)
                        .where(AutoBlockRequest.status == "pending")) or 0
    return {
        "enabled": cfg["enabled"], "configured": cfgmod.configured(cfg), "auto_enabled": cfg["auto_enabled"],
        "window_enabled": cfg["window_enabled"], "window_start": cfg["window_start"], "window_end": cfg["window_end"],
        "in_window": cfgmod.in_window(cfg), "window_reason": cfgmod.window_reason(cfg),
        "weekend_full": cfg["weekend_full"], "holidays": cfg["holidays"], "schedule": cfgmod.schedule_text(cfg),
        "holiday_today": bool(cfgmod._holiday(cfg, _now().astimezone(cfgmod.VN_TZ).date())),
        "hourly_limit": cfg["hourly_limit"],
        "auto_last_hour": auto_count_last_hour(db), "poll_seconds": cfg["poll_seconds"],
        "scheduler": settings.AUTOBLOCK_POLL_SECONDS > 0,
        "breaker_tripped_at": st.get("breaker_tripped_at") or None, "breaker_reason": st.get("breaker_reason", ""),
        "last_poll_at": st.get("last_poll_at") or None, "last_ok": st.get("last_ok"),
        "last_error": st.get("last_error", ""), "pending": pending,
        "cursor": st.get("cursor") or None, "last_fetched": st.get("last_fetched", 0),
        "last_truncated": bool(st.get("last_truncated")), "server_filter": st.get("server_filter"),
        "stale_minutes": int(cfgmod.stale_after(cfg).total_seconds() // 60), "soc_senders": len(cfg["soc_senders"]),
        "night": {"start": start.isoformat(), "end": end.isoformat()}, "syntax": f"{parser.PREFIX} <ip>",
        "reply_enabled": bool(cfg["reply_enabled"] and cfg["reply_url_enc"]),
        "reply_syntax": reply.TEMPLATE.format(ip="<ip>", ts="<thời điểm>"),
    }


def seen_senders(db: Session) -> list[dict]:
    seen = cfgmod.state(db).get("seen_senders", {})
    return sorted(({"id": k, **v} for k, v in seen.items()), key=lambda x: x.get("last", ""), reverse=True)


def test_connection(db: Session) -> dict:
    """Lấy token + đọc 50 tin gần nhất (không xử lý) — để quản trị viên kiểm tra quyền và chọn tài khoản SOC."""
    cfg = cfgmod.raw(db)
    if not cfgmod.configured(cfg):
        raise AppError(400, "Cần nhập đủ Tenant ID, Client ID, Client secret và Chat ID")
    try:
        msgs = graph.list_messages(cfg, _now() - dt.timedelta(days=30), max_pages=1)
    except graph.GraphError as exc:
        raise AppError(502, str(exc)) from exc
    senders: dict[str, dict] = {}
    for m in msgs:
        u = ((m.get("from") or {}).get("user") or {})
        if u.get("id"):
            s = senders.setdefault(u["id"].lower(), {"id": u["id"].lower(), "name": u.get("displayName") or "",
                                                     "count": 0, "commands": 0})
            s["count"] += 1
            body = m.get("body") or {}
            s["commands"] += len(parser.find_commands(parser.html_to_text(body.get("content", ""),
                                                                          body.get("contentType", "html"))))
    soc = {s["id"] for s in cfg["soc_senders"]}
    return {"ok": True, "messages": len(msgs),
            "senders": [{**s, "is_soc": s["id"] in soc} for s in senders.values()]}


def _maybe_digest(db: Session, cfg: dict, st: dict) -> None:
    """Khi một ca ngoài giờ kết thúc (vd 08:00 sáng, 08:00 thứ 2 sau cuối tuần / sau kỳ nghỉ lễ): email nhóm Admin
    danh sách lệnh trong ca. Mỗi ca một lần (khóa = thời điểm kết thúc ca); ca đã hết hơn 12 giờ thì bỏ qua."""
    now = _now()
    if not cfg.get("window_enabled") or cfgmod.in_window(cfg, now):
        return
    start, end = cfgmod.off_hours_span(cfg, now)
    today = end.isoformat()
    if st.get("digest_date") == today or now - end > dt.timedelta(hours=12):
        return
    start, end = start.astimezone(dt.timezone.utc), end.astimezone(dt.timezone.utc)
    rows = list(db.scalars(select(AutoBlockRequest).where(
        AutoBlockRequest.created_at >= start, AutoBlockRequest.created_at < end).order_by(AutoBlockRequest.id)))
    st["digest_date"] = today
    cfgmod.save_state(db, st)
    db.commit()
    if not rows:
        return
    lines = [f"- {_vn(r.created_at)} · {r.ip} · {r.status} · {r.sender_name}"
             + (f" · {r.pending_reason}" if r.pending_reason else "") for r in rows]
    auto = sum(1 for r in rows if r.mode == "auto")
    _mail(db, cfg, f"autoblock_digest:{today[:16]}", "autoblock_digest",
          f"[SOC Rapid Block] Ca ngoài giờ {_vn(start)} – {_vn(end)}: {auto} IP tự chặn, "
          f"{sum(1 for r in rows if r.status == 'pending')} chờ duyệt",
          "Danh sách lệnh chặn SOC gửi trong ca ngoài giờ:\n\n" + "\n".join(lines)
          + f"\n\nRà soát, gỡ chặn nếu nhầm, duyệt mục còn chờ tại {_link()}.")


# ------------------------------------------------------------------ bằng chứng
def evidence_for(db: Session, request_id: int) -> dict:
    r = db.get(AutoBlockRequest, request_id)
    if r is None:
        raise AppError(404, "Không tìm thấy lệnh")
    msg = db.get(AutoBlockMessage, r.message_id)
    ev = db.scalars(select(AutoBlockEvidence).where(AutoBlockEvidence.message_id == r.message_id)
                    .order_by(AutoBlockEvidence.id)).first()
    if ev is None or msg is None:
        raise AppError(404, "Lệnh này chưa có bản chụp bằng chứng (tạo trước phiên bản có tính năng bằng chứng)")
    iso = lambda t: _aware(t).isoformat() if t else None  # noqa: E731
    intact = hashlib.sha256(ev.raw_json.encode()).hexdigest() == ev.sha256 and hashchain.digest(ev) == ev.row_hash
    teams_state = ("deleted" if msg.deleted_at else "edited" if msg.edited_at else "intact")
    return {
        "request": to_dict(r),
        "evidence": {
            "id": ev.id, "captured_at": iso(ev.captured_at), "msg_id": ev.msg_id, "chat_id": ev.chat_id,
            "sender_id": ev.sender_id, "sender_name": ev.sender_name, "sender_type": ev.sender_type,
            "teams_created_at": iso(ev.teams_created_at), "teams_modified_at": iso(ev.teams_modified_at),
            "status_at_capture": ev.status, "commands": json.loads(ev.commands or "[]"), "text": ev.text,
            "sha256": ev.sha256, "row_hash": ev.row_hash, "prev_hash": ev.prev_hash, "intact": intact,
        },
        "teams_now": {"state": teams_state, "deleted_at": iso(msg.deleted_at), "deleted_seen_at": iso(msg.deleted_seen_at),
                      "edited_at": iso(msg.edited_at), "edited_seen_at": iso(msg.edited_seen_at)},
        "raw_json": ev.raw_json,
    }
