"""/api/firewalls/{id}/group*, /api/group-cache, /api/parse, /api/block, /api/unblock, /api/jobs."""
from __future__ import annotations

import datetime as dt
import threading

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core import jobs
from ...auth.rbac import current_user, operator, principal, role_at_least
from ...core.config import settings
from ...core.db import get_session
from ...core.deps import job_response, client_ip_of, get_fw, selected_firewalls
from ...core.models import Firewall
from ...integrations.sophos.policy import BLOCK_GROUP
from ..shared import enforce_group_audited
from . import group_cache as gc
from .parse import extract, host_object_name
from .schemas import BlockIn, ParseIn, UnblockIn
from .service import block_on_firewall, derive_host, normalize_entries, unblock_on_firewall

router = APIRouter()


def locked_group(db: Session, request: Request, requested, actor: str) -> str:
    """Áp chính sách group cố định; vi phạm → 403 và ghi audit 'policy_violation'."""
    return enforce_group_audited(db, requested, actor=actor, client_ip=client_ip_of(request))


@router.get("/api/firewalls/{fw_id}/groups")
def fw_groups(
    fw_id: int, db: Session = Depends(get_session), user: str = Depends(current_user)
):
    fw = get_fw(db, fw_id)
    row = gc.get_row(db, fw.id)
    if row is None or row.scanned_at is None:
        row = _scan_wait(db, fw, "full") or row  # chưa có cache: quét (chờ tối đa GROUP_CACHE_REFRESH_WAIT giây)
    d = gc.data(row)
    if row is None or not d:
        if row is not None and row.status == "error":
            raise HTTPException(502, row.error)
        return {"firewall": fw.name, "default_group": BLOCK_GROUP, "locked": True, "groups": [],
                "pending": True, "cache": gc.meta(row)}
    groups = []
    if d.get("exists"):
        groups = [{"name": d.get("group", BLOCK_GROUP), "description": d.get("description", ""),
                   "ip_family": d.get("ip_family", ""), "count": d.get("total", 0)}]
    return {"firewall": fw.name, "default_group": BLOCK_GROUP, "locked": True, "groups": groups,
            "cache": gc.meta(row)}


def _schedule_refresh(bg: BackgroundTasks, fw_ids: list[int], force: bool = True, mode: str = "lite",
                      hints: dict[int, dict] | None = None) -> None:
    """Sau thao tác ghi: quét NHẸ (group theo tên + chi tiết từ cache/tên) — nhanh kể cả firewall nhiều object."""
    for fid in dict.fromkeys(fw_ids):
        bg.add_task(gc.refresh_now, fid, force=force, mode=mode, hints=(hints or {}).get(fid))


def _scan_wait(db: Session, fw, mode: str = "full"):
    """Quét trong luồng riêng, chờ tối đa GROUP_CACHE_REFRESH_WAIT giây.

    Xong kịp → trả row mới. Firewall chậm → trả None, lượt quét vẫn chạy nền; giao diện hỏi /group-cache để cập nhật.
    Tránh request treo quá timeout của Entra App Proxy (~85 giây) / NGINX.
    """
    import threading

    t = threading.Thread(target=gc.refresh_now, args=(fw.id,), kwargs={"force": True, "mode": mode},
                         name=f"scan-{fw.id}", daemon=True)
    t.start()
    t.join(settings.GROUP_CACHE_REFRESH_WAIT)
    db.expire_all()
    row = gc.get_row(db, fw.id)
    return None if t.is_alive() else row


def _block_hints(results: list[dict], reason: str) -> dict[int, dict]:
    """Chi tiết object vừa tạo (giá trị + ghi chú = lý do) để cache hiển thị đủ ngay, không cần đọc lại firewall."""
    out: dict[int, dict] = {}
    for r in results:
        h = {}
        for row in r.get("rows", []):
            if row.get("result") == "added" and row.get("object"):
                v = row.get("value", "")
                d = derive_host(v) or {}
                h[row["object"]] = {**d, "name": row["object"], "description": (reason or "")[:255], "derived": False}
        if h:
            out[r["firewall_id"]] = h
    return out


@router.get("/api/firewalls/{fw_id}/group-members")
def fw_group_members(
    fw_id: int,
    request: Request,
    bg: BackgroundTasks,
    group: str = Query(default=""),
    q: str = Query(default=""),
    refresh: bool = Query(default=False),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    """Trả danh sách từ cache (nhanh). refresh=1: quét lại firewall ngay. Cache cũ/dirty: trả ngay + quét nền."""
    group = locked_group(db, request, group, user)
    fw = get_fw(db, fw_id)
    row = gc.get_row(db, fw.id)
    source = "cache"
    if refresh and row is not None and not gc.can_force(row):
        refresh = False  # vừa quét xong vài giây trước — dùng luôn kết quả đó
    if row is None or row.scanned_at is None or refresh:
        new = _scan_wait(db, fw, "full")
        if new is not None:
            row, source = new, "live"
        else:
            row = gc.get_row(db, fw.id)  # firewall chậm: trả cache cũ (nếu có), lượt quét tiếp tục nền
            if row is None or not gc.data(row):
                return {"firewall": fw.name, "group": group, "description": "", "ip_family": "", "total": 0,
                        "members": [], "source": "pending", "pending": True, "cache": gc.meta(row)}
    else:
        m = gc.meta(row)
        if (m["stale"] or m["dirty"]) and not m["refreshing"]:
            row.refreshing_since = dt.datetime.now(dt.timezone.utc)
            db.commit()
            _schedule_refresh(bg, [fw.id], mode="full" if m["stale"] else "lite")
    d = gc.data(row)
    if not d:
        raise HTTPException(502, row.error or f"Không đọc được group trên {fw.name}")
    if not d.get("exists"):
        raise HTTPException(404, f"Group '{group}' không tồn tại trên {fw.name}")
    members = d.get("members", [])
    if q:
        needle = q.lower().strip()
        members = [m for m in members if needle in m["object"].lower() or needle in m["value"].lower()]
    return {
        "firewall": fw.name, "group": d.get("group", group), "description": d.get("description", ""),
        "ip_family": d.get("ip_family", ""), "total": d.get("total", 0), "members": members,
        "source": source, "cache": gc.meta(row),
    }


@router.get("/api/firewalls/{fw_id}/group-cache")
def fw_group_cache(fw_id: int, db: Session = Depends(get_session), user: str = Depends(current_user)):
    """Trạng thái cache (nhẹ, để giao diện hỏi định kỳ khi đang quét lại)."""
    fw = get_fw(db, fw_id)
    row = gc.get_row(db, fw.id)
    return {"firewall_id": fw.id, "firewall": fw.name, "total": gc.data(row).get("total"), **gc.meta(row)}


@router.get("/api/group-cache")
def group_cache_overview(db: Session = Depends(get_session), user: str = Depends(current_user)):
    """Tổng quan cache SCANPORT GROUP của mọi firewall (không kèm danh sách thành viên)."""
    out = []
    for fw in db.scalars(select(Firewall).order_by(Firewall.name)):
        row = gc.get_row(db, fw.id)
        d = gc.data(row)
        out.append({"firewall_id": fw.id, "firewall": fw.name, "site": fw.site, "enabled": fw.enabled,
                    "exists": d.get("exists"), "total": d.get("total"), **gc.meta(row)})
    return {"group": BLOCK_GROUP, "ttl_minutes": settings.GROUP_CACHE_TTL_MINUTES,
            "daily_at": settings.GROUP_CACHE_DAILY_AT, "firewalls": out}


@router.post("/api/parse")
def parse_text(payload: ParseIn = Body(...), user: str = Depends(current_user)):
    text = payload.text or ""
    extra_safe = payload.extra_safe or []
    res = extract(text, extra_safe)
    for item in res["accepted"]:
        item["object"] = host_object_name(item["value"])
    return res


def _after_write(changed: list[int], hints: dict[int, dict] | None = None) -> None:
    """Sau khi ghi firewall: đánh dấu cache cũ + quét nhẹ lại (luồng nền, không giữ request)."""
    if not changed:
        return
    from ...core.db import SessionLocal

    with SessionLocal() as s:
        gc.mark_dirty(s, changed)
    for fid in dict.fromkeys(changed):
        threading.Thread(target=gc.refresh_now, args=(fid,),
                         kwargs={"force": True, "mode": "lite", "hints": (hints or {}).get(fid)},
                         name=f"refresh-{fid}", daemon=True).start()


@router.post("/api/block")
def block(
    request: Request,
    payload: BlockIn = Body(...),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    user = p["user"]
    locked_group(db, request, payload.group, user)
    values: list[str] = [str(v) for v in (payload.values or [])]
    if payload.text:
        values += [i["value"] for i in extract(payload.text, payload.extra_safe)["accepted"]]
    entries, rejected = normalize_entries(values, payload.extra_safe)
    if not entries:
        raise HTTPException(400, "Không có IP hợp lệ nào để chặn")
    if len(entries) > 500:
        raise HTTPException(400, "Tối đa 500 IP mỗi lần để tránh treo firewall")

    fws = selected_firewalls(db, payload.firewall_ids)
    ip = client_ip_of(request)
    reason = payload.reason or ""
    source = payload.source or "manual"
    dry = bool(payload.dry_run)

    def work(s: Session, fw: Firewall) -> dict:
        return block_on_firewall(s, fw, entries, reason=reason, source=source, actor=user, client_ip=ip,
                                 dry_run=dry, who=p)

    def on_done(results: list[dict]) -> dict:
        if dry:
            return {"cache_refresh": []}
        changed = [r["firewall_id"] for r in results if r.get("summary", {}).get("added")]
        _after_write(changed, _block_hints(results, reason))  # cache khớp firewall (kèm chi tiết object vừa tạo)
        return {"cache_refresh": changed}

    job_id = jobs.submit("block", user, [fw.id for fw in fws], work, on_done=on_done,
                         meta={"entries": entries, "rejected": rejected, "dry_run": dry,
                               "firewalls": [{"id": fw.id, "name": fw.name} for fw in fws]})
    return job_response(db, job_id)


@router.post("/api/unblock")
def unblock(
    request: Request,
    payload: UnblockIn = Body(...),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    user = p["user"]
    locked_group(db, request, payload.group, user)
    targets = [str(t).strip() for t in (payload.targets or []) if str(t).strip()]
    if not targets:
        raise HTTPException(400, "Chưa chọn IP/object nào để bỏ chặn")
    fws = selected_firewalls(db, payload.firewall_ids)
    ip = client_ip_of(request)
    delete_object = bool(payload.delete_object)
    reason = payload.reason or ""

    def work(s: Session, fw: Firewall) -> dict:
        return unblock_on_firewall(s, fw, targets, delete_object=delete_object, reason=reason,
                                   actor=user, client_ip=ip, who=p)

    def on_done(results: list[dict]) -> dict:
        changed = [r["firewall_id"] for r in results if r.get("summary", {}).get("removed")]
        _after_write(changed)
        return {"cache_refresh": changed}

    job_id = jobs.submit("unblock", user, [fw.id for fw in fws], work, on_done=on_done,
                         meta={"targets": targets,
                               "firewalls": [{"id": fw.id, "name": fw.name} for fw in fws]})
    return job_response(db, job_id)


@router.get("/api/jobs/{job_id}")
def job_status(job_id: str, db: Session = Depends(get_session), p: dict = Depends(principal)):
    """Tiến độ / kết quả một lượt chặn hoặc bỏ chặn chạy nền. Chỉ người tạo hoặc quản trị viên xem được."""
    job = jobs.get(db, job_id[:32])
    if job is None or (job.actor != p["user"] and not role_at_least(p["role"], "admin")):
        raise HTTPException(404, "Không tìm thấy công việc (đã hết hạn lưu hoặc không thuộc về bạn)")
    return jobs.to_dict(job)
