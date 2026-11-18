"""/api/changes* — nhật ký thay đổi SCANPORT GROUP (hash chain), xuất CSV, đồng bộ phát hiện drift."""
from __future__ import annotations

import csv
import datetime as dt
import io

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ...auth.rbac import current_user, operator, principal
from ...core.db import get_session
from ...core.deps import client_ip_of, selected_firewalls
from ...integrations.sophos import SophosAuthError, SophosError
from ...integrations.sophos.policy import BLOCK_GROUP
from ..shared import enforce_group_audited
from . import changelog
from .router import _schedule_refresh
from .schemas import SyncIn
from .service import _host_value, cached_details, client_for, resolve_hosts

router = APIRouter()


def locked_group(db: Session, request: Request, requested, actor: str) -> str:
    """Áp chính sách group cố định; vi phạm → 403 và ghi audit 'policy_violation'."""
    return enforce_group_audited(db, requested, actor=actor, client_ip=client_ip_of(request))


def _parse_day(v: str, end: bool = False) -> dt.datetime | None:
    if not v:
        return None
    try:
        d = dt.date.fromisoformat(v)
    except ValueError as exc:
        raise HTTPException(400, f"Ngày không hợp lệ: {v} (định dạng YYYY-MM-DD)") from exc
    tz = dt.timezone(dt.timedelta(hours=7))  # Asia/Ho_Chi_Minh
    base = dt.datetime.combine(d, dt.time.min, tzinfo=tz)
    return base + dt.timedelta(days=1) if end else base


@router.get("/api/changes")
def changes(
    request: Request,
    firewall_id: int | None = Query(default=None),
    group: str = Query(default=""),
    type: str = Query(default=""),
    actor: str = Query(default=""),
    q: str = Query(default=""),
    date_from: str = Query(default="", alias="from"),
    date_to: str = Query(default="", alias="to"),
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    group = locked_group(db, request, group, user)
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=group, change_type=type, actor=actor.strip(),
        q=q, date_from=_parse_day(date_from), date_to=_parse_day(date_to, end=True),
        limit_batches=limit,
    )
    totals = {
        "batches": len(batches),
        "added": sum(len(b["added"]) for b in batches),
        "removed": sum(len(b["removed"]) for b in batches),
        "drift": sum(1 for b in batches if b["kind"] == "drift"),
    }
    return {"batches": batches, "totals": totals, "groups": [BLOCK_GROUP], "locked_group": BLOCK_GROUP}


@router.get("/api/changes.csv")
def changes_csv(
    token: str = Query(default=""),
    firewall_id: int | None = Query(default=None),
    group: str = Query(default=""),
    q: str = Query(default=""),
    date_from: str = Query(default="", alias="from"),
    date_to: str = Query(default="", alias="to"),
    db: Session = Depends(get_session),
):
    principal(token, db)  # cùng kiểm tra như API: token hợp lệ, user chưa bị khóa/xóa
    if group.strip() not in ("", BLOCK_GROUP):
        raise HTTPException(403, f"Chỉ xuất lịch sử của IP Host Group '{BLOCK_GROUP}'")
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=BLOCK_GROUP, q=q,
        date_from=_parse_day(date_from), date_to=_parse_day(date_to, end=True), limit_batches=5000,
    )
    labels = {"change": "thao tac trong app", "drift": "thay doi ngoai app",
              "baseline": "trang thai ban dau", "create_group": "tao group"}
    buf = io.StringIO()
    buf.write("\ufeff")  # BOM để Excel đọc đúng tiếng Việt
    w = csv.writer(buf)
    w.writerow(["thoi_gian_vn", "lo_thao_tac", "loai", "thay_doi", "ip_cidr", "object", "firewall",
                "group", "so_object_truoc", "so_object_sau", "nguoi_thuc_hien", "ten_hien_thi",
                "phuong_thuc_dang_nhap", "ly_do", "nguon", "ip_client"])
    for b in batches:
        lines = [("+", i) for i in b["added"]] + [("-", i) for i in b["removed"]] or [("", {"value": "", "object": ""})]
        for sign, it in lines:
            w.writerow([changelog.vn_time(b["ts"]), b["batch_id"], labels.get(b["kind"], b["kind"]),
                        {"+": "THEM", "-": "BOT"}.get(sign, ""), it["value"], it["object"],
                        b["firewall_name"], b["group_name"], b["count_before"], b["count_after"],
                        b["actor"], b["actor_name"], b["auth_method"], b["reason"], b["source"],
                        b["client_ip"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=lich_su_thay_doi_object_group.csv"},
    )


@router.get("/api/changes/verify")
def changes_verify(db: Session = Depends(get_session), user: str = Depends(current_user)):
    return changelog.verify_chain(db)


@router.post("/api/changes/sync")
def changes_sync(
    request: Request,
    bg: BackgroundTasks,
    payload: SyncIn = Body(default=SyncIn()),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    """Đọc lại group cố định trên firewall để phát hiện thay đổi ngoài app."""
    group = locked_group(db, request, payload.group, p["user"])
    fws = selected_firewalls(db, payload.firewall_ids)
    out = []
    for fw in fws:
        try:
            with client_for(fw) as cli:
                g = cli.get_group(group)
                hosts = list(g["hosts"]) if g else []
                det, _ = resolve_hosts(cli, hosts, cached_details(db, fw.id)) if hosts else ({}, [])
            details = {n: _host_value(h) for n, h in det.items()}
            res = changelog.detect_drift(db, fw, group, {h: details.get(h, "") for h in hosts})
            db.commit()
            out.append({"firewall": fw.name, "group": group, "ok": True, "exists": bool(g),
                        "total": len(hosts), **res})
        except (SophosError, SophosAuthError, ValueError) as exc:
            db.rollback()
            out.append({"firewall": fw.name, "group": group, "ok": False, "error": str(exc)})
    _schedule_refresh(bg, [fw.id for fw in fws])
    return {"results": out}
