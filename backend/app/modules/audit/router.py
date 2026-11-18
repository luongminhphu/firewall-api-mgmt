"""/api/audit, /api/audit.csv."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ...auth.rbac import current_user, principal
from ...core.db import get_session
from ...core.models import AuditLog

router = APIRouter()


@router.get("/api/audit")
def audit_list(
    limit: int = Query(default=200, le=2000),
    action: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    stmt = select(AuditLog).order_by(desc(AuditLog.id)).limit(limit)
    if action:
        stmt = select(AuditLog).where(AuditLog.action == action).order_by(desc(AuditLog.id)).limit(limit)
    rows = [r.to_dict() for r in db.scalars(stmt).all()]
    if q:
        needle = q.lower()
        rows = [
            r for r in rows
            if needle in (r["target"] or "").lower()
            or needle in (r["firewall_name"] or "").lower()
            or needle in (r["reason"] or "").lower()
        ]
    return {"rows": rows, "count": len(rows)}


@router.get("/api/audit.csv")
def audit_csv(
    token: str = Query(default=""),
    db: Session = Depends(get_session),
):
    principal(token, db)  # cùng kiểm tra như API: token hợp lệ, user chưa bị khóa/xóa
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.id)).limit(5000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["thoi_gian", "nguoi_thuc_hien", "hanh_dong", "firewall", "group",
                "doi_tuong", "ket_qua", "ma_loi", "thong_diep", "ly_do", "nguon", "ip_client"])
    for r in rows:
        d = r.to_dict()
        w.writerow([d["ts"], d["actor"], d["action"], d["firewall_name"], d["group_name"],
                    d["target"], d["result"], d["status_code"], d["message"], d["reason"],
                    d["source"], d["client_ip"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_soc_rapid_block.csv"},
    )
