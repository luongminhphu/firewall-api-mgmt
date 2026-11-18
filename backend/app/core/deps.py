"""Tiện ích tầng HTTP dùng chung giữa các router (không chứa nghiệp vụ)."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import jobs
from .config import settings
from .models import Firewall


def client_ip_of(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def get_fw(db: Session, fw_id: int) -> Firewall:
    fw = db.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, f"Không tìm thấy firewall id={fw_id}")
    return fw


def selected_firewalls(db: Session, ids: list[int] | None) -> list[Firewall]:
    stmt = select(Firewall).where(Firewall.enabled.is_(True))
    if ids:
        stmt = select(Firewall).where(Firewall.id.in_(ids))
    fws = list(db.scalars(stmt).all())
    if not fws:
        raise HTTPException(400, "Chưa chọn firewall nào (hoặc firewall đang bị tắt)")
    return fws


def job_response(db: Session, job_id: str) -> JSONResponse:
    """Chờ công việc nền tối đa JOB_SYNC_WAIT giây. Xong → 200 + kết quả; chưa xong → 202 + tiến độ
    (giao diện hỏi /api/jobs/{id}) — tránh request treo tới timeout App Proxy / ingress (504)."""
    finished = jobs.wait(job_id, settings.JOB_SYNC_WAIT)
    db.expire_all()
    body = jobs.to_dict(jobs.get(db, job_id))
    return JSONResponse(body, status_code=200 if finished and body["status"] != "running" else 202)
