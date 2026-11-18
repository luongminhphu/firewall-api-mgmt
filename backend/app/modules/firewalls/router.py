"""/api/firewalls — router mỏng: phân quyền, schema vào/ra, gọi service."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Request
from sqlalchemy.orm import Session

from ... import group_cache as gc
from ... import jobs
from ...auth.rbac import admin, current_user, operator
from ...core.config import settings
from ...core.db import get_session
from ...core.deps import client_ip_of, selected_firewalls
from . import repository as repo
from . import service
from .schemas import FirewallCreateIn, FirewallOut, FirewallUpdateIn, TestAllIn, TestResultOut

router = APIRouter()


@router.get("/api/firewalls", response_model=list[FirewallOut])
def list_firewalls(db: Session = Depends(get_session), user: str = Depends(current_user)):
    return [f.to_dict() for f in repo.list_all(db)]


@router.post("/api/firewalls", response_model=FirewallOut)
def create_firewall(request: Request, bg: BackgroundTasks, payload: FirewallCreateIn = Body(...),
                    db: Session = Depends(get_session), p: dict = Depends(admin)):
    fw = service.create(db, payload, actor=p["user"], client_ip=client_ip_of(request))
    bg.add_task(gc.refresh_now, fw.id, force=True)
    return fw.to_dict()


@router.put("/api/firewalls/{fw_id}", response_model=FirewallOut)
def update_firewall(fw_id: int, request: Request, bg: BackgroundTasks, payload: FirewallUpdateIn = Body(...),
                    db: Session = Depends(get_session), p: dict = Depends(admin)):
    fw = service.update(db, fw_id, payload, actor=p["user"], client_ip=client_ip_of(request))
    gc.mark_dirty(db, [fw.id])
    bg.add_task(gc.refresh_now, fw.id, force=True, mode="full")  # host/tài khoản có thể đã đổi
    return fw.to_dict()


@router.delete("/api/firewalls/{fw_id}")
def delete_firewall(fw_id: int, request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    name = service.delete(db, fw_id, actor=p["user"], client_ip=client_ip_of(request),
                          on_delete=lambda s, fw: gc.drop(s, fw.id))
    return {"ok": True, "deleted": name}


@router.post("/api/firewalls/{fw_id}/test", response_model=TestResultOut)
def test_one(fw_id: int, request: Request, db: Session = Depends(get_session), p: dict = Depends(operator)):
    return service.test_firewall(db, service.get_or_404(db, fw_id), p["user"], client_ip_of(request))


@router.post("/api/firewalls/test-all")
def test_all(request: Request, payload: TestAllIn = Body(default=TestAllIn()),
             db: Session = Depends(get_session), p: dict = Depends(operator)):
    user, ip = p["user"], client_ip_of(request)
    ids = [fw.id for fw in selected_firewalls(db, payload.firewall_ids)]
    job_id = jobs.submit("test", user, ids, lambda s, fw: service.test_firewall(s, fw, user, ip))
    jobs.wait(job_id, settings.API_CONNECT_TIMEOUT + settings.API_TIMEOUT + 5)
    db.expire_all()
    return {"results": jobs.to_dict(jobs.get(db, job_id))["results"]}
