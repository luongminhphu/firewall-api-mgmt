"""/api/vpn/* — module VPN (CHỈ ĐỌC trên firewall). viewer: xem; operator: đồng bộ; admin: cấu hình (phase 4–5)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import current_user, operator
from ...core import jobs
from ...core.db import get_session
from ...core.deps import client_ip_of, job_response, selected_firewalls
from ...core.models import Firewall
from . import accounts

router = APIRouter()


class SyncIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    firewall_ids: list[int] | None = None


@router.get("/api/vpn/accounts")
def vpn_accounts(
    firewall_id: int | None = Query(default=None),
    q: str = Query(default="", max_length=120),
    scope: Literal["vpn", "all"] = Query(default="vpn"),
    state: Literal["present", "removed", "all"] = Query(default="present"),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    """Danh sách tài khoản (mặc định: tài khoản có quyền SSL VPN/IPsec, còn trên firewall)."""
    rows = accounts.list_accounts(db, firewall_id=firewall_id, q=q, scope=scope, state=state)
    return {"accounts": rows, "total": len(rows), "syncs": accounts.sync_status(db)}


@router.post("/api/vpn/sync")
def vpn_sync(request: Request, payload: SyncIn = Body(default=SyncIn()), db: Session = Depends(get_session),
             p: dict = Depends(operator)):
    """Đồng bộ ngay (chạy nền, song song theo firewall; quá JOB_SYNC_WAIT giây → 202 + mã công việc)."""
    fws = selected_firewalls(db, payload.firewall_ids)
    user, ip = p["user"], client_ip_of(request)

    def work(s: Session, fw: Firewall) -> dict:
        return accounts.sync_firewall(s, fw, actor=user, client_ip=ip)

    job_id = jobs.submit("vpn-sync", user, [fw.id for fw in fws], work,
                         meta={"firewalls": [{"id": fw.id, "name": fw.name} for fw in fws]})
    return job_response(db, job_id)
