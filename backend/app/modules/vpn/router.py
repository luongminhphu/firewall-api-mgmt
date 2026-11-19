"""/api/vpn/* — module VPN (CHỈ ĐỌC trên firewall). viewer: xem; operator: đồng bộ; admin: cấu hình."""
from __future__ import annotations

import csv
import datetime as dt
import io
from typing import Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import admin, current_user, operator, principal
from ...core import hashchain, jobs
from ...core.db import get_session
from ...core.deps import client_ip_of, job_response
from ...core.errors import AppError
from ...core.models import Firewall, VpnRule, VpnRuleChange
from . import accounts, rules
from . import settings as vpn_settings
from . import sync

router = APIRouter()


class SyncIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    firewall_ids: list[int] | None = None
    kind: Literal["all", "accounts", "rules"] = "all"


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    expiring_days: int | None = None
    rule_groups: list[str] | None = None
    firewall_ids: list[int] | None = None


# ----------------------------------------------------------------- tài khoản
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
    """Đồng bộ ngay tài khoản + rule (chạy nền, song song theo firewall; quá JOB_SYNC_WAIT → 202 + mã công việc)."""
    fws = vpn_settings.sync_firewalls(db, payload.firewall_ids)
    if not fws:
        raise AppError(400, "Không có firewall nào để đồng bộ VPN: chọn firewall có VPN ở Cài đặt › VPN "
                            "(và firewall phải đang bật)")
    user, ip, kind = p["user"], client_ip_of(request), payload.kind

    def work(s: Session, fw: Firewall) -> dict:
        return sync.sync_firewall(s, fw, kind=kind, actor=user, client_ip=ip)

    job_id = jobs.submit("vpn-sync", user, [fw.id for fw in fws], work,
                         meta={"firewalls": [{"id": fw.id, "name": fw.name} for fw in fws], "sync_kind": kind})
    return job_response(db, job_id)


# ----------------------------------------------------------------- rule thời hạn
def _rules(db: Session, firewall_id, status, team, q, date_from, date_to, include_removed, as_of=None) -> dict:
    return rules.list_rules(db, firewall_id=firewall_id, status=status, team=team, q=q, date_from=date_from,
                            date_to=date_to, include_removed=include_removed, today=as_of)


@router.get("/api/vpn/rules")
def vpn_rules(
    firewall_id: int | None = Query(default=None),
    status: str = Query(default="", max_length=200),
    team: str = Query(default="", max_length=160),
    q: str = Query(default="", max_length=120),
    date_from: dt.date | None = Query(default=None),
    date_to: dt.date | None = Query(default=None),
    include_removed: bool = Query(default=False),
    as_of: dt.date | None = Query(default=None, description="Xem trạng thái tại ngày này (mặc định hôm nay, giờ VN)"),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    """Rule thuộc Rule Group VPN + hạn + trạng thái (tính theo hôm nay / as_of) + thẻ đếm theo trạng thái."""
    out = _rules(db, firewall_id, status, team, q, date_from, date_to, include_removed, as_of)
    return {**out, "syncs": rules.sync_status(db)}


@router.get("/api/vpn/rules.csv")
def vpn_rules_csv(
    token: str = Query(default=""),
    firewall_id: int | None = Query(default=None),
    status: str = Query(default=""),
    team: str = Query(default=""),
    q: str = Query(default=""),
    date_from: dt.date | None = Query(default=None),
    date_to: dt.date | None = Query(default=None),
    as_of: dt.date | None = Query(default=None),
    db: Session = Depends(get_session),
):
    """Danh sách cần xử lý (CSV) — app KHÔNG tự tắt/sửa/xóa rule; Infra xử lý trên firewall theo danh sách này."""
    principal(token, db)  # cùng kiểm tra như API (giống /api/audit.csv)
    rows = _rules(db, firewall_id, status, team, q, date_from, date_to, False, as_of)["rules"]
    buf = io.StringIO()
    buf.write("﻿")  # Excel đọc đúng tiếng Việt
    w = csv.writer(buf)
    w.writerow(["firewall", "rule_group", "vi_tri", "ten_rule", "team", "ma_user", "trang_thai", "con_lai_ngay",
                "ngay_het_han", "nguon_han", "lech_han", "rule_bat", "tai_khoan", "dich", "dich_vu", "schedule"])
    for x in rows:
        w.writerow([x["firewall"], x["group_name"], x["position"], x["rule_name"], x["team"], x["user_code"],
                    x["status_label"], "" if x["days_left"] is None else x["days_left"], x["expiry_date"] or "",
                    x["expiry_source"], "có" if x["expiry_mismatch"] else "", "bật" if x["enabled"] else "tắt",
                    " ".join(x["identities"]), " ".join(x["dst_zones"] + x["dst_networks"]),
                    " ".join(x["services"]), x["schedule_name"]])
    buf.seek(0)
    name = f"vpn_rules_can_xu_ly_{dt.date.today().isoformat()}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename={name}"})


@router.get("/api/vpn/rules/{rule_id}")
def vpn_rule_detail(rule_id: int, db: Session = Depends(get_session), user: str = Depends(current_user)):
    r = db.get(VpnRule, rule_id)
    if r is None:
        raise AppError(404, "Không tìm thấy rule")
    found = [x for x in _rules(db, r.firewall_id, "", "", "", None, None, True)["rules"] if x["id"] == rule_id]
    return {"rule": found[0], "history": rules.changes(db, firewall_id=r.firewall_id, rule_name=r.rule_name)}


@router.get("/api/vpn/changes")
def vpn_changes(firewall_id: int | None = Query(default=None), limit: int = Query(default=200, le=2000),
                db: Session = Depends(get_session), user: str = Depends(current_user)):
    return {"changes": rules.changes(db, firewall_id=firewall_id, limit=limit)}


@router.get("/api/vpn/changes/verify")
def vpn_changes_verify(db: Session = Depends(get_session), user: str = Depends(current_user)):
    return hashchain.verify(db, VpnRuleChange)


# ----------------------------------------------------------------- cấu hình
@router.get("/api/vpn/settings")
def vpn_settings_get(db: Session = Depends(get_session), user: str = Depends(current_user)):
    return vpn_settings.get(db)


@router.put("/api/vpn/settings")
def vpn_settings_put(request: Request, payload: SettingsIn = Body(...), db: Session = Depends(get_session),
                     p: dict = Depends(admin)):
    return vpn_settings.update(db, payload.model_dump(), actor=p["user"], client_ip=client_ip_of(request))
