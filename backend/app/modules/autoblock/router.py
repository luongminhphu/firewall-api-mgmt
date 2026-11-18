"""/api/autoblock/* — tự động chặn IP từ group chat Teams.

Quyền: xem trạng thái / danh sách = viewer · duyệt, từ chối, gỡ chặn, TẮT công tắc khẩn cấp = operator (Write) ·
cấu hình, BẬT lại công tắc, mở lại sau ngắt ngưỡng, đọc ngay, kiểm tra kết nối = admin.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import admin, operator, require, role_at_least
from ...core import hashchain
from ...core.db import get_session
from ...core.deps import client_ip_of, job_response
from ...core.errors import AppError
from ...core.models import AutoBlockEvent
from . import service
from . import settings as cfgmod

router = APIRouter()
viewer = require("viewer")


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SenderIn(_In):
    id: str
    name: str | None = None


class WhitelistIn(_In):
    name: str
    entries: Any = None  # list hoặc chuỗi nhiều dòng


class SettingsIn(_In):
    enabled: bool | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None  # bỏ trống = giữ secret cũ
    clear_secret: bool | None = None
    chat_id: str | None = None
    soc_senders: list[SenderIn] | None = None
    window_enabled: bool | None = None
    window_start: str | None = None
    window_end: str | None = None
    hourly_limit: int | None = None
    poll_seconds: int | None = None
    admin_emails: Any = None
    firewall_ids: list[int] | None = None
    whitelists: list[WhitelistIn] | None = None
    reply_enabled: bool | None = None
    reply_webhook_url: str | None = None  # bỏ trống = giữ URL cũ
    clear_reply_url: bool | None = None


class IdsIn(_In):
    ids: list[int] = []
    night: bool = False  # gỡ tất cả IP tự chặn trong ca đêm gần nhất
    note: str | None = None


class SwitchIn(_In):
    on: bool


@router.get("/api/autoblock/status")
def ab_status(db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return service.status(db)


@router.get("/api/autoblock/requests")
def ab_requests(view: Literal["all", "night", "pending"] = Query(default="all"),
                status: str = Query(default="", max_length=16),
                db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return service.list_requests(db, view=view, status_=status)


@router.post("/api/autoblock/approve")
def ab_approve(request: Request, payload: IdsIn = Body(...), db: Session = Depends(get_session),
               p: dict = Depends(operator)):
    job_id = service.approve(db, payload.ids, p=p, client_ip=client_ip_of(request))
    if not job_id:
        raise AppError(400, "Không có firewall nào đang bật")
    return job_response(db, job_id)


@router.post("/api/autoblock/reject")
def ab_reject(request: Request, payload: IdsIn = Body(...), db: Session = Depends(get_session),
              p: dict = Depends(operator)):
    n = service.reject(db, payload.ids, p=p, client_ip=client_ip_of(request), note=payload.note or "")
    return {"rejected": n}


@router.post("/api/autoblock/unblock")
def ab_unblock(request: Request, payload: IdsIn = Body(...), db: Session = Depends(get_session),
               p: dict = Depends(operator)):
    ids = list(payload.ids)
    if payload.night:
        ids += [r["id"] for r in service.list_requests(db, view="night")["items"] if r["status"] == "blocked"]
    if not ids:
        raise AppError(400, "Chưa chọn IP nào để gỡ chặn")
    return job_response(db, service.unblock(db, ids, p=p, client_ip=client_ip_of(request)))


@router.post("/api/autoblock/switch")
def ab_switch(request: Request, payload: SwitchIn = Body(...), db: Session = Depends(get_session),
              p: dict = Depends(operator)):
    """Công tắc khẩn cấp: Write được TẮT (an toàn); chỉ quản trị viên BẬT lại."""
    if payload.on and not role_at_least(p["role"], "admin"):
        raise AppError(403, "Chỉ quản trị viên được bật lại tự động chặn")
    return service.set_switch(db, payload.on, actor=p["user"], client_ip=client_ip_of(request))


@router.post("/api/autoblock/breaker/reset")
def ab_breaker_reset(request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    return service.reset_breaker(db, actor=p["user"], client_ip=client_ip_of(request))


@router.get("/api/autoblock/settings")
def ab_settings_get(db: Session = Depends(get_session), p: dict = Depends(admin)):
    return {**cfgmod.get(db), "seen_senders": service.seen_senders(db)}


@router.put("/api/autoblock/settings")
def ab_settings_put(request: Request, payload: SettingsIn = Body(...), db: Session = Depends(get_session),
                    p: dict = Depends(admin)):
    data = payload.model_dump(exclude_none=True)
    if payload.soc_senders is not None:
        data["soc_senders"] = [s.model_dump() for s in payload.soc_senders]
    if payload.whitelists is not None:
        data["whitelists"] = [w.model_dump() for w in payload.whitelists]
    out = cfgmod.update(db, data, actor=p["user"], client_ip=client_ip_of(request))
    return {**out, "seen_senders": service.seen_senders(db)}


@router.post("/api/autoblock/test")
def ab_test(db: Session = Depends(get_session), p: dict = Depends(admin)):
    return service.test_connection(db)


@router.post("/api/autoblock/poll")
def ab_poll(db: Session = Depends(get_session), p: dict = Depends(admin)):
    """Đọc Teams ngay (không chờ chu kỳ)."""
    return service.poll()


@router.post("/api/autoblock/reply-test")
def ab_reply_test(request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    """Gửi thử một dòng vào group chat qua Teams Workflows (IP mẫu 192.0.2.1 — dải tài liệu RFC 5737)."""
    import datetime as dt

    import httpx

    from ...core.security import decrypt
    from . import reply

    cfg = cfgmod.raw(db)
    if not cfg["reply_url_enc"]:
        raise AppError(400, "Chưa nhập URL webhook của Teams Workflows")
    now = dt.datetime.now(dt.timezone.utc)
    text = "[THỬ] " + reply.text_for("192.0.2.1", now)
    try:
        r = httpx.post(decrypt(cfg["reply_url_enc"]), json=reply.payload(text, "192.0.2.1", now), timeout=20)
    except httpx.HTTPError as exc:
        raise AppError(502, f"Không gọi được webhook ({type(exc).__name__})") from exc
    if not 200 <= r.status_code < 300:
        raise AppError(502, f"Teams Workflows trả {r.status_code}")
    return {"ok": True, "text": text}


@router.get("/api/autoblock/verify")
def ab_verify(db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return hashchain.verify(db, AutoBlockEvent)
