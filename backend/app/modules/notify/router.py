"""/api/settings/smtp, /api/notify/* — chỉ quản trị viên (cấu hình máy chủ, người nhận, xem hàng đợi email)."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import admin
from ...core.audit import audit
from ...core.db import get_session
from ...core.deps import client_ip_of
from ...core.errors import AppError
from . import outbox, planner, smtp

router = APIRouter()


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SmtpIn(_In):
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    security: Literal["none", "starttls", "ssl"] | None = None
    verify_tls: bool | None = None
    username: str | None = None
    password: str | None = None  # bỏ trống = giữ mật khẩu cũ
    clear_password: bool | None = None
    from_addr: str | None = None
    from_name: str | None = None


class TestIn(_In):
    to: str


class NotifyIn(_In):
    enabled: bool | None = None
    infra_emails: Any = None  # list hoặc chuỗi phân cách , ; xuống dòng
    reminder_days: list[int] | None = None
    expired_weekly: bool | None = None


class ContactIn(_In):
    team: str
    emails: Any = None
    note: str | None = None
    members: Any = None  # user VPN của group: list hoặc chuỗi phân cách , ; xuống dòng


class ContactsIn(_In):
    contacts: list[ContactIn]


@router.get("/api/settings/smtp")
def smtp_get(db: Session = Depends(get_session), p: dict = Depends(admin)):
    return smtp.get(db)


@router.put("/api/settings/smtp")
def smtp_put(request: Request, payload: SmtpIn = Body(...), db: Session = Depends(get_session),
             p: dict = Depends(admin)):
    return smtp.update(db, payload.model_dump(), actor=p["user"], client_ip=client_ip_of(request))


@router.post("/api/settings/smtp/test")
def smtp_test(request: Request, payload: TestIn = Body(...), db: Session = Depends(get_session),
              p: dict = Depends(admin)):
    """Gửi thử ngay (không qua hàng đợi) — kiểm tra máy chủ, tài khoản, người nhận."""
    to = smtp.parse_emails(payload.to)
    if len(to) != 1:
        raise AppError(400, "Nhập đúng một địa chỉ nhận thư thử")
    ip = client_ip_of(request)
    try:
        smtp.send(db, to, "[SOC Rapid Block] Thư thử cấu hình SMTP",
                  f"Thư thử do {p['user']} gửi từ tab Cài đặt của SOC Rapid Block.\n"
                  "Nhận được thư này nghĩa là cấu hình SMTP hoạt động.\n\n(Email tự động — vui lòng không trả lời.)\n")
    except smtp.MailError as exc:
        audit(db, action="smtp_test", fw=None, target=to[0], result="error", message=str(exc), actor=p["user"],
              client_ip=ip)
        db.commit()
        raise AppError(400, f"Gửi thử không thành công: {exc}") from exc
    audit(db, action="smtp_test", fw=None, target=to[0], result="ok", message="Gửi thử thành công",
          actor=p["user"], client_ip=ip)
    db.commit()
    return {"ok": True, "message": f"Đã gửi thư thử tới {to[0]}"}


@router.get("/api/notify/settings")
def notify_get(db: Session = Depends(get_session), p: dict = Depends(admin)):
    return {**planner.get_cfg(db), "contacts": planner.get_contacts(db), "smtp": smtp.get(db)}


@router.put("/api/notify/settings")
def notify_put(request: Request, payload: NotifyIn = Body(...), db: Session = Depends(get_session),
               p: dict = Depends(admin)):
    return planner.update_cfg(db, payload.model_dump(), actor=p["user"], client_ip=client_ip_of(request))


@router.put("/api/notify/contacts")
def contacts_put(request: Request, payload: ContactsIn = Body(...), db: Session = Depends(get_session),
                 p: dict = Depends(admin)):
    return {"contacts": planner.replace_contacts(db, [c.model_dump() for c in payload.contacts], actor=p["user"],
                                                 client_ip=client_ip_of(request))}


@router.get("/api/notify/outbox")
def outbox_list(status: Literal["", "pending", "sent", "failed"] = Query(default=""),
                limit: int = Query(default=100, le=1000), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    return {"emails": outbox.list_outbox(db, status, limit)}


@router.post("/api/notify/run")
def notify_run(request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    """Chạy ngay: lập kế hoạch (idempotent) + gửi thư đến hạn."""
    res = {**outbox.plan_now(db), **outbox.deliver(db)}
    audit(db, action="notify_run", fw=None, target="vpn", result="ok", actor=p["user"],
          client_ip=client_ip_of(request), message=f"Xếp hàng {res.get('queued', 0)} · đã gửi {res['sent']} · "
                                                   f"thử lại {res['retry']} · chờ {res['pending']}")
    db.commit()
    return res
