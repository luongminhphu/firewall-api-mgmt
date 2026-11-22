"""/api/reports/* — báo cáo thống kê chặn IP 7 / 14 / 30 ngày: xem trước, tải PDF / Excel, gửi email.

Quyền: xem + tải = viewer (tải qua ?token= như audit.csv, cùng kiểm tra người dùng bị khóa / xóa);
gửi email = Write (operator) trở lên. Mọi lần tải / gửi ghi audit `report_export` / `report_email`.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import operator, principal, require, role_at_least
from ...core.audit import audit
from ...core.db import get_session
from ...core.deps import client_ip_of
from ...core.errors import AppError
from ..notify import smtp
from . import data
from .logo import logo_png
from .pdf import build_pdf
from .xlsx import build_xlsx

router = APIRouter()
viewer = require("viewer")
MIME = {"pdf": "application/pdf", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def _now_vn() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone(data.VN_TZ).strftime("%d/%m/%Y %H:%M")


def _file(rep: dict, kind: str, who: str, logo=None) -> tuple[str, bytes]:
    last = rep["end"] - dt.timedelta(microseconds=1)
    name = f"bao-cao-chan-ip_{rep['start']:%Y%m%d}-{last:%Y%m%d}.{kind}"
    build = build_pdf if kind == "pdf" else build_xlsx
    return name, build(rep, generated_by=who, generated_at=_now_vn(), logo=logo)


def _build(db: Session, days: int | None, date_from: str | None, date_to: str | None) -> dict:
    try:
        return data.build(db, days, date_from=date_from or None, date_to=date_to or None)
    except data.RangeError as exc:
        raise AppError(400, str(exc)) from exc


def _download(kind: str, days: int | None, date_from: str, date_to: str, token: str, request: Request,
              db: Session) -> Response:
    p = principal(token, db)  # token hợp lệ, người dùng chưa bị khóa / xóa; vai trò Rà soát bị chặn
    if not role_at_least(p["role"], "viewer"):
        raise AppError(403, "Không đủ quyền xem báo cáo")
    rep = _build(db, days, date_from, date_to)
    name, blob = _file(rep, kind, p.get("name") or p["user"], logo_png(db))
    audit(db, action="report_export", fw=None, target=rep["label"], result="ok", actor=p["user"],
          client_ip=client_ip_of(request), message=f"Tải báo cáo {kind.upper()} {rep['label']} ({len(rep['ips'])} IP)")
    db.commit()
    return Response(blob, media_type=MIME[kind], headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


# Kỳ báo cáo: ?days=7|14|30 (mốc nhanh) hoặc ?from=YYYY-MM-DD&to=YYYY-MM-DD (chọn trên lịch, tối đa 366 ngày)
_DAYS = Query(default=None)
_FROM = Query(default="", alias="from", max_length=10)
_TO = Query(default="", alias="to", max_length=10)


@router.get("/api/reports/summary")
def report_summary(days: int | None = _DAYS, date_from: str = _FROM, date_to: str = _TO,
                   db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return data.to_json(_build(db, days, date_from, date_to))


@router.get("/api/reports/blocks.pdf")
def report_pdf(request: Request, days: int | None = _DAYS, date_from: str = _FROM, date_to: str = _TO,
               token: str = Query(default=""), db: Session = Depends(get_session)):
    return _download("pdf", days, date_from, date_to, token, request, db)


@router.get("/api/reports/blocks.xlsx")
def report_xlsx(request: Request, days: int | None = _DAYS, date_from: str = _FROM, date_to: str = _TO,
                token: str = Query(default=""), db: Session = Depends(get_session)):
    return _download("xlsx", days, date_from, date_to, token, request, db)


class EmailIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    days: int | None = None
    date_from: str | None = None        # YYYY-MM-DD — khoảng ngày chọn trên lịch (ưu tiên hơn days)
    date_to: str | None = None
    to: Any = None                      # list hoặc chuỗi phân cách , ; xuống dòng
    formats: list[Literal["pdf", "xlsx"]] = ["pdf", "xlsx"]
    note: str | None = None


def email_body(rep: dict, note: str = "", sender: str = "") -> str:
    ex = data.executive(rep)
    s = rep["summary"]
    lines = [f"BÁO CÁO CHẶN IP — {rep['label'].upper()}",
             f"Kỳ: {data.fmt(rep['start'])} → {data.fmt(rep['end'])} (giờ Việt Nam)", ""]
    if note:
        lines += [note.strip(), ""]
    lines += ["TÓM TẮT ĐIỀU HÀNH", ex["headline"], "", "Chỉ số chính:",
              f"  - IP bị chặn: {s['unique_ips']} (thủ công {s['manual_ips']}, tự động {s['auto_ips']}, tự động {s['auto_share']}%)",
              f"  - Lượt chặn (IP × firewall): {s['actions']} · IP còn đang chặn: {s['still_blocked']}",
              f"  - SOC gửi → chặn xong (trung bình): {data.fmt_dur(rep['autoblock']['latency_avg'])}", "",
              "Nhận định nổi bật:"] + [f"  - {x}" for x in ex["highlights"] or ["Không có dữ liệu trong kỳ."]] + [
              "", "Cần lưu ý / hành động:"] + [f"  - {x}" for x in ex["attention"]] + [
              "", "Chi tiết (theo ngày, tự động chặn, người thực hiện, danh sách IP) trong file đính kèm.",
              f"Gửi từ SOC Rapid Block{(' bởi ' + sender) if sender else ''}."]
    return "\n".join(lines)


@router.post("/api/reports/email")
def report_email(request: Request, payload: EmailIn = Body(...), db: Session = Depends(get_session),
                 p: dict = Depends(operator)):
    """Gửi báo cáo ngay qua SMTP đã cấu hình (tab Cài đặt), đính kèm PDF / Excel."""
    to = smtp.parse_emails(payload.to)
    if not to:
        raise AppError(400, "Nhập ít nhất một địa chỉ email người nhận")
    if len(to) > 20:
        raise AppError(400, "Tối đa 20 người nhận mỗi lần gửi")
    fmts = list(dict.fromkeys(payload.formats or []))
    if not fmts:
        raise AppError(400, "Chọn ít nhất một định dạng đính kèm (PDF / Excel)")
    cfg = smtp.get(db)
    if not cfg["configured"]:
        raise AppError(400, "Chưa cấu hình máy chủ SMTP — quản trị viên cấu hình ở tab Cài đặt")
    if not cfg["enabled"]:
        raise AppError(400, "Gửi email đang TẮT trong cấu hình SMTP (tab Cài đặt)")
    who = p.get("name") or p["user"]
    rep = _build(db, payload.days, payload.date_from, payload.date_to)
    logo = logo_png(db)
    files = [(*_file(rep, k, who, logo), MIME[k]) for k in fmts]
    last = rep["end"] - dt.timedelta(microseconds=1)
    subject = (f"[SOC Rapid Block] Báo cáo chặn IP {rep['days']} ngày "
               f"({rep['start']:%d/%m} – {last:%d/%m/%Y}): {rep['summary']['unique_ips']} IP")
    try:
        smtp.send(db, to, subject, email_body(rep, (payload.note or "")[:1000], who), attachments=files)
    except smtp.MailError as exc:
        audit(db, action="report_email", fw=None, target=", ".join(to)[:255], result="error", actor=p["user"],
              client_ip=client_ip_of(request), message=str(exc))
        db.commit()
        raise AppError(502, f"Không gửi được email: {exc}") from exc
    audit(db, action="report_email", fw=None, target=", ".join(to)[:255], result="ok", actor=p["user"],
          client_ip=client_ip_of(request),
          message=f"Gửi báo cáo {rep['label']} ({', '.join(f.upper() for f in fmts)}) tới {len(to)} người nhận")
    db.commit()
    return {"sent": True, "to": to, "files": [f[0] for f in files], "subject": subject}
