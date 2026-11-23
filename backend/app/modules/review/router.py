"""/api/review/* — rà soát quyền truy cập VPN (ISO 27001 A.5.18).

- /api/review/my*, /api/review/items/{id}/decision: mọi người đăng nhập (kể cả vai trò reviewer) — chỉ thấy /
  quyết định mục thuộc team mình đại diện (quản trị viên: thêm phạm vi Infra và quyết định thay).
- /api/review/campaigns*, /verify, CSV: viewer trở lên (bằng chứng cho auditor); mở / đóng đợt, cấu hình: admin.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...auth.rbac import admin, principal, require
from ...core import hashchain
from ...core.audit import audit
from ...core.db import get_session
from ...core.deps import client_ip_of
from ...core.errors import AppError
from ...core.models import ReviewCampaign, ReviewDecision
from ..notify import smtp
from . import service

router = APIRouter()
viewer = require("viewer")  # reviewer không vào được (đã chặn ở principal, đây là lớp thứ hai)


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class DecisionIn(_In):
    decision: Literal["keep", "revoke", "change"]
    comment: str = ""


class OpenIn(_In):
    name: str | None = None


class DraftIn(_In):
    to: Any = None  # list hoặc chuỗi phân cách , ; xuống dòng
    cc: Any = None
    subject: str = Field(min_length=1, max_length=250)
    body: str = Field(min_length=1, max_length=100_000)


class SettingsIn(_In):
    auto_quarterly: bool | None = None
    due_days: int | None = None
    remind_days: int | None = None


def _camp(db: Session, cid: int) -> ReviewCampaign:
    c = db.get(ReviewCampaign, cid)
    if c is None:
        raise AppError(404, "Không tìm thấy đợt rà soát")
    return c


# ------------------------------------------------------------------ người rà soát
@router.get("/api/review/my")
def my_review(decision: str = Query(default="", max_length=16), db: Session = Depends(get_session),
              p: dict = Depends(principal)):
    """Đợt đang mở + mục thuộc team mình (admin: + Infra). Trả cả danh sách team mình đại diện."""
    teams = service.contact_teams(db, p["user"])
    scopes = set(teams) | ({"infra"} if p["role"] == "admin" else set())
    camp = db.scalar(select(ReviewCampaign).where(ReviewCampaign.status == "open").order_by(ReviewCampaign.id.desc()))
    names = {s["scope"]: s["name"] for s in service.summary(db, camp.id)["by_scope"]} if camp else {}
    return {
        "campaign": ({k: v for k, v in service.campaign_dict(camp, db).items() if k != "by_scope"} if camp else None),
        "scopes": [{"scope": s, "name": names.get(s, "Infra" if s == "infra" else s)} for s in sorted(scopes)],
        "items": service.items(db, camp.id, scopes=scopes, decision=decision) if camp else [],
        "is_admin": p["role"] == "admin",
    }


@router.post("/api/review/items/{item_id}/decision")
def review_decide(item_id: int, request: Request, payload: DecisionIn = Body(...), db: Session = Depends(get_session),
                  p: dict = Depends(principal)):
    return service.decide(db, item_id, payload.decision, payload.comment, p=p, client_ip=client_ip_of(request))


# ------------------------------------------------------------------ quản lý đợt
@router.get("/api/review/campaigns")
def review_campaigns(db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return {"campaigns": service.campaigns(db), "settings": service.get_settings(db)}


@router.post("/api/review/campaigns")
def review_open(request: Request, payload: OpenIn = Body(default=OpenIn()), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    camp = service.open_campaign(db, actor=p["user"], client_ip=client_ip_of(request),
                                 name=(payload.name or "").strip()[:160] or None)
    return service.campaign_dict(camp, db)


@router.post("/api/review/campaigns/{cid}/close")
def review_close(cid: int, request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    return service.close_campaign(db, cid, actor=p["user"], client_ip=client_ip_of(request))


@router.get("/api/review/campaigns/{cid}/items")
def review_items(cid: int, scope: str = Query(default="", max_length=160), decision: str = Query(default=""),
                 q: str = Query(default="", max_length=120), db: Session = Depends(get_session),
                 p: dict = Depends(viewer)):
    _camp(db, cid)
    return {"items": service.items(db, cid, scopes={scope} if scope else None, decision=decision, q=q)}


@router.get("/api/review/verify")
def review_verify(db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return hashchain.verify(db, ReviewDecision)


@router.get("/api/review/settings")
def review_settings(db: Session = Depends(get_session), p: dict = Depends(viewer)):
    return service.get_settings(db)


@router.put("/api/review/settings")
def review_settings_put(request: Request, payload: SettingsIn = Body(...), db: Session = Depends(get_session),
                        p: dict = Depends(admin)):
    return service.update_settings(db, payload.model_dump(), actor=p["user"], client_ip=client_ip_of(request))


# ------------------------------------------------------------------ bằng chứng
def _csv_response(name: str, header: list[str], rows: list[list]) -> StreamingResponse:
    buf = io.StringIO()
    buf.write("﻿")
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename={name}"})


def _csv_auth(token: str, db: Session) -> None:
    p = principal(token, db)  # reviewer bị chặn (không có request → 403)
    if p["role"] not in ("viewer", "operator", "admin"):
        raise AppError(403, "Không đủ quyền")


@router.get("/api/review/campaigns/{cid}/evidence.csv")
def review_evidence(cid: int, token: str = Query(default=""), db: Session = Depends(get_session)):
    """Bằng chứng rà soát cho auditor: mọi mục, quyết định, người, thời điểm, lý do + mã băm nhật ký."""
    _csv_auth(token, db)
    c = _camp(db, cid)
    chain = {d.item_id: d.row_hash for d in db.scalars(select(ReviewDecision).where(ReviewDecision.campaign_id == cid)
                                                       .order_by(ReviewDecision.id))}
    rows = []
    for it in service.items(db, cid):
        s = it["snapshot"]
        rows.append([c.name, c.period_key, it["firewall"], "rule" if it["kind"] == "rule" else "tài khoản mồ côi",
                     it["title"], it["team"], "Infra" if it["scope"] == "infra" else it["scope"],
                     s.get("expiry_date") or "", s.get("status_label") or "",
                     " ".join(s.get("accounts") or s.get("identities") or [s.get("username", "")]),
                     " ".join((s.get("dst_zones") or []) + (s.get("dst_networks") or [])),
                     it["decision_label"], it["comment"], it["decided_by"], it["decided_at"] or "",
                     "có" if it["on_behalf"] else "", chain.get(it["id"], "")])
    return _csv_response(f"ra_soat_vpn_{c.period_key}_bang_chung.csv",
                         ["dot", "ky", "firewall", "loai", "quyen", "team", "pham_vi", "han", "trang_thai_han",
                          "nguoi_dung", "dich", "quyet_dinh", "ly_do", "nguoi_quyet_dinh", "thoi_diem",
                          "infra_quyet_dinh_thay", "ma_bam_nhat_ky"], rows)


@router.get("/api/review/campaigns/{cid}/revocations.csv")
def review_revocations(cid: int, token: str = Query(default=""), db: Session = Depends(get_session)):
    """Danh sách Infra cần xử lý trên firewall: Thu hồi / Cần điều chỉnh / Không phản hồi (leo thang)."""
    _csv_auth(token, db)
    c = _camp(db, cid)
    rows = [[it["firewall"], it["title"], it["team"], it["decision_label"], it["comment"], it["decided_by"],
             it["decided_at"] or ""]
            for it in service.items(db, cid) if it["decision"] in ("revoke", "change", "no_response")]
    return _csv_response(f"ra_soat_vpn_{c.period_key}_can_xu_ly.csv",
                         ["firewall", "quyen", "team", "quyet_dinh", "ly_do", "nguoi_quyet_dinh", "thoi_diem"], rows)


# ------------------------------------------------------------------ email rà soát (bản nháp) — quản trị viên
@router.get("/api/review/campaigns/{cid}/drafts")
def review_drafts(cid: int, db: Session = Depends(get_session), p: dict = Depends(admin)):
    _camp(db, cid)
    return {"drafts": service.drafts(db, cid)}


@router.get("/api/review/campaigns/{cid}/drafts/{scope}")
def review_draft(cid: int, scope: str, db: Session = Depends(get_session), p: dict = Depends(admin)):
    _camp(db, cid)
    return service.draft(db, cid, scope.lower())


def _draft_in(payload: DraftIn) -> tuple[list[str], list[str]]:
    to, cc = smtp.parse_emails(payload.to or []), smtp.parse_emails(payload.cc or [])
    if not to:
        raise AppError(400, "Nhập ít nhất một người nhận hợp lệ")
    return to, cc


@router.post("/api/review/campaigns/{cid}/drafts/{scope}/eml")
def review_draft_eml(cid: int, scope: str, payload: DraftIn = Body(...), db: Session = Depends(get_session),
                     p: dict = Depends(admin)):
    camp = _camp(db, cid)
    to, cc = _draft_in(payload)
    data = service.draft_eml(to, cc, payload.subject, payload.body)
    name = f"ra-soat-vpn-{camp.period_key}-{scope}".replace(" ", "-")
    name = "".join(ch for ch in name if ch.isalnum() or ch in "-_.")[:120] or "ra-soat-vpn"
    return Response(data, media_type="message/rfc822",
                    headers={"Content-Disposition": f'attachment; filename="{name}.eml"'})


@router.post("/api/review/campaigns/{cid}/drafts/{scope}/send")
def review_draft_send(cid: int, scope: str, request: Request, payload: DraftIn = Body(...),
                      db: Session = Depends(get_session), p: dict = Depends(admin)):
    camp = _camp(db, cid)
    to, cc = _draft_in(payload)
    ip = client_ip_of(request)
    try:
        smtp.send(db, to, " ".join(payload.subject.split()), payload.body, cc=cc)  # tiêu đề sửa tay: gộp xuống dòng
    except smtp.MailError as exc:
        audit(db, action="review", fw=None, target=camp.period_key, result="error", actor=p["user"], client_ip=ip,
              message=f"Gửi email rà soát {scope} không thành công: {exc}")
        db.commit()
        raise AppError(400, f"Gửi không thành công: {exc}") from exc
    audit(db, action="review", fw=None, target=camp.period_key, result="ok", actor=p["user"], client_ip=ip,
          message=f"Gửi email rà soát cho {scope}: {', '.join(to)}" + (f" · Cc {', '.join(cc)}" if cc else ""))
    db.commit()
    return {"ok": True, "message": f"Đã gửi tới {', '.join(to)}"}
