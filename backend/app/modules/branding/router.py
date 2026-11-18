"""/api/branding*."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ...auth.rbac import admin
from ...core.db import get_session
from ...core.deps import client_ip_of
from . import service

router = APIRouter()


class LogoIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    data_url: Any = None


@router.get("/api/branding")
def branding(db: Session = Depends(get_session)):
    return service.info(db)


@router.get("/api/branding/logo", include_in_schema=False)
def branding_logo(db: Session = Depends(get_session)):
    content, mime = service.logo_bytes(db)
    return Response(
        content=content, media_type=mime,
        headers={
            "Cache-Control": "public, max-age=86400",
            "X-Content-Type-Options": "nosniff",
            # SVG mở trực tiếp cũng không chạy được script
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
        },
    )


@router.put("/api/branding/logo")
def set_logo(request: Request, payload: LogoIn = Body(...), db: Session = Depends(get_session),
             p: dict = Depends(admin)):
    return service.set_logo(db, str(payload.data_url or ""), actor=p["user"], client_ip=client_ip_of(request))


@router.delete("/api/branding/logo")
def delete_logo(request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    return service.delete_logo(db, actor=p["user"], client_ip=client_ip_of(request))
