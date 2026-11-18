"""SOC Rapid Block — API backend (FastAPI) cho mini app chặn IP trên Sophos Firewall."""
from __future__ import annotations

import base64
import binascii
import csv
import datetime as dt
import io
import os
import re

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import group_cache as gc
from . import jobs
from .core.config import settings
from .core.db import get_session, init_db
from .auth.rbac import admin, current_user, principal
from .auth.router import resolve_sso  # noqa: F401 — tests/sso_once_test.py dùng main.resolve_sso
from .auth.router import router as auth_router
from .auth.users.router import router as users_router
from .modules.firewalls.router import router as firewalls_router
from .modules.ipblock.changes_router import router as changes_router
from .modules.ipblock.router import router as ipblock_router
from .core.deps import client_ip_of
from .core.models import AppSetting, AuditLog, Firewall
from .policy import BLOCK_GROUP
from .service import audit

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


from .core import errors as app_errors  # noqa: E402

app_errors.install(app)
app.include_router(auth_router)
app.include_router(firewalls_router)
app.include_router(users_router)
app.include_router(ipblock_router)
app.include_router(changes_router)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    # Hardening: chuẩn hóa mọi firewall về group cố định (dữ liệu cũ có thể còn SOC_BLOCKED_IPS)
    from .core.db import SessionLocal

    with SessionLocal() as db:
        db.query(Firewall).filter(Firewall.default_group != BLOCK_GROUP).update(
            {Firewall.default_group: BLOCK_GROUP}, synchronize_session=False
        )
        db.commit()
        try:
            jobs.purge_old(db)
        except Exception:  # noqa: BLE001
            pass
    # Bộ lập lịch cache: lần đầu quét firewall chưa có cache/quá hạn, sau đó quét đầy đủ hằng ngày (TTL / GROUP_CACHE_DAILY_AT)
    if settings.GROUP_CACHE_WARMUP:
        import threading

        threading.Thread(target=gc.scheduler_loop, name="group-cache-scheduler", daemon=True).start()


# ------------------------------------------------------------------- helpers


# --------------------------------------------------------------------- audit
@app.get("/api/audit")
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


@app.get("/api/audit.csv")
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


# ------------------------------------------------------------- change log


# ------------------------------------------------------------------ branding
_LOGO_MIME = {"image/png", "image/jpeg", "image/webp", "image/svg+xml"}
_SVG_BAD = re.compile(r"<\s*script|<\s*foreignObject|\bon[a-z]+\s*=|javascript:|<\s*iframe|<\s*embed|<\s*object"
                      r"|xlink:href\s*=\s*[\"'](?!#)|href\s*=\s*[\"'](?!#)", re.I)


def _logo_row(db: Session) -> AppSetting | None:
    return db.get(AppSetting, "logo")


@app.get("/api/branding")
def branding(db: Session = Depends(get_session)):
    """Công khai (màn hình đăng nhập cần): có logo hay không + mốc cập nhật để chống cache trình duyệt."""
    row = _logo_row(db)
    has = bool(row and row.value)
    v = int(row.updated_at.timestamp()) if has and row.updated_at else 0
    return {"app_name": "SOC Rapid Block", "has_logo": has, "logo_url": f"/api/branding/logo?v={v}" if has else "",
            "logo_max_kb": settings.LOGO_MAX_KB}


@app.get("/api/branding/logo", include_in_schema=False)
def branding_logo(db: Session = Depends(get_session)):
    row = _logo_row(db)
    if not row or not row.value:
        raise HTTPException(404, "Chưa có logo")
    meta, _, b64 = row.value.partition(",")
    mime = meta.removeprefix("data:").removesuffix(";base64")
    return Response(
        content=base64.b64decode(b64), media_type=mime,
        headers={
            "Cache-Control": "public, max-age=86400",
            "X-Content-Type-Options": "nosniff",
            # SVG mở trực tiếp cũng không chạy được script
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
        },
    )


@app.put("/api/branding/logo")
def set_logo(request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
             p: dict = Depends(admin)):
    url = str(payload.get("data_url") or "")
    m = re.fullmatch(r"data:([a-z+/]+);base64,([A-Za-z0-9+/=\s]+)", url, re.S)
    if not m or m.group(1) not in _LOGO_MIME:
        raise HTTPException(400, "Logo phải là PNG, JPEG, WebP hoặc SVG")
    try:
        raw = base64.b64decode(m.group(2), validate=False)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(400, "Dữ liệu logo không hợp lệ") from exc
    if len(raw) > settings.LOGO_MAX_KB * 1024:
        raise HTTPException(400, f"Logo tối đa {settings.LOGO_MAX_KB} KB")
    mime = m.group(1)
    sig = {"image/png": raw[:8] == b"\x89PNG\r\n\x1a\n", "image/jpeg": raw[:3] == b"\xff\xd8\xff",
           "image/webp": raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"}
    if mime == "image/svg+xml":
        txt = raw.decode("utf-8", "replace")
        if "<svg" not in txt.lower() or _SVG_BAD.search(txt):
            raise HTTPException(400, "SVG chứa script, sự kiện hoặc liên kết ngoài — không cho phép")
    elif not sig.get(mime):
        raise HTTPException(400, "Nội dung file không khớp định dạng ảnh")
    row = _logo_row(db) or AppSetting(key="logo")
    row.value = f"data:{mime};base64," + base64.b64encode(raw).decode()
    row.updated_by = p["user"]
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    audit(db, action="branding", fw=None, target="logo", result="ok",
          message=f"Cập nhật logo {mime} {len(raw)} byte", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    return branding(db)


@app.delete("/api/branding/logo")
def delete_logo(request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    row = _logo_row(db)
    if row:
        db.delete(row)
        audit(db, action="branding", fw=None, target="logo", result="ok", message="Gỡ logo",
              actor=p["user"], client_ip=client_ip_of(request))
        db.commit()
    return branding(db)


# --------------------------------------------------------------------- users


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


# ------------------------------------------------------------ static frontend
_FRONTEND = os.getenv(
    "FRONTEND_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend"),
)
_NO_CACHE = "no-cache, must-revalidate"


@app.middleware("http")
async def _static_no_cache(request: Request, call_next):
    """Bắt trình duyệt / reverse proxy luôn kiểm tra lại file tĩnh (ETag → 304),
    tránh tình trạng index.html mới chạy với app.js cũ sau khi nâng cấp."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/") and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = _NO_CACHE
    return response


def _render_index() -> HTMLResponse:
    with open(os.path.join(_FRONTEND, "index.html"), encoding="utf-8") as f:
        html = f.read()
    v = settings.APP_VERSION
    html = html.replace('src="app.js"', f'src="app.js?v={v}"').replace(
        'href="styles.css"', f'href="styles.css?v={v}"'
    ).replace('href="hsc-tokens.css"', f'href="hsc-tokens.css?v={v}"').replace(
        'href="fonts.css"', f'href="fonts.css?v={v}"'
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


if os.path.isdir(_FRONTEND):

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    def _index():
        return _render_index()

    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
