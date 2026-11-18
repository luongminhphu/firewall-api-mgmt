"""SOC Rapid Block — tạo app FastAPI: lifespan, middleware, mount router, phục vụ frontend tĩnh.

Nghiệp vụ nằm ở modules/*, xác thực ở auth/*, hạ tầng ở core/*, firewall ở integrations/sophos
(docs/architecture.md §3).
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .auth.router import resolve_sso  # noqa: F401 — tests/sso_once_test.py dùng main.resolve_sso
from .auth.router import router as auth_router
from .auth.users.router import router as users_router
from .core import errors as app_errors
from .core import jobs
from .core.config import settings
from .core.db import SessionLocal, init_db
from .core.models import Firewall
from .integrations.sophos.policy import BLOCK_GROUP
from .modules.audit.router import router as audit_router
from .modules.branding.router import router as branding_router
from .modules.firewalls.router import router as firewalls_router
from .modules.ipblock import group_cache as gc
from .modules.ipblock.changes_router import router as changes_router
from .modules.ipblock.router import router as ipblock_router


def _startup() -> None:
    init_db()
    with SessionLocal() as db:
        # Hardening: chuẩn hóa mọi firewall về group cố định (dữ liệu cũ có thể còn SOC_BLOCKED_IPS)
        db.query(Firewall).filter(Firewall.default_group != BLOCK_GROUP).update(
            {Firewall.default_group: BLOCK_GROUP}, synchronize_session=False
        )
        db.commit()
        try:
            jobs.purge_old(db)
        except Exception:  # noqa: BLE001
            pass
    # Bộ lập lịch cache: quét ngay firewall chưa có cache/quá hạn, sau đó kiểm tra định kỳ (TTL / GROUP_CACHE_DAILY_AT)
    if settings.GROUP_CACHE_WARMUP:
        gc.start_scheduler()


@asynccontextmanager
async def lifespan(_: FastAPI):
    _startup()
    yield


app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, docs_url="/api/docs", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app_errors.install(app)

for _router in (auth_router, firewalls_router, users_router, ipblock_router, changes_router, audit_router,
                branding_router):
    app.include_router(_router)


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
