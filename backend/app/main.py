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
from .core import logging as app_logging
from .core.config import settings
from .core.db import SessionLocal, init_db
from .core.models import Firewall
from .integrations.sophos.policy import BLOCK_GROUP
from .modules.audit.router import router as audit_router
from .modules.autoblock import service as autoblock_service
from .modules.autoblock.router import router as autoblock_router
from .modules.branding.router import router as branding_router
from .modules.firewalls.router import router as firewalls_router
from .modules.ipblock import group_cache as gc
from .modules.ipblock.changes_router import router as changes_router
from .modules.ipblock.router import router as ipblock_router
from .modules.notify import outbox as notify_outbox
from .modules.notify.router import router as notify_router
from .modules.reports.router import router as reports_router
from .modules.review import service as review_service
from .modules.review.router import router as review_router
from .modules.vpn import sync as vpn_sync
from .modules.vpn.router import router as vpn_router


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
    # Đồng bộ VPN định kỳ (tài khoản + rule thời hạn, chỉ đọc); mỗi vòng chỉ một pod chạy
    if settings.VPN_SYNC_MINUTES > 0:
        jobs.every("vpn-sync", settings.VPN_SYNC_MINUTES * 60, vpn_sync.sync_all)
    # Thông báo email: lập kế hoạch nhắc hạn VPN (idempotent) + gửi hàng đợi; mỗi vòng chỉ một pod chạy
    if settings.NOTIFY_INTERVAL_SECONDS > 0:
        jobs.every("notify", settings.NOTIFY_INTERVAL_SECONDS, notify_outbox.run_cycle)
    # Rà soát quyền VPN: tự mở đợt đầu quý, nhắc / báo quá hạn (một pod/vòng); kiểm tra mỗi giờ
    jobs.every("review", 3600, review_service.tick)
    # Tự động chặn từ Teams: kiểm tra mỗi 30 giây, chỉ đọc Graph khi đủ chu kỳ quản trị viên chọn (mặc định 5 phút)
    if settings.AUTOBLOCK_POLL_SECONDS > 0:
        jobs.every("autoblock", 30, autoblock_service.tick)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _startup()
    yield


app_logging.setup()  # mức module: uvicorn nạp app trước khi ghi log khởi động → mọi dòng đã đúng định dạng

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, docs_url="/api/docs", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app_errors.install(app)
app_logging.install(app)

for _router in (auth_router, firewalls_router, users_router, ipblock_router, changes_router, audit_router,
                branding_router, vpn_router, notify_router, review_router, autoblock_router,
                reports_router):
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
    tránh tình trạng index.html mới chạy với module JS cũ sau khi nâng cấp."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/") and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = _NO_CACHE
    return response


def _render_index() -> HTMLResponse:
    with open(os.path.join(_FRONTEND, "index.html"), encoding="utf-8") as f:
        html = f.read()
    v = settings.APP_VERSION
    html = html.replace('src="js/main.js"', f'src="js/main.js?v={v}"').replace(
        'href="styles.css"', f'href="styles.css?v={v}"'
    ).replace('href="theme.css"', f'href="theme.css?v={v}"').replace(
        'href="fonts.css"', f'href="fonts.css?v={v}"'
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


if os.path.isdir(_FRONTEND):

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    def _index():
        return _render_index()

    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
