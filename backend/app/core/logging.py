"""Log có cấu trúc (docs/architecture.md §3.6).

LOG_FORMAT=json → mỗi dòng một JSON: ts, level, logger, msg, request_id + trường `extra` (actor, path, status, ms,
fw_id, job_id…), kèm một dòng truy cập cho mỗi request /api/*. Mặc định `text`: giữ nguyên log như trước.
KHÔNG BAO GIỜ log body request, mật khẩu, token hay XML gửi firewall (chứa <Login>).
"""
from __future__ import annotations

import contextvars
import json
import logging
import time
import uuid

from .config import settings

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

_STD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "color_message"}
_access = logging.getLogger("access")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if request_id.get():
            out["request_id"] = request_id.get()
        for k, v in vars(record).items():
            if k not in _STD and not k.startswith("_"):
                out[k] = v if isinstance(v, (str, int, float, bool)) or v is None else str(v)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


def setup() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    if settings.LOG_FORMAT != "json":
        if settings.LOG_LEVEL:
            logging.getLogger().setLevel(level)
        return
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    logging.getLogger("uvicorn.access").disabled = True  # thay bằng dòng "access" có request_id


def install(app) -> None:
    @app.middleware("http")
    async def _request_context(req, call_next):
        rid = (req.headers.get("x-request-id") or "")[:64] or uuid.uuid4().hex[:16]
        tok_r = request_id.set(rid)
        t0 = time.monotonic()
        status = 500
        try:
            resp = await call_next(req)
            status = resp.status_code
            resp.headers["X-Request-ID"] = rid
            return resp
        finally:
            if settings.LOG_FORMAT == "json" and req.url.path.startswith("/api/"):
                _access.info("%s %s %s", req.method, req.url.path, status,
                             extra={"method": req.method, "path": req.url.path, "status": status,
                                    "ms": int((time.monotonic() - t0) * 1000),
                                    "actor": getattr(req.state, "actor", "")})
            request_id.reset(tok_r)
