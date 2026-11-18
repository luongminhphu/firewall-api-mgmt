"""Lỗi nghiệp vụ có mã HTTP — service ném AppError, không phụ thuộc FastAPI.

Định dạng phản hồi giữ nguyên như HTTPException: {"detail": "<thông điệp>"} (frontend hiển thị nguyên văn).
Lỗi validate của Pydantic cũng trả 400 + chuỗi tiếng Việt thay vì 422 dạng danh sách (docs/architecture.md §3.4).
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _field(loc) -> str:
    parts = [str(x) for x in loc if x not in ("body", "query", "path")]
    return ".".join(parts) or "dữ liệu"


def install(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        errs = exc.errors()
        first = errs[0] if errs else {}
        return JSONResponse(
            {"detail": f"Dữ liệu không hợp lệ: {_field(first.get('loc', ()))} — {first.get('msg', '')}".strip(" —")},
            status_code=400,
        )
