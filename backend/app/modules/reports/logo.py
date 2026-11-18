"""Logo cho header báo cáo: logo quản trị viên tải lên (tab Người dùng › Logo hiển thị) → PNG.

- PNG / JPG / WebP: chuẩn hóa sang PNG (giữ nền trong suốt), giới hạn cạnh dài 800px.
- SVG (reportlab / openpyxl không vẽ được SVG) hoặc chưa có logo: biểu tượng khiên mặc định của app,
  vẽ bằng Pillow theo màu brand HSC (#2681FF / #00468C).
Trả (png_bytes, width_px, height_px, is_default).
"""
from __future__ import annotations

import io

from PIL import Image, ImageDraw
from sqlalchemy.orm import Session

from ...core.errors import AppError
from ..branding import service as branding


def _default() -> tuple[bytes, int, int, bool]:
    s = 4  # vẽ lớn rồi thu nhỏ cho mượt cạnh
    w = h = 64 * s
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    shield = [(32, 4), (54, 12), (54, 30), (50, 44), (42, 54), (32, 60), (22, 54), (14, 44), (10, 30), (10, 12)]
    d.polygon([(x * s, y * s) for x, y in shield], fill=(0, 70, 140, 255))            # brand-deep #00468C
    d.line([(x * s, y * s) for x, y in shield + [shield[0]]], fill=(38, 129, 255, 255), width=3 * s, joint="curve")
    pulse = [(18, 33), (26, 33), (30, 23), (35, 42), (39, 31), (46, 31)]
    d.line([(x * s, y * s) for x, y in pulse], fill=(255, 255, 255, 255), width=4 * s, joint="curve")
    img = img.resize((128, 128), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue(), 128, 128, True


def logo_png(db: Session) -> tuple[bytes, int, int, bool]:
    try:
        raw, mime = branding.logo_bytes(db)
    except AppError:
        return _default()
    if mime == "image/svg+xml":
        return _default()
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
        img = img.convert("RGBA")
        img.thumbnail((800, 800))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue(), img.width, img.height, False
    except Exception:  # noqa: BLE001 — logo hỏng không được làm hỏng báo cáo
        return _default()
