"""Nghiệp vụ logo: kiểm tra định dạng/kích thước/nội dung SVG an toàn, lưu ở app_settings['logo']."""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import re

from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import AppSetting

LOGO_MIME = {"image/png", "image/jpeg", "image/webp", "image/svg+xml"}
SVG_BAD = re.compile(r"<\s*script|<\s*foreignObject|\bon[a-z]+\s*=|javascript:|<\s*iframe|<\s*embed|<\s*object"
                     r"|xlink:href\s*=\s*[\"'](?!#)|href\s*=\s*[\"'](?!#)", re.I)


def logo_row(db: Session) -> AppSetting | None:
    return db.get(AppSetting, "logo")


def info(db: Session) -> dict:
    """Công khai (màn hình đăng nhập cần): có logo hay không + mốc cập nhật để chống cache trình duyệt."""
    row = logo_row(db)
    has = bool(row and row.value)
    v = int(row.updated_at.timestamp()) if has and row.updated_at else 0
    return {"app_name": "SOC Rapid Block", "has_logo": has, "logo_url": f"/api/branding/logo?v={v}" if has else "",
            "logo_max_kb": settings.LOGO_MAX_KB}


def logo_bytes(db: Session) -> tuple[bytes, str]:
    row = logo_row(db)
    if not row or not row.value:
        raise AppError(404, "Chưa có logo")
    meta, _, b64 = row.value.partition(",")
    return base64.b64decode(b64), meta.removeprefix("data:").removesuffix(";base64")


def set_logo(db: Session, data_url: str, *, actor: str, client_ip: str) -> dict:
    m = re.fullmatch(r"data:([a-z+/]+);base64,([A-Za-z0-9+/=\s]+)", data_url, re.S)
    if not m or m.group(1) not in LOGO_MIME:
        raise AppError(400, "Logo phải là PNG, JPEG, WebP hoặc SVG")
    try:
        raw = base64.b64decode(m.group(2), validate=False)
    except (ValueError, binascii.Error) as exc:
        raise AppError(400, "Dữ liệu logo không hợp lệ") from exc
    if len(raw) > settings.LOGO_MAX_KB * 1024:
        raise AppError(400, f"Logo tối đa {settings.LOGO_MAX_KB} KB")
    mime = m.group(1)
    sig = {"image/png": raw[:8] == b"\x89PNG\r\n\x1a\n", "image/jpeg": raw[:3] == b"\xff\xd8\xff",
           "image/webp": raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"}
    if mime == "image/svg+xml":
        txt = raw.decode("utf-8", "replace")
        if "<svg" not in txt.lower() or SVG_BAD.search(txt):
            raise AppError(400, "SVG chứa script, sự kiện hoặc liên kết ngoài — không cho phép")
    elif not sig.get(mime):
        raise AppError(400, "Nội dung file không khớp định dạng ảnh")
    row = logo_row(db) or AppSetting(key="logo")
    row.value = f"data:{mime};base64," + base64.b64encode(raw).decode()
    row.updated_by = actor
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    audit(db, action="branding", fw=None, target="logo", result="ok",
          message=f"Cập nhật logo {mime} {len(raw)} byte", actor=actor, client_ip=client_ip)
    db.commit()
    return info(db)


def delete_logo(db: Session, *, actor: str, client_ip: str) -> dict:
    row = logo_row(db)
    if row:
        db.delete(row)
        audit(db, action="branding", fw=None, target="logo", result="ok", message="Gỡ logo",
              actor=actor, client_ip=client_ip)
        db.commit()
    return info(db)
