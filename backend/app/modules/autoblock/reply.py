"""Trả lời kết quả vào group chat Teams sau mỗi lệnh chặn thành công.

    INFRA ĐÃ BLOCK 195.178.110.102 THEO YÊU CẦU LÚC 18/11/2026 23:42:10

Microsoft Graph KHÔNG cho app gửi tin vào chat bằng quyền ứng dụng (chỉ có quyền thay mặt người dùng đăng nhập, hoặc
Teamwork.Migrate.All dành cho di chuyển dữ liệu). Vì vậy app gọi webhook của Teams Workflows — mẫu
"Send webhook alerts to a chat" (tên cũ "Post to a chat when a webhook request is received"): workflow đăng tin vào
đúng group chat đã chọn khi tạo.
Payload theo định dạng mẫu đó (message + Adaptive Card một dòng chữ); có thêm trường `text`, `ip`, `blocked_at`
cho workflow tự dựng. URL webhook chứa chữ ký (sig=…) nên lưu mã hóa bằng MASTER_KEY.

Gửi lỗi → reply_status=failed, mỗi chu kỳ đọc Teams thử lại, tối đa MAX_ATTEMPTS lần.
"""
from __future__ import annotations

import datetime as dt
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.models import AutoBlockRequest
from ...core.security import decrypt
from . import settings as cfgmod

log = logging.getLogger("autoblock.reply")
MAX_ATTEMPTS = 5
TEMPLATE = "INFRA ĐÃ BLOCK {ip} THEO YÊU CẦU LÚC {ts}"


def text_for(ip: str, blocked_at: dt.datetime) -> str:
    t = blocked_at if blocked_at.tzinfo else blocked_at.replace(tzinfo=dt.timezone.utc)
    return TEMPLATE.format(ip=ip, ts=t.astimezone(cfgmod.VN_TZ).strftime("%d/%m/%Y %H:%M:%S"))


def payload(text: str, ip: str, blocked_at: dt.datetime) -> dict:
    return {
        "type": "message",
        "text": text, "ip": ip, "blocked_at": blocked_at.isoformat(),
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                        "version": "1.4", "body": [{"type": "TextBlock", "text": text, "wrap": True,
                                                    "weight": "Bolder"}]},
        }],
    }


def send(db: Session, r: AutoBlockRequest) -> None:
    """Gửi (hoặc ghi lỗi) cho một yêu cầu đã chặn. Người gọi commit."""
    cfg = cfgmod.raw(db)
    if not (cfg["reply_enabled"] and cfg["reply_url_enc"]):
        r.reply_status = "skipped"
        return
    blocked_at = r.blocked_at or dt.datetime.now(dt.timezone.utc)
    text = text_for(r.ip, blocked_at)
    r.reply_attempts = (r.reply_attempts or 0) + 1
    try:
        url = decrypt(cfg["reply_url_enc"])
        resp = httpx.post(url, json=payload(text, r.ip, blocked_at), timeout=httpx.Timeout(20.0, connect=10.0))
        ok = 200 <= resp.status_code < 300
        err = "" if ok else f"Workflows trả {resp.status_code}"
    except Exception as exc:  # noqa: BLE001 — lỗi mạng / MASTER_KEY: ghi lại, thử lại chu kỳ sau
        ok, err = False, f"{type(exc).__name__}"
    if ok:
        r.reply_status, r.replied_at = "sent", dt.datetime.now(dt.timezone.utc)
    else:
        r.reply_status = "failed"
        log.warning("Trả lời Teams cho %s lỗi (lần %s): %s", r.ip, r.reply_attempts, err)
        r.note = (f"Chưa báo được vào Teams: {err}")[:500]


def retry_failed(db: Session) -> int:
    rows = list(db.scalars(select(AutoBlockRequest).where(
        AutoBlockRequest.status == "blocked", AutoBlockRequest.reply_status == "failed",
        AutoBlockRequest.reply_attempts < MAX_ATTEMPTS).limit(50)))
    for r in rows:
        send(db, r)
        if r.reply_status == "sent":
            r.note = ""
    db.commit()
    return len(rows)
