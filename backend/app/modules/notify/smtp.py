"""Cấu hình SMTP (quản trị viên, trên giao diện — tab Cài đặt) + gửi email.

- Lưu ở app_settings['smtp.settings'] (JSON). Mật khẩu mã hóa AES-GCM bằng MASTER_KEY như credential firewall;
  API KHÔNG BAO GIỜ trả mật khẩu (chỉ has_password). Mọi thay đổi ghi audit settings_cud.
- Bảo mật kết nối: none | starttls | ssl; kiểm tra chứng chỉ TLS mặc định BẬT.
- Chống header injection: địa chỉ / tiêu đề không được chứa CR/LF; địa chỉ phải đúng dạng.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import AppSetting
from ...core.security import MasterKeyMissing, decrypt, encrypt

KEY = "smtp.settings"
SECURITY = ("none", "starttls", "ssl")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
DEFAULTS = {"enabled": False, "host": "", "port": 25, "security": "starttls", "verify_tls": True, "username": "",
            "password_enc": "", "from_addr": "", "from_name": "SOC Rapid Block"}


class MailError(Exception):
    pass


def valid_email(v: str) -> bool:
    return bool(v) and len(v) <= 254 and EMAIL_RE.match(v) is not None


def parse_emails(value) -> list[str]:
    """Chuỗi (phân cách , ; xuống dòng) hoặc list → list địa chỉ đã chuẩn hóa; sai dạng → AppError 400."""
    items = value if isinstance(value, list) else re.split(r"[,;\s]+", str(value or ""))
    out = []
    for raw in items:
        e = str(raw).strip().lower()
        if not e:
            continue
        if not valid_email(e):
            raise AppError(400, f"Địa chỉ email không hợp lệ: {e[:80]}")
        if e not in out:
            out.append(e)
    return out


def _raw(db: Session) -> dict:
    row = db.get(AppSetting, KEY)
    cfg = dict(DEFAULTS)
    if row and row.value:
        try:
            cfg.update({k: v for k, v in json.loads(row.value).items() if k in DEFAULTS})
        except ValueError:
            pass
    return cfg


def get(db: Session) -> dict:
    """Cấu hình để hiển thị — không có mật khẩu."""
    cfg = _raw(db)
    row = db.get(AppSetting, KEY)
    out = {k: v for k, v in cfg.items() if k != "password_enc"}
    out["has_password"] = bool(cfg["password_enc"])
    out["configured"] = bool(cfg["host"] and cfg["from_addr"])
    out["updated_by"] = row.updated_by if row else ""
    out["updated_at"] = row.updated_at.isoformat() if row and row.updated_at else None
    return out


def update(db: Session, data: dict, *, actor: str, client_ip: str) -> dict:
    cfg = _raw(db)
    if data.get("host") is not None:
        host = str(data["host"]).strip()
        if host and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            raise AppError(400, "Máy chủ SMTP chỉ gồm chữ, số, dấu chấm, gạch ngang (tên miền hoặc IP)")
        cfg["host"] = host
    if data.get("port") is not None:
        if not isinstance(data["port"], int) or not 1 <= data["port"] <= 65535:
            raise AppError(400, "Cổng SMTP phải từ 1 đến 65535")
        cfg["port"] = data["port"]
    if data.get("security") is not None:
        if data["security"] not in SECURITY:
            raise AppError(400, "Bảo mật kết nối chỉ nhận: none, starttls, ssl")
        cfg["security"] = data["security"]
    for b in ("enabled", "verify_tls"):
        if data.get(b) is not None:
            cfg[b] = bool(data[b])
    if data.get("username") is not None:
        cfg["username"] = str(data["username"]).strip()[:254]
    if data.get("from_addr") is not None:
        fa = str(data["from_addr"]).strip().lower()
        if fa and not valid_email(fa):
            raise AppError(400, "Địa chỉ gửi (From) không hợp lệ")
        cfg["from_addr"] = fa
    if data.get("from_name") is not None:
        fn = str(data["from_name"]).strip()
        if "\r" in fn or "\n" in fn:
            raise AppError(400, "Tên người gửi không được xuống dòng")
        cfg["from_name"] = fn[:120]
    if data.get("clear_password"):
        cfg["password_enc"] = ""
    elif data.get("password"):  # bỏ trống = giữ mật khẩu cũ
        try:
            cfg["password_enc"] = encrypt(str(data["password"]))
        except MasterKeyMissing as exc:
            raise AppError(400, str(exc)) from exc
    if cfg["enabled"] and not (cfg["host"] and cfg["from_addr"]):
        raise AppError(400, "Cần nhập máy chủ SMTP và địa chỉ gửi trước khi bật gửi email")
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value = json.dumps(cfg)
    row.updated_by = actor
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    audit(db, action="settings_cud", fw=None, target="smtp", result="ok", actor=actor, client_ip=client_ip,
          message=f"SMTP {cfg['host']}:{cfg['port']} ({cfg['security']}) · {'bật' if cfg['enabled'] else 'tắt'} gửi")
    db.commit()
    return get(db)


def _clean_header(v: str) -> str:
    if "\r" in v or "\n" in v:
        raise MailError("Tiêu đề / địa chỉ chứa ký tự xuống dòng")
    return v


def send(db: Session, to: list[str], subject: str, body: str) -> None:
    """Gửi ngay một email. Ném MailError (thông điệp tiếng Việt, không chứa mật khẩu) nếu lỗi."""
    cfg = _raw(db)
    if not (cfg["host"] and cfg["from_addr"]):
        raise MailError("Chưa cấu hình máy chủ SMTP / địa chỉ gửi (tab Cài đặt)")
    rcpts = [a for a in to if valid_email(a)]
    if not rcpts:
        raise MailError("Không có người nhận hợp lệ")
    msg = EmailMessage()
    msg["From"] = formataddr((_clean_header(cfg["from_name"]), _clean_header(cfg["from_addr"])))
    msg["To"] = ", ".join(_clean_header(a) for a in rcpts)
    msg["Subject"] = _clean_header(subject)[:250]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg["from_addr"].split("@")[-1])
    msg["Auto-Submitted"] = "auto-generated"  # RFC 3834: thư tự động, không trả lời tự động
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if not cfg["verify_tls"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t = settings.SMTP_TIMEOUT
    try:
        if cfg["security"] == "ssl":
            conn = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=t, context=ctx)
        else:
            conn = smtplib.SMTP(cfg["host"], cfg["port"], timeout=t)
        with conn:
            conn.ehlo()
            if cfg["security"] == "starttls":
                conn.starttls(context=ctx)
                conn.ehlo()
            if cfg["username"]:
                conn.login(cfg["username"], decrypt(cfg["password_enc"]) if cfg["password_enc"] else "")
            refused = conn.send_message(msg, to_addrs=rcpts)
        if refused:
            raise MailError(f"Máy chủ từ chối người nhận: {', '.join(refused)}")
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(f"Sai tài khoản SMTP ({exc.smtp_code})") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailError(f"Máy chủ từ chối người nhận: {', '.join(exc.recipients)}") from exc
    except smtplib.SMTPException as exc:
        raise MailError(f"Lỗi SMTP: {str(exc)[:300]}") from exc
    except (OSError, ssl.SSLError) as exc:
        raise MailError(f"Không kết nối được {cfg['host']}:{cfg['port']} ({str(exc)[:200]})") from exc
