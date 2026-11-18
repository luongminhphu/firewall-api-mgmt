"""Nghiệp vụ firewall: tạo client Sophos, CRUD, kiểm tra kết nối. Không phụ thuộc FastAPI."""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import Firewall
from ...core.security import MasterKeyMissing, decrypt, encrypt
from ...integrations.sophos import SophosAuthError, SophosClient, SophosError
from ...integrations.sophos.policy import BLOCK_GROUP
from ..shared import enforce_group_audited
from . import repository as repo
from .schemas import FirewallCreateIn, FirewallUpdateIn


def client_for(fw: Firewall) -> SophosClient:
    return SophosClient(
        host=fw.host,
        port=fw.port,
        username=fw.username,
        password=decrypt(fw.password_enc),
        verify_ssl=fw.verify_ssl,
        timeout=settings.API_TIMEOUT,
        connect_timeout=settings.API_CONNECT_TIMEOUT,
    )


def mark_status(db: Session, fw: Firewall, status: str, message: str) -> None:
    fw.last_status = status
    fw.last_message = message[:2000]
    fw.last_checked = dt.datetime.now(dt.timezone.utc)
    db.add(fw)


def test_firewall(db: Session, fw: Firewall, actor: str, client_ip: str) -> dict:
    try:
        with client_for(fw) as cli:
            res = cli.test_login()
        mark_status(db, fw, "ok", res.message)
        audit(
            db, action="test", fw=fw, target=f"{fw.host}:{fw.port}", result="ok",
            code=res.code, message=res.message, actor=actor, client_ip=client_ip,
        )
        out = {"ok": True, "message": res.message, "code": res.code}
    except (SophosError, SophosAuthError, ValueError) as exc:
        msg = str(exc)
        code = getattr(exc, "code", "")
        status = "auth_error" if isinstance(exc, SophosAuthError) else "error"
        mark_status(db, fw, status, msg)
        audit(
            db, action="test", fw=fw, target=f"{fw.host}:{fw.port}", result="error",
            code=code, message=msg, actor=actor, client_ip=client_ip,
        )
        out = {"ok": False, "message": msg, "code": code}
    db.commit()
    return {"firewall_id": fw.id, "firewall": fw.name, **out}


def get_or_404(db: Session, fw_id: int) -> Firewall:
    fw = repo.get(db, fw_id)
    if not fw:
        raise AppError(404, f"Không tìm thấy firewall id={fw_id}")
    return fw


def _encrypt(password: str) -> str:
    try:
        return encrypt(password)
    except MasterKeyMissing as exc:
        raise AppError(400, str(exc)) from exc


def create(db: Session, data: FirewallCreateIn, *, actor: str, client_ip: str) -> Firewall:
    fields = data.model_dump()
    missing = [k for k in ("name", "host", "username", "password") if not (fields.get(k) or "").strip()]
    if missing:
        raise AppError(400, f"Thiếu thông tin: {', '.join(missing)}")
    if repo.get_by_name(db, data.name.strip()):
        raise AppError(400, "Tên firewall đã tồn tại")
    pwd = _encrypt(data.password)
    fw = Firewall(
        name=data.name.strip(),
        site=(data.site or "").strip(),
        host=data.host.strip(),
        port=int(data.port or 4444),
        username=data.username.strip(),
        password_enc=pwd,
        default_group=enforce_group_audited(db, data.default_group, actor=actor, client_ip=client_ip),
        verify_ssl=bool(data.verify_ssl),
        # như bản cũ bool(payload.get("enabled", True)): thiếu trường → bật; gửi null → tắt
        enabled=bool(data.enabled) if "enabled" in data.model_fields_set else True,
        note=(data.note or "").strip(),
    )
    repo.save(db, fw)
    audit(db, action="firewall_cud", fw=fw, target="create", result="ok",
          message=f"{fw.host}:{fw.port}", actor=actor, client_ip=client_ip)
    db.commit()
    return fw


def update(db: Session, fw_id: int, data: FirewallUpdateIn, *, actor: str, client_ip: str) -> Firewall:
    fw = get_or_404(db, fw_id)
    if data.default_group is not None:
        enforce_group_audited(db, data.default_group, actor=actor, client_ip=client_ip)
    fw.default_group = BLOCK_GROUP
    for field in ("name", "site", "host", "username", "note"):
        value = getattr(data, field)
        if value is not None:
            setattr(fw, field, str(value).strip())
    if data.port:
        fw.port = int(data.port)
    if data.verify_ssl is not None:
        fw.verify_ssl = bool(data.verify_ssl)
    if data.enabled is not None:
        fw.enabled = bool(data.enabled)
    if data.password:
        fw.password_enc = _encrypt(data.password)
    repo.save(db, fw)
    audit(db, action="firewall_cud", fw=fw, target="update", result="ok", actor=actor, client_ip=client_ip)
    db.commit()
    return fw


def delete(db: Session, fw_id: int, *, actor: str, client_ip: str, on_delete=None) -> str:
    fw = get_or_404(db, fw_id)
    name, host = fw.name, f"{fw.host}:{fw.port}"
    if on_delete:
        on_delete(db, fw)  # dọn dữ liệu phụ thuộc (cache group) trước khi xóa
    repo.delete(db, fw)
    db.commit()
    audit(db, action="firewall_cud", fw=None, target=f"delete {name}", result="ok",
          message=host, actor=actor, client_ip=client_ip)
    db.commit()
    return name
