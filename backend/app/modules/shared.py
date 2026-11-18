"""Kiểm tra dùng chung giữa các module nghiệp vụ."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..core.audit import audit
from ..core.errors import AppError
from ..integrations.sophos.policy import GroupPolicyError, enforce_group


def enforce_group_audited(db: Session, requested, *, actor: str, client_ip: str) -> str:
    """Áp chính sách group cố định; vi phạm → ghi audit 'policy_violation' rồi AppError 403."""
    try:
        return enforce_group(requested)
    except GroupPolicyError as exc:
        audit(db, action="policy_violation", fw=None, target=str(requested)[:120], result="denied",
              message=str(exc), group=str(requested)[:120], actor=actor, client_ip=client_ip)
        db.commit()
        raise AppError(403, str(exc)) from exc
