"""Ghi nhật ký audit (bảng audit_logs). Hàm chỉ `db.add` — người gọi quyết định commit."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog, Firewall


def audit(
    db: Session,
    *,
    action: str,
    fw: Firewall | None,
    target: str,
    result: str,
    code: str = "",
    message: str = "",
    group: str = "",
    reason: str = "",
    source: str = "",
    actor: str = "soc",
    client_ip: str = "",
) -> None:
    db.add(
        AuditLog(
            action=action,
            firewall_id=fw.id if fw else None,
            firewall_name=fw.name if fw else "",
            group_name=group,
            target=target,
            result=result,
            status_code=code,
            message=message[:2000],
            reason=reason[:2000],
            source=source,
            actor=actor,
            client_ip=client_ip,
        )
    )
