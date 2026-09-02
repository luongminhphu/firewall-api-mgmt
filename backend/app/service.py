"""Nghiệp vụ: chặn / bỏ chặn IP trên nhiều firewall Sophos + ghi audit."""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from .config import settings
from .crypto import decrypt
from .db import AuditLog, Firewall
from .ipparse import classify, host_object_name
from .sophos import SophosAuthError, SophosClient, SophosError


def client_for(fw: Firewall) -> SophosClient:
    return SophosClient(
        host=fw.host,
        port=fw.port,
        username=fw.username,
        password=decrypt(fw.password_enc),
        verify_ssl=fw.verify_ssl,
        timeout=settings.API_TIMEOUT,
    )


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


def mark_status(db: Session, fw: Firewall, status: str, message: str) -> None:
    fw.last_status = status
    fw.last_message = message[:2000]
    fw.last_checked = dt.datetime.now(dt.timezone.utc)
    db.add(fw)


# --------------------------------------------------------------------- test
def test_firewall(db: Session, fw: Firewall, actor: str, client_ip: str) -> dict:
    try:
        res = client_for(fw).test_login()
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


# -------------------------------------------------------------------- block
def block_on_firewall(
    db: Session,
    fw: Firewall,
    entries: list[dict],
    *,
    group_override: str = "",
    reason: str = "",
    source: str = "manual",
    actor: str = "soc",
    client_ip: str = "",
    dry_run: bool = False,
) -> dict:
    group = (group_override or fw.default_group).strip()
    rows: list[dict] = []
    try:
        cli = client_for(fw)
        existing_group = cli.get_group(group)
    except (SophosError, SophosAuthError, ValueError) as exc:
        msg = str(exc)
        mark_status(db, fw, "error", msg)
        for e in entries:
            audit(
                db, action="block", fw=fw, target=e["value"], result="error",
                message=msg, group=group, reason=reason, source=source,
                actor=actor, client_ip=client_ip, code=getattr(exc, "code", ""),
            )
        db.commit()
        return {
            "firewall_id": fw.id, "firewall": fw.name, "group": group,
            "ok": False, "error": msg, "rows": [], 
            "summary": {"added": 0, "existed": 0, "error": len(entries), "skipped": 0},
        }

    group_hosts = list(existing_group["hosts"]) if existing_group else []
    ip_index: dict[str, str] | None = None  # ip -> object name, nạp khi cần
    to_link: list[str] = []

    for e in entries:
        value, kind = e["value"], e.get("kind") or "IP"
        obj = host_object_name(value)
        row = {"value": value, "object": obj, "result": "", "code": "", "message": ""}

        if dry_run:
            row.update(result="dry-run", message=f"Sẽ tạo object {obj} và thêm vào {group}")
            rows.append(row)
            continue

        try:
            res = cli.add_ip_host(obj, kind, value, description=reason[:255])
            if res.ok:
                row.update(result="added", code=res.code, message=res.message)
            elif res.code == "502":  # đã tồn tại đúng tên
                row.update(result="existed", code=res.code, message="Object đã tồn tại, dùng lại")
            elif res.code == "503":  # đã có object khác cùng IP
                if ip_index is None:
                    ip_index = {h["ip_address"]: h["name"] for h in cli.get_hosts() if h["ip_address"]}
                found = ip_index.get(value)
                if found:
                    obj = found
                    row.update(
                        object=obj, result="existed", code=res.code,
                        message=f"IP đã tồn tại dưới object '{found}', dùng lại",
                    )
                else:
                    row.update(result="error", code=res.code, message=res.message)
            else:
                row.update(result="error", code=res.code, message=res.message)
        except (SophosError, SophosAuthError) as exc:
            row.update(result="error", code=getattr(exc, "code", ""), message=str(exc))

        if row["result"] in ("added", "existed"):
            if obj in group_hosts:
                row["message"] = (row["message"] + " · đã nằm trong group").strip(" ·")
                row["result"] = "existed"
            else:
                to_link.append(obj)
        rows.append(row)

    group_result = {"changed": False, "code": "", "message": ""}
    if not dry_run and to_link:
        merged = group_hosts + [h for h in to_link if h not in group_hosts]
        try:
            if existing_group:
                gres = cli.set_group_hosts(
                    group, merged, existing_group.get("description", ""),
                    existing_group.get("ip_family", "IPv4"),
                )
            else:
                gres = cli.create_group(group, merged, f"SOC block group ({reason})"[:255])
            group_result = {"changed": gres.ok, "code": gres.code, "message": gres.message}
            if not gres.ok:
                for r in rows:
                    if r["object"] in to_link:
                        r.update(result="error", code=gres.code,
                                 message=f"Tạo object OK nhưng cập nhật group lỗi: {gres.message}")
        except (SophosError, SophosAuthError) as exc:
            group_result = {"changed": False, "code": getattr(exc, "code", ""), "message": str(exc)}
            for r in rows:
                if r["object"] in to_link:
                    r.update(result="error", message=f"Cập nhật group lỗi: {exc}")

    for r in rows:
        audit(
            db, action="block", fw=fw, target=r["value"],
            result="ok" if r["result"] in ("added", "existed") else r["result"],
            code=r["code"], message=f"{r['object']} · {r['message']}", group=group,
            reason=reason, source=source, actor=actor, client_ip=client_ip,
        )
    ok_rows = [r for r in rows if r["result"] in ("added", "existed", "dry-run")]
    mark_status(db, fw, "ok" if ok_rows else "error", group_result.get("message") or "")
    db.commit()

    return {
        "firewall_id": fw.id,
        "firewall": fw.name,
        "group": group,
        "ok": bool(ok_rows) and all(r["result"] != "error" for r in rows),
        "rows": rows,
        "group_result": group_result,
        "summary": {
            "added": sum(1 for r in rows if r["result"] == "added"),
            "existed": sum(1 for r in rows if r["result"] == "existed"),
            "error": sum(1 for r in rows if r["result"] == "error"),
            "dry_run": sum(1 for r in rows if r["result"] == "dry-run"),
        },
    }


# ------------------------------------------------------------------ unblock
def unblock_on_firewall(
    db: Session,
    fw: Firewall,
    targets: list[str],
    *,
    group_override: str = "",
    delete_object: bool = False,
    reason: str = "",
    actor: str = "soc",
    client_ip: str = "",
) -> dict:
    """`targets` có thể là tên object hoặc địa chỉ IP."""
    group = (group_override or fw.default_group).strip()
    rows: list[dict] = []
    try:
        cli = client_for(fw)
        g = cli.get_group(group)
        if not g:
            raise SophosError(f"Group '{group}' không tồn tại trên firewall này", "526")
        hosts = list(g["hosts"])
        details = cli.get_hosts(hosts) if hosts else []
        ip_of = {h["name"]: h["ip_address"] for h in details}
    except (SophosError, SophosAuthError, ValueError) as exc:
        msg = str(exc)
        mark_status(db, fw, "error", msg)
        for t in targets:
            audit(db, action="unblock", fw=fw, target=t, result="error", message=msg,
                  group=group, reason=reason, actor=actor, client_ip=client_ip)
        db.commit()
        return {"firewall_id": fw.id, "firewall": fw.name, "group": group, "ok": False,
                "error": msg, "rows": []}

    remove: list[str] = []
    for t in targets:
        t = t.strip()
        match = None
        if t in hosts:
            match = t
        else:
            candidate = host_object_name(t)
            if candidate in hosts:
                match = candidate
            else:
                for name, ip in ip_of.items():
                    if ip and ip == t:
                        match = name
                        break
        if match:
            remove.append(match)
            rows.append({"value": t, "object": match, "result": "removed", "message": "Đã bỏ khỏi group"})
        else:
            rows.append({"value": t, "object": "", "result": "not_found",
                         "message": f"Không tìm thấy trong group {group}"})

    if remove:
        remaining = [h for h in hosts if h not in remove]
        try:
            gres = cli.set_group_hosts(group, remaining, g.get("description", ""), g.get("ip_family", "IPv4"))
            if not gres.ok:
                for r in rows:
                    if r["result"] == "removed":
                        r.update(result="error", message=f"Cập nhật group lỗi: {gres.message}")
            elif delete_object:
                for r in rows:
                    if r["result"] != "removed":
                        continue
                    try:
                        dres = cli.delete_ip_host(r["object"])
                        r["message"] += " · xóa object: " + (
                            "OK" if dres.ok else f"lỗi {dres.code} {dres.message}"
                        )
                    except SophosError as exc:
                        r["message"] += f" · xóa object lỗi: {exc}"
        except (SophosError, SophosAuthError) as exc:
            for r in rows:
                if r["result"] == "removed":
                    r.update(result="error", message=f"Cập nhật group lỗi: {exc}")

    for r in rows:
        audit(db, action="unblock", fw=fw, target=r["value"],
              result="ok" if r["result"] == "removed" else r["result"],
              message=f"{r['object']} · {r['message']}", group=group, reason=reason,
              actor=actor, client_ip=client_ip)
    db.commit()

    return {
        "firewall_id": fw.id, "firewall": fw.name, "group": group,
        "ok": all(r["result"] in ("removed", "not_found") for r in rows),
        "rows": rows,
        "summary": {
            "removed": sum(1 for r in rows if r["result"] == "removed"),
            "not_found": sum(1 for r in rows if r["result"] == "not_found"),
            "error": sum(1 for r in rows if r["result"] == "error"),
        },
    }


def normalize_entries(values: list[str], extra_safe: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    ok, bad = [], []
    seen = set()
    for v in values:
        info = classify(v, extra_safe)
        if not info["valid"] or info["excluded"]:
            bad.append(info)
            continue
        if info["value"] in seen:
            continue
        seen.add(info["value"])
        ok.append({"value": info["value"], "kind": info["kind"]})
    return ok, bad
