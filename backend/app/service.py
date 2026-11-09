"""Nghiệp vụ: chặn / bỏ chặn IP trên nhiều firewall Sophos + ghi audit."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import changelog
from .config import settings
from .crypto import decrypt
from .db import AuditLog, Firewall, GroupCache
from .ipparse import classify, host_object_name, legacy_object_name
from .policy import BLOCK_GROUP, BLOCK_GROUP_FAMILY, GroupPolicyError
from .sophos import SophosAuthError, SophosClient, SophosError, build_iphostgroup_xml, pretty_xml


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


log = logging.getLogger("service")


def derive_host(name: str) -> dict | None:
    """Suy ra chi tiết IP Host từ tên object (không cần gọi firewall).

    Từ v1.4 tên object = chính IP/CIDR (`45.1.2.3`, `185.220.101.0/24`); bản cũ dùng `SOC_BLOCK_45_1_2_3`,
    `SOC_BLOCK_185_220_101_0-24`. Tên khác (object tạo tay) trả về None → phải tra trên firewall.
    """
    raw = name.strip()
    if settings.HOST_PREFIX and raw.startswith(settings.HOST_PREFIX):
        raw = raw[len(settings.HOST_PREFIX):].replace("_", ".").replace("-", "/")
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version != 4:
                return None
            if net.prefixlen == 32:
                return {"name": name, "host_type": "IP", "ip_address": str(net.network_address), "subnet": "",
                        "start_ip": "", "end_ip": "", "description": "", "derived": True}
            return {"name": name, "host_type": "Network", "ip_address": str(net.network_address),
                    "subnet": str(net.netmask), "start_ip": "", "end_ip": "", "description": "", "derived": True}
        ip = ipaddress.ip_address(raw)
        if ip.version != 4:
            return None
        return {"name": name, "host_type": "IP", "ip_address": str(ip), "subnet": "",
                "start_ip": "", "end_ip": "", "description": "", "derived": True}
    except ValueError:
        return None


def cached_details(db: Session, fw_id: int) -> dict[str, dict]:
    """Chi tiết IP Host đã biết từ lượt quét đầy đủ gần nhất (bảng group_cache)."""
    row = db.scalar(select(GroupCache).where(GroupCache.firewall_id == fw_id))
    if not row or not row.data_json:
        return {}
    try:
        data = json.loads(row.data_json)
    except ValueError:
        return {}
    return {d["name"]: d for d in data.get("details", []) if isinstance(d, dict) and d.get("name")}


def resolve_hosts(cli: SophosClient, names: list[str], known: dict[str, dict] | None = None,
                  *, full_timeout: int | None = None) -> tuple[dict[str, dict], list[str]]:
    """Chi tiết các IP Host theo tên mà KHÔNG đọc toàn bộ IP Host của firewall nếu không cần.

    Thứ tự: cache lượt quét đầy đủ → suy ra từ tên (IP/CIDR) → tra từng tên (≤ HOST_LOOKUP_LIMIT)
    → nếu còn nhiều hơn thì mới đọc cả danh sách. Trả (chi tiết, danh sách tên chưa xác định được).
    """
    known = known or {}
    out: dict[str, dict] = {}
    unknown: list[str] = []
    for n in names:
        if n in known:
            out[n] = known[n]
        elif (d := derive_host(n)) is not None:
            out[n] = d
        else:
            unknown.append(n)
    if not unknown:
        return out, []
    try:
        if len(unknown) <= settings.HOST_LOOKUP_LIMIT:
            for n in unknown:
                h = cli.get_host(n)
                if h:
                    out[n] = h
        else:
            want = set(unknown)
            for h in cli.get_hosts(timeout=full_timeout or settings.GROUP_SCAN_TIMEOUT):
                if h["name"] in want:
                    out[h["name"]] = h
    except SophosError as exc:
        log.warning("Không tra được chi tiết %d IP Host: %s", len(unknown), exc)
    return out, [n for n in unknown if n not in out]


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


def _host_value(h: dict) -> str:
    """Giá trị hiển thị của IP Host: IP, CIDR hoặc dải."""
    t = h.get("host_type", "")
    if t == "Network" and h.get("subnet"):
        try:
            import ipaddress

            return str(ipaddress.ip_network(f"{h['ip_address']}/{h['subnet']}", strict=False))
        except ValueError:
            return f"{h.get('ip_address', '')}/{h['subnet']}"
    if t == "IPRange" and h.get("start_ip"):
        return f"{h['start_ip']}-{h.get('end_ip', '')}"
    return h.get("ip_address") or ""


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
    reason: str = "",
    source: str = "manual",
    actor: str = "soc",
    client_ip: str = "",
    dry_run: bool = False,
    who: dict | None = None,
) -> dict:
    group = BLOCK_GROUP  # cố định — xem policy.py
    who = who or {"user": actor, "name": actor, "method": "local"}
    rows: list[dict] = []
    try:
        cli = client_for(fw)
        existing_group = cli.get_group(group)
        if not existing_group:
            # Không tự tạo group: group mới chưa gắn vào rule chặn nào sẽ khiến việc "chặn" vô tác dụng
            raise SophosError(
                f"IP Host Group '{group}' chưa tồn tại trên {fw.name}. Admin firewall cần tạo group "
                f"này ({BLOCK_GROUP_FAMILY}) và gắn vào firewall rule chặn trước khi dùng app.",
                "526",
            )
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

    group_family = existing_group.get("ip_family") or "IPv4"
    if group_family != BLOCK_GROUP_FAMILY:
        # Sophos không cho trộn IPv4 và IPv6 trong cùng một IPHostGroup
        msg = (f"Group '{group}' là IPHostGroup {group_family} — không thể thêm IP Host IPv4. "
               "Hãy chọn/tạo group IPv4 khác.")
        for e in entries:
            audit(db, action="block", fw=fw, target=e["value"], result="error", message=msg,
                  group=group, reason=reason, source=source, actor=actor, client_ip=client_ip)
        db.commit()
        return {
            "firewall_id": fw.id, "firewall": fw.name, "group": group, "ok": False, "error": msg,
            "rows": [], "summary": {"added": 0, "existed": 0, "error": len(entries), "skipped": 0},
        }
    group_desc = existing_group.get("description") or ""
    group_hosts = list(existing_group["hosts"])

    # Giá trị IP/CIDR của các thành viên hiện có (để nhận ra IP đã bị chặn, kể cả object tên kiểu cũ)
    # v1.6.1: không đọc toàn bộ IP Host (chậm/timeout với firewall nhiều object) — dùng cache + suy từ tên.
    _all_hosts: list[dict] | None = None

    def all_hosts() -> list[dict]:
        """Chỉ dùng khi hiếm gặp: firewall báo đã có object khác cùng IP (mã 503)."""
        nonlocal _all_hosts
        if _all_hosts is None:
            _all_hosts = cli.get_hosts(timeout=settings.GROUP_SCAN_TIMEOUT)
        return _all_hosts

    member_value: dict[str, str] = {}
    if group_hosts:
        try:
            det, _ = resolve_hosts(cli, group_hosts, cached_details(db, fw.id))
            member_value = {n: _host_value(h) for n, h in det.items()}
        except Exception:  # noqa: BLE001
            member_value = {}
    in_group = {host_object_name(v): n for n, v in member_value.items() if v}

    # Phát hiện thay đổi ngoài app trước khi sửa group
    try:
        changelog.detect_drift(
            db, fw, group, {h: "" for h in group_hosts},
            resolve_values=lambda names: {n: member_value.get(n, "") for n in names},
        )
    except Exception:  # noqa: BLE001 — không để drift chặn thao tác khẩn cấp
        pass
    to_link: list[str] = []

    for e in entries:
        value, kind = e["value"], e.get("kind") or "IP"
        obj = host_object_name(value)
        row = {"value": value, "object": obj, "result": "", "code": "", "message": ""}

        already = in_group.get(obj)
        if already:
            row.update(object=already, result="existed",
                       message=f"Đã nằm trong {group} (object '{already}')")
            rows.append(row)
            continue

        if dry_run:
            row.update(result="dry-run", message=f"Sẽ tạo object {obj} và thêm vào {group}")
            rows.append(row)
            continue

        try:
            res = cli.add_ip_host(obj, kind, value, description=reason[:255])
            if res.ok:
                row.update(result="added", code=res.code, message=res.message)
            elif res.code == "502":  # đã có object đúng tên — chỉ dùng lại nếu trỏ đúng địa chỉ
                cur = cli.get_host(obj)
                cur_val = _host_value(cur) if cur else ""
                if cur and host_object_name(cur_val) == obj:
                    row.update(result="existed", code=res.code, message="Object đã tồn tại, dùng lại")
                else:
                    row.update(result="error", code=res.code,
                               message=f"Đã có object tên '{obj}' nhưng trỏ tới '{cur_val or '?'}' — không dùng")
            elif res.code == "503":  # đã có object khác cùng IP
                ip_index = {host_object_name(_host_value(h)): h["name"] for h in all_hosts() if _host_value(h)}
                found = ip_index.get(obj)
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
            gres = cli.set_group_hosts(group, merged, group_desc, group_family)
            group_result = {"changed": gres.ok, "code": gres.code, "message": gres.message}
            if gres.ok:
                values = {r["object"]: r["value"] for r in rows}
                batch = changelog.new_batch()
                changelog.record(
                    db, fw=fw, group=group, change_type="add",
                    items=[(o, values.get(o, "")) for o in to_link],
                    count_before=len(group_hosts), count_after=len(merged), who=who,
                    reason=reason, source=source, client_ip=client_ip, batch_id=batch,
                )
                group_result["batch_id"] = batch
                snap = changelog.get_snapshot(db, fw.id, group)
                known = __import__("json").loads(snap.members_json) if snap else {}
                changelog.save_snapshot(db, fw.id, group,
                                        {h: values.get(h) or known.get(h, "") for h in merged})
            if not gres.ok:
                for r in rows:
                    if r["object"] in to_link:
                        r.update(result="error", code=gres.code,
                                 message=f"Tạo object OK nhưng cập nhật group lỗi: {gres.message}")
        except (SophosError, SophosAuthError, ValueError) as exc:
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

    # Payload IPHostGroup (dự kiến khi chạy thử / đã gửi khi chạy thật) để người trực đối chiếu
    planned = [r["object"] for r in rows if r["result"] in ("added", "existed", "dry-run")]
    final_hosts = group_hosts + [h for h in planned if h not in group_hosts]
    try:
        group_xml = pretty_xml(build_iphostgroup_xml(group, final_hosts, group_desc, group_family))
    except ValueError as exc:
        group_xml = f"<!-- {exc} -->"

    return {
        "firewall_id": fw.id,
        "firewall": fw.name,
        "group": group,
        "ip_family": group_family,
        "group_operation": "update",
        "group_xml": group_xml,
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
    delete_object: bool = False,
    reason: str = "",
    actor: str = "soc",
    client_ip: str = "",
    who: dict | None = None,
) -> dict:
    """`targets` có thể là tên object hoặc địa chỉ IP."""
    group = BLOCK_GROUP  # cố định — xem policy.py
    who = who or {"user": actor, "name": actor, "method": "local"}
    rows: list[dict] = []
    try:
        cli = client_for(fw)
        g = cli.get_group(group)
        if not g:
            raise SophosError(f"Group '{group}' không tồn tại trên firewall này", "526")
        hosts = list(g["hosts"])
        det, _ = resolve_hosts(cli, hosts, cached_details(db, fw.id)) if hosts else ({}, [])
        ip_of = {n: _host_value(h) for n, h in det.items()}
    except (SophosError, SophosAuthError, ValueError) as exc:
        msg = str(exc)
        mark_status(db, fw, "error", msg)
        for t in targets:
            audit(db, action="unblock", fw=fw, target=t, result="error", message=msg,
                  group=group, reason=reason, actor=actor, client_ip=client_ip)
        db.commit()
        return {"firewall_id": fw.id, "firewall": fw.name, "group": group, "ok": False,
                "error": msg, "rows": []}

    try:
        changelog.detect_drift(db, fw, group, {h: ip_of.get(h, "") for h in hosts})
    except Exception:  # noqa: BLE001
        pass

    remove: list[str] = []
    for t in targets:
        t = t.strip()
        match = None
        if t in hosts:
            match = t
        else:
            norm = host_object_name(t)
            for candidate in (norm, legacy_object_name(t)):
                if candidate in hosts:
                    match = candidate
                    break
            if not match:
                for name, ip in ip_of.items():
                    if ip and (host_object_name(ip) == norm or ip.split("/")[0] == t):
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
            if gres.ok:
                changelog.record(
                    db, fw=fw, group=group, change_type="remove",
                    items=[(o, ip_of.get(o, "")) for o in remove],
                    count_before=len(hosts), count_after=len(remaining), who=who,
                    reason=reason, source="unblock", client_ip=client_ip,
                )
                changelog.save_snapshot(db, fw.id, group, {h: ip_of.get(h, "") for h in remaining})
            if not gres.ok:
                for r in rows:
                    if r["result"] == "removed":
                        r.update(result="error", message=f"Cập nhật group lỗi: {gres.message}")
            elif delete_object:
                for r in rows:
                    if r["result"] != "removed":
                        continue
                    try:
                        dres = cli.delete_ip_host(r["object"], ip_of.get(r["object"]))
                        r["message"] += " · xóa object: " + (
                            "OK" if dres.ok else f"lỗi {dres.code} {dres.message}"
                        )
                    except (SophosError, ValueError) as exc:
                        r["message"] += f" · xóa object lỗi: {exc}"
        except (SophosError, SophosAuthError, ValueError) as exc:
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
