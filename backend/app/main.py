"""SOC Rapid Block — API backend (FastAPI) cho mini app chặn IP trên Sophos Firewall."""
from __future__ import annotations

import csv
import io
import os
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .config import settings
from .crypto import MasterKeyMissing, decrypt, encrypt, issue_token, verify_token
from .db import AuditLog, Firewall, get_session, init_db
from .ipparse import extract, host_object_name
from .service import (
    audit,
    block_on_firewall,
    client_for,
    normalize_entries,
    test_firewall,
    unblock_on_firewall,
)
from .sophos import SophosAuthError, SophosError

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


# ------------------------------------------------------------------- helpers
def current_user(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
) -> str:
    user = verify_token(x_auth_token or "")
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc session đã hết hạn")
    return user


def client_ip_of(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def get_fw(db: Session, fw_id: int) -> Firewall:
    fw = db.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, f"Không tìm thấy firewall id={fw_id}")
    return fw


def selected_firewalls(db: Session, ids: list[int] | None) -> list[Firewall]:
    stmt = select(Firewall).where(Firewall.enabled.is_(True))
    if ids:
        stmt = select(Firewall).where(Firewall.id.in_(ids))
    fws = list(db.scalars(stmt).all())
    if not fws:
        raise HTTPException(400, "Chưa chọn firewall nào (hoặc firewall đang bị tắt)")
    return fws


# ---------------------------------------------------------------------- auth
@app.post("/api/login")
def login(payload: dict = Body(...)):
    if (payload.get("password") or "") != settings.APP_PASSWORD:
        raise HTTPException(401, "Mật khẩu không đúng")
    user = (payload.get("user") or "soc").strip()[:60] or "soc"
    return {"token": issue_token(user), "user": user, "ttl_hours": settings.SESSION_TTL_HOURS}


@app.get("/api/config")
def config(user: str = Depends(current_user)):
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "user": user,
        "host_prefix": settings.HOST_PREFIX,
        "safe_list": [s.strip() for s in settings.SAFE_LIST.split(",") if s.strip()],
        "allow_private": settings.ALLOW_PRIVATE,
        "master_key_set": bool(settings.MASTER_KEY),
    }


# ----------------------------------------------------------------- firewalls
@app.get("/api/firewalls")
def list_firewalls(db: Session = Depends(get_session), user: str = Depends(current_user)):
    fws = db.scalars(select(Firewall).order_by(Firewall.name)).all()
    return [f.to_dict() for f in fws]


@app.post("/api/firewalls")
def create_firewall(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    required = ("name", "host", "username", "password")
    missing = [k for k in required if not (payload.get(k) or "").strip()]
    if missing:
        raise HTTPException(400, f"Thiếu thông tin: {', '.join(missing)}")
    if db.scalar(select(Firewall).where(Firewall.name == payload["name"].strip())):
        raise HTTPException(400, "Tên firewall đã tồn tại")
    try:
        pwd = encrypt(payload["password"])
    except MasterKeyMissing as exc:
        raise HTTPException(400, str(exc)) from exc

    fw = Firewall(
        name=payload["name"].strip(),
        site=(payload.get("site") or "").strip(),
        host=payload["host"].strip(),
        port=int(payload.get("port") or 4444),
        username=payload["username"].strip(),
        password_enc=pwd,
        default_group=(payload.get("default_group") or "SOC_BLOCKED_IPS").strip(),
        verify_ssl=bool(payload.get("verify_ssl")),
        enabled=bool(payload.get("enabled", True)),
        note=(payload.get("note") or "").strip(),
    )
    db.add(fw)
    db.commit()
    audit(db, action="firewall_cud", fw=fw, target="create", result="ok",
          message=f"{fw.host}:{fw.port}", actor=user, client_ip=client_ip_of(request))
    db.commit()
    return fw.to_dict()


@app.put("/api/firewalls/{fw_id}")
def update_firewall(
    fw_id: int,
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    fw = get_fw(db, fw_id)
    for field in ("name", "site", "host", "username", "default_group", "note"):
        if payload.get(field) is not None:
            setattr(fw, field, str(payload[field]).strip())
    if payload.get("port"):
        fw.port = int(payload["port"])
    if payload.get("verify_ssl") is not None:
        fw.verify_ssl = bool(payload["verify_ssl"])
    if payload.get("enabled") is not None:
        fw.enabled = bool(payload["enabled"])
    if payload.get("password"):
        try:
            fw.password_enc = encrypt(payload["password"])
        except MasterKeyMissing as exc:
            raise HTTPException(400, str(exc)) from exc
    db.add(fw)
    db.commit()
    audit(db, action="firewall_cud", fw=fw, target="update", result="ok",
          actor=user, client_ip=client_ip_of(request))
    db.commit()
    return fw.to_dict()


@app.delete("/api/firewalls/{fw_id}")
def delete_firewall(
    fw_id: int,
    request: Request,
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    fw = get_fw(db, fw_id)
    name, host = fw.name, f"{fw.host}:{fw.port}"
    db.query(AuditLog).filter(AuditLog.firewall_id == fw.id).update({"firewall_id": None})
    db.delete(fw)
    db.commit()
    audit(db, action="firewall_cud", fw=None, target=f"delete {name}", result="ok",
          message=host, actor=user, client_ip=client_ip_of(request))
    db.commit()
    return {"ok": True, "deleted": name}


@app.post("/api/firewalls/{fw_id}/test")
def test_one(
    fw_id: int,
    request: Request,
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    return test_firewall(db, get_fw(db, fw_id), user, client_ip_of(request))


@app.post("/api/firewalls/test-all")
def test_all(
    request: Request,
    payload: dict = Body(default={}),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    fws = selected_firewalls(db, payload.get("firewall_ids"))
    ip = client_ip_of(request)
    return {"results": [test_firewall(db, fw, user, ip) for fw in fws]}


# --------------------------------------------------------------- object view
@app.get("/api/firewalls/{fw_id}/groups")
def fw_groups(
    fw_id: int, db: Session = Depends(get_session), user: str = Depends(current_user)
):
    fw = get_fw(db, fw_id)
    try:
        groups = client_for(fw).list_groups()
    except (SophosError, SophosAuthError, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {
        "firewall": fw.name,
        "default_group": fw.default_group,
        "groups": [{**g, "count": len(g["hosts"])} for g in groups],
    }


@app.get("/api/firewalls/{fw_id}/group-members")
def fw_group_members(
    fw_id: int,
    group: str = Query(...),
    q: str = Query(default=""),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    fw = get_fw(db, fw_id)
    try:
        cli = client_for(fw)
        g = cli.get_group(group)
        if not g:
            raise HTTPException(404, f"Group '{group}' không tồn tại trên {fw.name}")
        details = {h["name"]: h for h in cli.get_hosts(g["hosts"])} if g["hosts"] else {}
    except (SophosError, SophosAuthError, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc

    members = []
    for name in g["hosts"]:
        d = details.get(name, {})
        value = d.get("ip_address") or d.get("start_ip") or ""
        if d.get("host_type") == "IPRange" and d.get("start_ip"):
            value = f"{d['start_ip']} - {d.get('end_ip', '')}"
        elif d.get("host_type") == "Network" and d.get("subnet"):
            try:
                import ipaddress

                net = ipaddress.ip_network(f"{d['ip_address']}/{d['subnet']}", strict=False)
                value = str(net)
            except ValueError:
                value = f"{d['ip_address']}/{d['subnet']}"
        members.append(
            {
                "object": name,
                "host_type": d.get("host_type", ""),
                "value": value,
                "description": d.get("description", ""),
            }
        )
    if q:
        needle = q.lower().strip()
        members = [m for m in members if needle in m["object"].lower() or needle in m["value"].lower()]
    return {
        "firewall": fw.name, "group": g["name"], "description": g["description"],
        "ip_family": g["ip_family"], "total": len(g["hosts"]), "members": members,
    }


# ------------------------------------------------------------------- parsing
@app.post("/api/parse")
def parse_text(payload: dict = Body(...), user: str = Depends(current_user)):
    text = payload.get("text") or ""
    extra_safe = payload.get("extra_safe") or []
    res = extract(text, extra_safe)
    for item in res["accepted"]:
        item["object"] = host_object_name(item["value"])
    return res


# --------------------------------------------------------------------- block
@app.post("/api/block")
def block(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    values: list[str] = [str(v) for v in (payload.get("values") or [])]
    if payload.get("text"):
        values += [i["value"] for i in extract(payload["text"], payload.get("extra_safe")) ["accepted"]]
    entries, rejected = normalize_entries(values, payload.get("extra_safe"))
    if not entries:
        raise HTTPException(400, "Không có IP hợp lệ nào để chặn")
    if len(entries) > 500:
        raise HTTPException(400, "Tối đa 500 IP mỗi lần để tránh treo firewall")

    fws = selected_firewalls(db, payload.get("firewall_ids"))
    ip = client_ip_of(request)
    results = [
        block_on_firewall(
            db, fw, entries,
            group_override=payload.get("group") or "",
            reason=payload.get("reason") or "",
            source=payload.get("source") or "manual",
            actor=user, client_ip=ip, dry_run=bool(payload.get("dry_run")),
        )
        for fw in fws
    ]
    return {"entries": entries, "rejected": rejected, "results": results}


@app.post("/api/unblock")
def unblock(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    targets = [str(t).strip() for t in (payload.get("targets") or []) if str(t).strip()]
    if not targets:
        raise HTTPException(400, "Chưa chọn IP/object nào để bỏ chặn")
    fws = selected_firewalls(db, payload.get("firewall_ids"))
    ip = client_ip_of(request)
    results = [
        unblock_on_firewall(
            db, fw, targets,
            group_override=payload.get("group") or "",
            delete_object=bool(payload.get("delete_object")),
            reason=payload.get("reason") or "",
            actor=user, client_ip=ip,
        )
        for fw in fws
    ]
    return {"targets": targets, "results": results}


# --------------------------------------------------------------------- audit
@app.get("/api/audit")
def audit_list(
    limit: int = Query(default=200, le=2000),
    action: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    stmt = select(AuditLog).order_by(desc(AuditLog.id)).limit(limit)
    if action:
        stmt = select(AuditLog).where(AuditLog.action == action).order_by(desc(AuditLog.id)).limit(limit)
    rows = [r.to_dict() for r in db.scalars(stmt).all()]
    if q:
        needle = q.lower()
        rows = [
            r for r in rows
            if needle in (r["target"] or "").lower()
            or needle in (r["firewall_name"] or "").lower()
            or needle in (r["reason"] or "").lower()
        ]
    return {"rows": rows, "count": len(rows)}


@app.get("/api/audit.csv")
def audit_csv(
    token: str = Query(default=""),
    db: Session = Depends(get_session),
):
    if not verify_token(token):
        raise HTTPException(401, "Token không hợp lệ")
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.id)).limit(5000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["thoi_gian", "nguoi_thuc_hien", "hanh_dong", "firewall", "group",
                "doi_tuong", "ket_qua", "ma_loi", "thong_diep", "ly_do", "nguon", "ip_client"])
    for r in rows:
        d = r.to_dict()
        w.writerow([d["ts"], d["actor"], d["action"], d["firewall_name"], d["group_name"],
                    d["target"], d["result"], d["status_code"], d["message"], d["reason"],
                    d["source"], d["client_ip"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_soc_rapid_block.csv"},
    )


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


# ------------------------------------------------------------ static frontend
_FRONTEND = os.getenv(
    "FRONTEND_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend"),
)
if os.path.isdir(_FRONTEND):
    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
