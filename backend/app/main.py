"""SOC Rapid Block — API backend (FastAPI) cho mini app chặn IP trên Sophos Firewall."""
from __future__ import annotations

import csv
import datetime as dt
import io
import os
import urllib.parse
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import auth as sso
from . import changelog
from .config import settings
from .crypto import MasterKeyMissing, decrypt, encrypt, issue_token, verify_principal, verify_token
from .db import AuditLog, Firewall, GroupChange, get_session, init_db
from .ipparse import extract, host_object_name
from .service import (
    _host_value,
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
def principal(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
) -> dict:
    p = verify_principal(x_auth_token or "")
    if not p:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc session đã hết hạn")
    return {"user": p["u"], "name": p.get("n") or p["u"], "role": p["r"], "method": p.get("m", "local")}


def current_user(p: dict = Depends(principal)) -> str:
    return p["user"]


def require(role: str):
    def dep(p: dict = Depends(principal)) -> dict:
        if not sso.role_at_least(p["role"], role):
            raise HTTPException(403, f"Vai trò '{p['role']}' không đủ quyền (cần '{role}')")
        return p
    return dep


def operator(p: dict = Depends(require("operator"))) -> dict:
    return p


def admin(p: dict = Depends(require("admin"))) -> dict:
    return p


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
@app.get("/api/auth/modes")
def auth_modes():
    modes = settings.auth_modes
    ready, msg = sso.oidc_ready()
    return {
        "modes": modes,
        "local": "local" in modes,
        "oidc": "oidc" in modes,
        "oidc_ready": ready,
        "oidc_message": msg,
        "header": "header" in modes,
    }


@app.post("/api/login")
def login(payload: dict = Body(...)):
    if "local" not in settings.auth_modes:
        raise HTTPException(403, "Đăng nhập bằng mật khẩu đã bị tắt — dùng tài khoản Microsoft")
    import hmac as _h

    if not _h.compare_digest((payload.get("password") or "").encode(), settings.APP_PASSWORD.encode()):
        raise HTTPException(401, "Mật khẩu không đúng")
    user = (payload.get("user") or "soc").strip()[:60] or "soc"
    tok = issue_token(user, role=settings.LOCAL_ROLE, method="local")
    return {"token": tok, "user": user, "ttl_hours": settings.SESSION_TTL_HOURS}


_FLOW_COOKIE = "srb_oidc"


@app.get("/api/auth/oidc/login")
def oidc_login():
    if "oidc" not in settings.auth_modes:
        raise HTTPException(404, "Chưa bật đăng nhập Microsoft (AUTH_MODES)")
    try:
        url, cookie = sso.build_authorize_url()
    except sso.AuthError as exc:
        raise HTTPException(500, str(exc)) from exc
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        _FLOW_COOKIE, cookie, max_age=600, httponly=True, samesite="lax",
        secure=settings.OIDC_REDIRECT_URI.startswith("https://"), path="/api/auth/oidc",
    )
    return resp


@app.get("/api/auth/oidc/callback")
def oidc_callback(
    request: Request,
    code: str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
    db: Session = Depends(get_session),
):
    def fail(msg: str):
        r = RedirectResponse("/#sso_error=" + urllib.parse.quote(msg[:300]), status_code=302)
        r.delete_cookie(_FLOW_COOKIE, path="/api/auth/oidc")
        audit(db, action="login", fw=None, target="entra-oidc", result="error", message=msg,
              actor="?", client_ip=client_ip_of(request))
        db.commit()
        return r

    if error:
        return fail(f"{error}: {error_description}")
    try:
        flow = sso.unpack_flow(request.cookies.get(_FLOW_COOKIE, ""))
        if not state or state != flow["s"]:
            raise sso.AuthError("Sai tham số state — yêu cầu đăng nhập không hợp lệ")
        p = sso.exchange_code(code, flow)
    except sso.AuthError as exc:
        return fail(str(exc))
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"])
    audit(db, action="login", fw=None, target="entra-oidc", result="ok",
          message=f"{p['name']} · vai trò {p['role']}", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    r = RedirectResponse("/#sso=" + urllib.parse.quote(tok), status_code=302)
    r.delete_cookie(_FLOW_COOKIE, path="/api/auth/oidc")
    return r


@app.post("/api/auth/header")
def header_login(request: Request, db: Session = Depends(get_session)):
    if "header" not in settings.auth_modes:
        raise HTTPException(404, "Chưa bật header SSO (AUTH_MODES)")
    peer = request.client.host if request.client else ""
    try:
        p = sso.principal_from_headers(peer, request.headers)
    except sso.AuthError as exc:
        raise HTTPException(401, str(exc)) from exc
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"])
    audit(db, action="login", fw=None, target="entra-header", result="ok",
          message=f"{p['name']} · vai trò {p['role']}", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    return {"token": tok, "user": p["user"], "name": p["name"], "role": p["role"]}


@app.get("/api/config")
def config(p: dict = Depends(principal)):
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "user": p["user"],
        "name": p["name"],
        "role": p["role"],
        "auth_method": p["method"],
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
    p: dict = Depends(admin),
):
    user = p["user"]
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
    p: dict = Depends(admin),
):
    user = p["user"]
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
    p: dict = Depends(admin),
):
    user = p["user"]
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
    p: dict = Depends(operator),
):
    user = p["user"]
    return test_firewall(db, get_fw(db, fw_id), user, client_ip_of(request))


@app.post("/api/firewalls/test-all")
def test_all(
    request: Request,
    payload: dict = Body(default={}),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    user = p["user"]
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

    try:
        changelog.detect_drift(db, fw, g["name"], {n: _host_value(details.get(n, {})) for n in g["hosts"]})
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()

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
    p: dict = Depends(operator),
):
    user = p["user"]
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
            actor=user, client_ip=ip, dry_run=bool(payload.get("dry_run")), who=p,
        )
        for fw in fws
    ]
    return {"entries": entries, "rejected": rejected, "results": results}


@app.post("/api/unblock")
def unblock(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    user = p["user"]
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
            actor=user, client_ip=ip, who=p,
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


# ------------------------------------------------------------- change log
def _parse_day(v: str, end: bool = False) -> dt.datetime | None:
    if not v:
        return None
    try:
        d = dt.date.fromisoformat(v)
    except ValueError as exc:
        raise HTTPException(400, f"Ngày không hợp lệ: {v} (định dạng YYYY-MM-DD)") from exc
    tz = dt.timezone(dt.timedelta(hours=7))  # Asia/Ho_Chi_Minh
    base = dt.datetime.combine(d, dt.time.min, tzinfo=tz)
    return base + dt.timedelta(days=1) if end else base


@app.get("/api/changes")
def changes(
    firewall_id: int | None = Query(default=None),
    group: str = Query(default=""),
    type: str = Query(default=""),
    actor: str = Query(default=""),
    q: str = Query(default=""),
    date_from: str = Query(default="", alias="from"),
    date_to: str = Query(default="", alias="to"),
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=group.strip(), change_type=type, actor=actor.strip(),
        q=q, date_from=_parse_day(date_from), date_to=_parse_day(date_to, end=True),
        limit_batches=limit,
    )
    totals = {
        "batches": len(batches),
        "added": sum(len(b["added"]) for b in batches),
        "removed": sum(len(b["removed"]) for b in batches),
        "drift": sum(1 for b in batches if b["kind"] == "drift"),
    }
    groups = sorted({g for (g,) in db.query(GroupChange.group_name).distinct().all() if g})
    return {"batches": batches, "totals": totals, "groups": groups}


@app.get("/api/changes.csv")
def changes_csv(
    token: str = Query(default=""),
    firewall_id: int | None = Query(default=None),
    group: str = Query(default=""),
    q: str = Query(default=""),
    date_from: str = Query(default="", alias="from"),
    date_to: str = Query(default="", alias="to"),
    db: Session = Depends(get_session),
):
    if not verify_token(token):
        raise HTTPException(401, "Token không hợp lệ")
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=group.strip(), q=q,
        date_from=_parse_day(date_from), date_to=_parse_day(date_to, end=True), limit_batches=5000,
    )
    labels = {"change": "thao tac trong app", "drift": "thay doi ngoai app",
              "baseline": "trang thai ban dau", "create_group": "tao group"}
    buf = io.StringIO()
    buf.write("\ufeff")  # BOM để Excel đọc đúng tiếng Việt
    w = csv.writer(buf)
    w.writerow(["thoi_gian_vn", "lo_thao_tac", "loai", "thay_doi", "ip_cidr", "object", "firewall",
                "group", "so_object_truoc", "so_object_sau", "nguoi_thuc_hien", "ten_hien_thi",
                "phuong_thuc_dang_nhap", "ly_do", "nguon", "ip_client"])
    for b in batches:
        lines = [("+", i) for i in b["added"]] + [("-", i) for i in b["removed"]] or [("", {"value": "", "object": ""})]
        for sign, it in lines:
            w.writerow([changelog.vn_time(b["ts"]), b["batch_id"], labels.get(b["kind"], b["kind"]),
                        {"+": "THEM", "-": "BOT"}.get(sign, ""), it["value"], it["object"],
                        b["firewall_name"], b["group_name"], b["count_before"], b["count_after"],
                        b["actor"], b["actor_name"], b["auth_method"], b["reason"], b["source"],
                        b["client_ip"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=lich_su_thay_doi_object_group.csv"},
    )


@app.get("/api/changes/verify")
def changes_verify(db: Session = Depends(get_session), user: str = Depends(current_user)):
    return changelog.verify_chain(db)


@app.post("/api/changes/sync")
def changes_sync(
    payload: dict = Body(default={}),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    """Đọc lại group trên firewall để phát hiện thay đổi ngoài app."""
    fws = selected_firewalls(db, payload.get("firewall_ids"))
    out = []
    for fw in fws:
        group = (payload.get("group") or fw.default_group).strip()
        try:
            cli = client_for(fw)
            g = cli.get_group(group)
            hosts = list(g["hosts"]) if g else []
            details = {h["name"]: _host_value(h) for h in cli.get_hosts(hosts)} if hosts else {}
            res = changelog.detect_drift(db, fw, group, {h: details.get(h, "") for h in hosts})
            db.commit()
            out.append({"firewall": fw.name, "group": group, "ok": True, "exists": bool(g),
                        "total": len(hosts), **res})
        except (SophosError, SophosAuthError, ValueError) as exc:
            db.rollback()
            out.append({"firewall": fw.name, "group": group, "ok": False, "error": str(exc)})
    return {"results": out}


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
