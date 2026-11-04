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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import auth as sso
from . import changelog
from . import users as um
from .config import settings
from .crypto import MasterKeyMissing, decrypt, encrypt, issue_token, verify_principal
from .db import AppUser, AuditLog, Firewall, GroupChange, get_session, init_db
from .ipparse import extract, host_object_name
from .policy import BLOCK_GROUP, GroupPolicyError, enforce_group
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
    # Hardening: chuẩn hóa mọi firewall về group cố định (dữ liệu cũ có thể còn SOC_BLOCKED_IPS)
    from .db import SessionLocal

    with SessionLocal() as db:
        db.query(Firewall).filter(Firewall.default_group != BLOCK_GROUP).update(
            {Firewall.default_group: BLOCK_GROUP}, synchronize_session=False
        )
        db.commit()


# ------------------------------------------------------------------- helpers
def principal(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
    db: Session = Depends(get_session),
) -> dict:
    p = verify_principal(x_auth_token or "")
    if not p:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc session đã hết hạn")
    out = {"user": p["u"], "name": p.get("n") or p["u"], "role": p["r"], "method": p.get("m", "local"),
           "managed": False}
    # Quyền lấy lại từ DB ở MỌI request → khóa / hạ quyền / xóa user có hiệu lực ngay, không chờ token hết hạn.
    if out["method"] != "shared":
        u = um.find(db, out["user"])
        if u:
            if not u.enabled:
                raise HTTPException(401, "Tài khoản đã bị khóa — liên hệ quản trị viên")
            out.update(role=u.role, name=u.display_name or out["name"], managed=True,
                       auth_type=u.auth_type)
        elif p.get("s") == "db":
            raise HTTPException(401, "Tài khoản không còn tồn tại — liên hệ quản trị viên")
        elif settings.USERS_STRICT and out["method"].startswith("entra"):
            raise HTTPException(401, "Tài khoản chưa có trong danh sách người dùng của app")
    return out


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


def locked_group(db: Session, request: Request, requested, actor: str) -> str:
    """Áp chính sách group cố định; vi phạm → 403 và ghi audit 'policy_violation'."""
    try:
        return enforce_group(requested)
    except GroupPolicyError as exc:
        audit(db, action="policy_violation", fw=None, target=str(requested)[:120], result="denied",
              message=str(exc), group=str(requested)[:120], actor=actor, client_ip=client_ip_of(request))
        db.commit()
        raise HTTPException(403, str(exc)) from exc


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
        "oidc_auto": settings.OIDC_AUTO_LOGIN and "oidc" in modes and ready,
    }


@app.post("/api/login")
def login(request: Request, payload: dict = Body(...), db: Session = Depends(get_session)):
    """Đăng nhập bằng mật khẩu: ưu tiên tài khoản riêng trong app; mật khẩu chung APP_PASSWORD là
    đường dự phòng (break-glass) và có thể tắt bằng SHARED_PASSWORD_LOGIN=false."""
    if "local" not in settings.auth_modes:
        raise HTTPException(403, "Đăng nhập bằng mật khẩu đã bị tắt — dùng tài khoản Microsoft")
    import hmac as _h

    raw_user = (payload.get("user") or "soc").strip()[:120] or "soc"
    pw = payload.get("password") or ""
    key = raw_user.lower()
    ip = client_ip_of(request)

    def deny(msg: str, code: int = 401):
        um.login_failed(key)
        audit(db, action="login", fw=None, target="password", result="error", message=msg,
              actor=raw_user, client_ip=ip)
        db.commit()
        raise HTTPException(code, msg)

    wait = um.login_locked(key)
    if wait:
        raise HTTPException(429, f"Sai mật khẩu quá {settings.LOGIN_MAX_FAILS} lần — thử lại sau {wait // 60 + 1} phút")

    u = um.find(db, raw_user)
    if u:
        # Tài khoản đã có trong app → chỉ chấp nhận mật khẩu riêng (không dùng mật khẩu chung để mạo danh)
        if u.auth_type != "local" or not u.password_hash:
            um.burn_time(pw)
            deny("Tài khoản này đăng nhập bằng Microsoft, không dùng mật khẩu")
        if not um.verify_password(pw, u.password_hash):
            deny("Tên đăng nhập hoặc mật khẩu không đúng")
        if not u.enabled:
            deny("Tài khoản đã bị khóa — liên hệ quản trị viên", 403)
        um.login_ok(key)
        um.touch_login(db, u)
        tok = issue_token(u.username, role=u.role, method="local", name=u.display_name, src="db")
        audit(db, action="login", fw=None, target="password", result="ok",
              message=f"{u.display_name or u.username} · vai trò {u.role}", actor=u.username, client_ip=ip)
        db.commit()
        return {"token": tok, "user": u.username, "ttl_hours": settings.SESSION_TTL_HOURS}

    if not settings.SHARED_PASSWORD_LOGIN:
        um.burn_time(pw)
        deny("Tên đăng nhập hoặc mật khẩu không đúng")
    if not _h.compare_digest(pw.encode(), settings.APP_PASSWORD.encode()):
        deny("Tên đăng nhập hoặc mật khẩu không đúng")
    um.login_ok(key)
    tok = issue_token(raw_user[:60], role=settings.LOCAL_ROLE, method="shared")
    audit(db, action="login", fw=None, target="shared-password", result="ok",
          message=f"Mật khẩu chung · vai trò {settings.LOCAL_ROLE}", actor=raw_user[:60], client_ip=ip)
    db.commit()
    return {"token": tok, "user": raw_user[:60], "ttl_hours": settings.SESSION_TTL_HOURS}


def resolve_sso(db: Session, p: dict) -> dict:
    """Ghép danh tính Microsoft với danh sách người dùng của app.
    Có trong danh sách → dùng quyền của app; không có → dùng App Role/header (trừ khi USERS_STRICT)."""
    u = um.find(db, p["user"])
    if u:
        if not u.enabled:
            raise sso.AuthError("Tài khoản đã bị khóa trong SOC Rapid Block — liên hệ quản trị viên")
        um.touch_login(db, u)
        return {**p, "role": u.role, "name": u.display_name or p["name"], "src": "db"}
    if settings.USERS_STRICT:
        raise sso.AuthError("Tài khoản chưa có trong danh sách người dùng của SOC Rapid Block")
    if not p.get("role"):
        raise sso.AuthError(
            "Tài khoản chưa được cấp quyền: chưa có trong danh sách người dùng của app và chưa được gán App Role "
            f"({settings.ROLE_ADMIN} / {settings.ROLE_OPERATOR} / {settings.ROLE_VIEWER})"
        )
    return {**p, "src": ""}


_FLOW_COOKIE = "srb_oidc"


@app.get("/api/auth/oidc/login")
def oidc_login(hint: str = Query(default="")):
    if "oidc" not in settings.auth_modes:
        raise HTTPException(404, "Chưa bật đăng nhập Microsoft (AUTH_MODES)")
    try:
        url, cookie = sso.build_authorize_url(hint)
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
        p = resolve_sso(db, sso.exchange_code(code, flow))
    except sso.AuthError as exc:
        return fail(str(exc))
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"], src=p["src"])
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
        p = resolve_sso(db, sso.principal_from_headers(peer, request.headers))
    except sso.AuthError as exc:
        raise HTTPException(401, str(exc)) from exc
    tok = issue_token(p["user"], role=p["role"], method=p["method"], name=p["name"], src=p["src"])
    audit(db, action="login", fw=None, target="entra-header", result="ok",
          message=f"{p['name']} · vai trò {p['role']}", actor=p["user"], client_ip=client_ip_of(request))
    db.commit()
    return {"token": tok, "user": p["user"], "name": p["name"], "role": p["role"]}


@app.get("/api/config")
def config(p: dict = Depends(principal)):
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "block_group": BLOCK_GROUP,
        "user": p["user"],
        "name": p["name"],
        "role": p["role"],
        "auth_method": p["method"],
        "managed_user": p.get("managed", False),
        "can_change_password": p.get("managed", False) and p.get("auth_type") == "local",
        "users_strict": settings.USERS_STRICT,
        "shared_password_login": settings.SHARED_PASSWORD_LOGIN,
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
        default_group=locked_group(db, request, payload.get("default_group"), user),
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
    if payload.get("default_group") is not None:
        locked_group(db, request, payload.get("default_group"), user)
    fw.default_group = BLOCK_GROUP
    for field in ("name", "site", "host", "username", "note"):
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
        g = client_for(fw).get_group(BLOCK_GROUP)  # chỉ đọc group cố định, không liệt kê group khác
    except (SophosError, SophosAuthError, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {
        "firewall": fw.name,
        "default_group": BLOCK_GROUP,
        "locked": True,
        "groups": [{**g, "count": len(g["hosts"])}] if g else [],
    }


@app.get("/api/firewalls/{fw_id}/group-members")
def fw_group_members(
    fw_id: int,
    request: Request,
    group: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_session),
    user: str = Depends(current_user),
):
    group = locked_group(db, request, group, user)
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
    locked_group(db, request, payload.get("group"), user)
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
    locked_group(db, request, payload.get("group"), user)
    targets = [str(t).strip() for t in (payload.get("targets") or []) if str(t).strip()]
    if not targets:
        raise HTTPException(400, "Chưa chọn IP/object nào để bỏ chặn")
    fws = selected_firewalls(db, payload.get("firewall_ids"))
    ip = client_ip_of(request)
    results = [
        unblock_on_firewall(
            db, fw, targets,
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
    principal(token, db)  # cùng kiểm tra như API: token hợp lệ, user chưa bị khóa/xóa
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
    request: Request,
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
    group = locked_group(db, request, group, user)
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=group, change_type=type, actor=actor.strip(),
        q=q, date_from=_parse_day(date_from), date_to=_parse_day(date_to, end=True),
        limit_batches=limit,
    )
    totals = {
        "batches": len(batches),
        "added": sum(len(b["added"]) for b in batches),
        "removed": sum(len(b["removed"]) for b in batches),
        "drift": sum(1 for b in batches if b["kind"] == "drift"),
    }
    return {"batches": batches, "totals": totals, "groups": [BLOCK_GROUP], "locked_group": BLOCK_GROUP}


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
    principal(token, db)  # cùng kiểm tra như API: token hợp lệ, user chưa bị khóa/xóa
    if group.strip() not in ("", BLOCK_GROUP):
        raise HTTPException(403, f"Chỉ xuất lịch sử của IP Host Group '{BLOCK_GROUP}'")
    batches = changelog.query_batches(
        db, firewall_id=firewall_id, group=BLOCK_GROUP, q=q,
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
    request: Request,
    payload: dict = Body(default={}),
    db: Session = Depends(get_session),
    p: dict = Depends(operator),
):
    """Đọc lại group cố định trên firewall để phát hiện thay đổi ngoài app."""
    group = locked_group(db, request, payload.get("group"), p["user"])
    fws = selected_firewalls(db, payload.get("firewall_ids"))
    out = []
    for fw in fws:
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


# --------------------------------------------------------------------- users
def _get_user(db: Session, uid: int) -> AppUser:
    u = db.get(AppUser, uid)
    if not u:
        raise HTTPException(404, f"Không tìm thấy người dùng id={uid}")
    return u


def _user_audit(db: Session, request: Request, actor: str, target: str, msg: str, result: str = "ok"):
    audit(db, action="user_mgmt", fw=None, target=target[:120], result=result, message=msg[:500],
          actor=actor, client_ip=client_ip_of(request))


@app.get("/api/users")
def list_users(db: Session = Depends(get_session), p: dict = Depends(admin)):
    rows = db.scalars(select(AppUser).order_by(AppUser.username)).all()
    return {"users": [u.to_dict() for u in rows], "users_strict": settings.USERS_STRICT,
            "shared_password_login": settings.SHARED_PASSWORD_LOGIN,
            "password_min_length": settings.PASSWORD_MIN_LENGTH}


@app.post("/api/users")
def create_user(request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    try:
        username = um.norm_username(payload.get("username") or "")
        if um.find(db, username):
            raise um.UserError(f"Tên đăng nhập '{username}' đã tồn tại")
        u = AppUser(username=username, created_by=p["user"])
        um.apply_fields(u, payload, creating=True)
        if u.auth_type == "local":
            pw = payload.get("password") or ""
            um.check_password_strength(pw, username)
            u.password_hash = um.hash_password(pw)
    except um.UserError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.add(u)
    db.commit()
    _user_audit(db, request, p["user"], username,
                f"Tạo người dùng · {u.auth_type} · quyền {u.permission}{' · quản trị' if u.is_admin else ''}"
                f"{'' if u.enabled else ' · đang khóa'}")
    db.commit()
    return u.to_dict()


@app.put("/api/users/{uid}")
def update_user(uid: int, request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                p: dict = Depends(admin)):
    u = _get_user(db, uid)
    before = u.to_dict()
    is_self = u.username == p["user"]
    try:
        old_type = u.auth_type
        um.apply_fields(u, {k: v for k, v in payload.items() if k != "username"}, creating=False)
        if is_self and (not u.is_admin or not u.enabled):
            raise um.UserError("Không thể tự bỏ quyền quản trị hoặc tự khóa tài khoản của chính mình")
        if before["is_admin"] and before["enabled"] and not (u.is_admin and u.enabled) \
                and um.count_admins(db, exclude_id=u.id) == 0:
            raise um.UserError("Phải còn ít nhất một quản trị viên đang hoạt động")
        pw = payload.get("password") or ""
        if u.auth_type == "local" and (pw or (old_type != "local" and not u.password_hash)):
            if not pw:
                raise um.UserError("Chuyển sang tài khoản nội bộ cần đặt mật khẩu")
            um.check_password_strength(pw, u.username)
            u.password_hash = um.hash_password(pw)
    except um.UserError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    u.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    after = u.to_dict()
    changes = [f"{k}: {before[k]} → {after[k]}" for k in ("display_name", "auth_type", "permission", "is_admin",
                                                         "enabled", "note") if before[k] != after[k]]
    if payload.get("password"):
        changes.append("đặt lại mật khẩu")
    _user_audit(db, request, p["user"], u.username, "Sửa người dùng · " + ("; ".join(changes) or "không đổi"))
    db.commit()
    return after


@app.delete("/api/users/{uid}")
def delete_user(uid: int, request: Request, db: Session = Depends(get_session), p: dict = Depends(admin)):
    u = _get_user(db, uid)
    if u.username == p["user"]:
        raise HTTPException(400, "Không thể tự xóa tài khoản của chính mình")
    if u.is_admin and u.enabled and um.count_admins(db, exclude_id=u.id) == 0:
        raise HTTPException(400, "Phải còn ít nhất một quản trị viên đang hoạt động")
    name = u.username
    db.delete(u)
    db.commit()
    _user_audit(db, request, p["user"], name, "Xóa người dùng — các phiên đăng nhập của tài khoản này bị vô hiệu ngay")
    db.commit()
    return {"deleted": name}


@app.post("/api/me/password")
def change_my_password(request: Request, payload: dict = Body(...), db: Session = Depends(get_session),
                       p: dict = Depends(principal)):
    u = um.find(db, p["user"])
    if not u or u.auth_type != "local":
        raise HTTPException(400, "Chỉ tài khoản nội bộ của app mới đổi được mật khẩu tại đây")
    if not um.verify_password(payload.get("current_password") or "", u.password_hash):
        _user_audit(db, request, p["user"], u.username, "Đổi mật khẩu thất bại — sai mật khẩu hiện tại", "error")
        db.commit()
        raise HTTPException(400, "Mật khẩu hiện tại không đúng")
    try:
        um.check_password_strength(payload.get("new_password") or "", u.username)
    except um.UserError as exc:
        raise HTTPException(400, str(exc)) from exc
    u.password_hash = um.hash_password(payload["new_password"])
    u.updated_at = dt.datetime.now(dt.timezone.utc)
    _user_audit(db, request, p["user"], u.username, "Tự đổi mật khẩu")
    db.commit()
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


# ------------------------------------------------------------ static frontend
_FRONTEND = os.getenv(
    "FRONTEND_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend"),
)
_NO_CACHE = "no-cache, must-revalidate"


@app.middleware("http")
async def _static_no_cache(request: Request, call_next):
    """Bắt trình duyệt / reverse proxy luôn kiểm tra lại file tĩnh (ETag → 304),
    tránh tình trạng index.html mới chạy với app.js cũ sau khi nâng cấp."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/") and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = _NO_CACHE
    return response


def _render_index() -> HTMLResponse:
    with open(os.path.join(_FRONTEND, "index.html"), encoding="utf-8") as f:
        html = f.read()
    v = settings.APP_VERSION
    html = html.replace('src="app.js"', f'src="app.js?v={v}"').replace(
        'href="styles.css"', f'href="styles.css?v={v}"'
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


if os.path.isdir(_FRONTEND):

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    def _index():
        return _render_index()

    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="frontend")
