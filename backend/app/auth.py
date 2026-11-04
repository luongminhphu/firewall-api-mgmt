"""Xác thực: Microsoft Entra ID (OIDC + PKCE) và header-based SSO qua Entra Application Proxy.

Mô hình bảo vệ hai lớp khi truy cập từ Internet:
  1. Entra Application Proxy (pre-authentication = Microsoft Entra ID) + Conditional Access bắt MFA.
     App KHÔNG mở cổng inbound nào ra Internet; Private Network Connector chỉ kết nối outbound 443.
  2. App tự xác minh danh tính (OIDC: kiểm chữ ký id_token qua JWKS; header: chỉ tin IP connector)
     và phân quyền theo App Role (admin / operator / viewer).
"""
from __future__ import annotations

import base64
import re
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
import urllib.parse

import httpx
import jwt
from jwt import PyJWKClient

from .config import settings

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}

_jwks_client: PyJWKClient | None = None


class AuthError(Exception):
    pass


# ----------------------------------------------------------------- helpers
def _csv(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def role_at_least(role: str, needed: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[needed]


def _authority() -> str:
    return f"{settings.OIDC_AUTHORITY.rstrip('/')}/{settings.OIDC_TENANT_ID}/v2.0"


def oidc_ready() -> tuple[bool, str]:
    missing = [k for k in ("OIDC_TENANT_ID", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI")
               if not getattr(settings, k)]
    if missing:
        return False, "Thiếu cấu hình: " + ", ".join(missing)
    return True, ""


# Trạng thái đăng nhập (state, nonce, PKCE verifier) được ký HMAC và đặt vào cookie ngắn hạn,
# nên backend không cần lưu session phía server và chạy được nhiều replica.
def _sign(data: str) -> str:
    return hmac.new(settings.SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()


def pack_flow(flow: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(flow).encode()).decode().rstrip("=")
    return f"{body}.{_sign(body)}"


def unpack_flow(cookie: str) -> dict:
    try:
        body, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            raise ValueError
        flow = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if flow.get("exp", 0) < time.time():
            raise AuthError("Phiên đăng nhập Microsoft đã quá hạn, vui lòng thử lại")
        return flow
    except AuthError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AuthError("Cookie trạng thái đăng nhập không hợp lệ") from exc


# ------------------------------------------------------------------- OIDC
_HINT_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}$")


def build_authorize_url(login_hint: str = "") -> tuple[str, str]:
    """Trả về (URL chuyển hướng tới Entra ID, cookie trạng thái).

    Mặc định KHÔNG gửi `prompt` → Entra dùng lại phiên vừa xác thực ở Application Proxy (SSO, không MFA lần 2).
    `login_hint` (UPN lần đăng nhập trước) giúp Entra chọn đúng tài khoản khi trình duyệt có nhiều tài khoản.
    """
    ok, msg = oidc_ready()
    if not ok:
        raise AuthError(msg)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    hint = (login_hint or "").strip()
    if hint and _HINT_RE.match(hint):
        params["login_hint"] = hint
    prompt = settings.OIDC_PROMPT
    if prompt in ("login", "none", "consent") or (prompt == "select_account" and "login_hint" not in params):
        params["prompt"] = prompt  # Entra không cho dùng login_hint cùng select_account
    if settings.OIDC_DOMAIN_HINT:
        params["domain_hint"] = settings.OIDC_DOMAIN_HINT
    url = f"{_authority()}/oauth2/authorize?" + urllib.parse.urlencode(params)
    cookie = pack_flow({"s": state, "n": nonce, "v": verifier, "exp": int(time.time()) + 600})
    return url, cookie


def _jwks() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(f"{_authority()}/discovery/v2.0/keys", cache_keys=True, lifespan=3600)
    return _jwks_client


def validate_id_token(id_token: str, nonce: str) -> dict:
    try:
        key = _jwks().get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=["RS256"],
            audience=settings.OIDC_CLIENT_ID,
            issuer=_authority(),
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            leeway=120,
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"id_token không hợp lệ: {exc}") from exc
    if claims.get("nonce") != nonce:
        raise AuthError("Sai nonce — có dấu hiệu phát lại token")
    if claims.get("tid") != settings.OIDC_TENANT_ID:
        raise AuthError("Tài khoản không thuộc tenant của công ty")
    return claims


def role_from_claims(claims: dict) -> str | None:
    roles = set(claims.get("roles") or [])
    if settings.ROLE_ADMIN in roles:
        return "admin"
    if settings.ROLE_OPERATOR in roles:
        return "operator"
    if settings.ROLE_VIEWER in roles:
        return "viewer"
    return None


def exchange_code(code: str, flow: dict) -> dict:
    """Đổi authorization code lấy token, xác minh id_token, trả về principal."""
    data = {
        "client_id": settings.OIDC_CLIENT_ID,
        "client_secret": settings.OIDC_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "code_verifier": flow["v"],
        "scope": "openid profile email",
    }
    try:
        resp = httpx.post(f"{_authority()}/oauth2/token", data=data, timeout=15)
    except httpx.HTTPError as exc:
        raise AuthError(f"Không gọi được Entra ID token endpoint: {exc}") from exc
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code != 200 or "id_token" not in body:
        raise AuthError(f"Entra ID từ chối: {body.get('error_description') or resp.text[:300]}")

    claims = validate_id_token(body["id_token"], flow["n"])
    if settings.OIDC_REQUIRE_MFA_CLAIM and "mfa" not in (claims.get("amr") or []):
        raise AuthError("Phiên đăng nhập chưa qua MFA")
    # role có thể None: khi đó app xét danh sách người dùng nội bộ (main.resolve_sso) trước khi từ chối
    role = role_from_claims(claims)
    upn = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or claims["sub"]
    return {"user": upn.lower(), "name": claims.get("name") or upn, "role": role, "method": "entra-oidc"}


# ----------------------------------------------------------------- header
def _trusted_networks() -> list:
    nets = []
    for c in _csv(settings.TRUSTED_PROXY_CIDRS):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def _utf8_header(v: str) -> str:
    """HTTP header được đọc theo latin-1; tên tiếng Việt từ App Proxy thực chất là byte UTF-8."""
    v = (v or "").strip()
    try:
        return v.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v


def principal_from_headers(peer_ip: str, headers) -> dict:
    """Header-based SSO: chỉ chấp nhận khi kết nối TCP đến từ IP connector đã khai báo.

    Không dùng X-Forwarded-For để quyết định tin cậy (client có thể tự đặt header đó).
    """
    nets = _trusted_networks()
    if not nets:
        raise AuthError("Chưa khai báo TRUSTED_PROXY_CIDRS — từ chối header SSO")
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError as exc:
        raise AuthError("Không xác định được IP nguồn") from exc
    if not any(ip in n for n in nets):
        raise AuthError(f"IP nguồn {peer_ip} không phải Private Network Connector tin cậy")
    upn = (headers.get(settings.HEADER_USER) or "").strip().lower()
    if not upn:
        raise AuthError(f"Thiếu header {settings.HEADER_USER} từ Application Proxy")
    name = _utf8_header(headers.get(settings.HEADER_NAME) or "") or upn
    if upn in [u.lower() for u in _csv(settings.HEADER_ADMINS)]:
        role = "admin"
    elif upn in [u.lower() for u in _csv(settings.HEADER_OPERATORS)]:
        role = "operator"
    else:
        role = settings.HEADER_DEFAULT_ROLE if settings.HEADER_DEFAULT_ROLE in ROLE_RANK else "viewer"
    return {"user": upn, "name": name, "role": role, "method": "entra-header"}
