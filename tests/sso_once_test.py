# Chạy: cd backend && PYTHONPATH=. python3 ../tests/sso_once_test.py
# v1.5.1: SSO một lần — không ép chọn tài khoản, login_hint đúng tài khoản, tự đăng nhập, user list áp quyền.
import os, sys, urllib.parse
os.environ.update(DATABASE_URL="sqlite:////tmp/sso1.db", MASTER_KEY="0123456789abcdef0123456789abcdef",
  SESSION_SECRET="s", AUTH_MODES="oidc,local", OIDC_TENANT_ID="tid-hsc", OIDC_CLIENT_ID="cid-srb",
  OIDC_CLIENT_SECRET="sec", OIDC_REDIRECT_URI="https://socblock-hsc.msappproxy.net/api/auth/oidc/callback",
  OIDC_DOMAIN_HINT="hsc.com.vn", APP_PASSWORD="x")
if os.path.exists("/tmp/sso1.db"): os.remove("/tmp/sso1.db")
from fastapi.testclient import TestClient
from app import auth as sso, main
from app.config import settings
fails = 0
def chk(n, cond, extra=""):
    global fails; fails += 0 if cond else 1; print(("PASS " if cond else "FAIL ") + n, "" if cond else extra)
def q(url): return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
c = TestClient(main.app, base_url="https://testserver"); c.__enter__()

m = c.get("/api/auth/modes").json()
chk("modes: oidc_auto on by default", m["oidc_auto"] is True and m["local"] and m["oidc"], m)
p = q(c.get("/api/auth/oidc/login", follow_redirects=False).headers["location"])
chk("default: no prompt (reuse App Proxy session)", "prompt" not in p, p)
chk("domain_hint sent", p.get("domain_hint") == "hsc.com.vn", p)
p = q(c.get("/api/auth/oidc/login?hint=phu.luong@hsc.com.vn", follow_redirects=False).headers["location"])
chk("login_hint = last UPN", p.get("login_hint") == "phu.luong@hsc.com.vn", p)
p = q(c.get("/api/auth/oidc/login?hint=evil%22%3E%3Cscript%3E", follow_redirects=False).headers["location"])
chk("invalid hint ignored", "login_hint" not in p, p)
settings.OIDC_PROMPT = "select_account"
p = q(c.get("/api/auth/oidc/login", follow_redirects=False).headers["location"])
chk("OIDC_PROMPT=select_account honored w/o hint", p.get("prompt") == "select_account", p)
p = q(c.get("/api/auth/oidc/login?hint=a@hsc.com.vn", follow_redirects=False).headers["location"])
chk("select_account dropped when login_hint (Entra rule)", "prompt" not in p and p.get("login_hint"), p)
settings.OIDC_PROMPT = ""
settings.OIDC_AUTO_LOGIN = False
chk("OIDC_AUTO_LOGIN=false -> oidc_auto off", c.get("/api/auth/modes").json()["oidc_auto"] is False)
settings.OIDC_AUTO_LOGIN = True

# Người có trong danh sách: quyền theo app, không cần App Role; không có & không App Role -> từ chối rõ ràng
from app.db import SessionLocal, AppUser
with SessionLocal() as db:
    db.add(AppUser(username="soc.a@hsc.com.vn", auth_type="microsoft", permission="write")); db.commit()
    p1 = main.resolve_sso(db, {"user": "soc.a@hsc.com.vn", "name": "A", "role": None, "method": "entra-oidc"})
    chk("listed user w/o App Role -> write (operator)", p1["role"] == "operator" and p1["src"] == "db", p1)
    try:
        main.resolve_sso(db, {"user": "x@hsc.com.vn", "name": "X", "role": None, "method": "entra-oidc"}); chk("unlisted no role rejected", False)
    except sso.AuthError as e:
        chk("unlisted & no App Role -> rejected with VN message", "chưa được cấp quyền" in str(e), str(e))
    settings.USERS_STRICT = True
    try:
        main.resolve_sso(db, {"user": "y@hsc.com.vn", "name": "Y", "role": "admin", "method": "entra-oidc"}); chk("strict rejects", False)
    except sso.AuthError:
        chk("USERS_STRICT: App Role alone not enough", True)
    settings.USERS_STRICT = False

html = c.get("/").text
chk("login page has auto-SSO status + emergency toggle", 'id="sso-auto"' in html and 'id="local-toggle"' in html)
print("RESULT", "OK" if not fails else f"{fails} FAIL")
