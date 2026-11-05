# Rà soát Entra ID OIDC (v1.5.2). Chạy: cd backend && PYTHONPATH=. python3 ../tests/entra_review_test.py
import os, time, json, sqlite3, urllib.parse, urllib.request
DB = "/tmp/entra_rv.db"
if os.path.exists(DB): os.remove(DB)
# DB "cũ" (v1.5.1) chưa có cột entra_oid → kiểm tra migration
con = sqlite3.connect(DB); con.execute("""CREATE TABLE app_users (id INTEGER PRIMARY KEY, username VARCHAR(120) UNIQUE,
 display_name VARCHAR(120), auth_type VARCHAR(16), password_hash TEXT, permission VARCHAR(16), is_admin BOOLEAN,
 enabled BOOLEAN, note TEXT, created_by VARCHAR(120), created_at DATETIME, updated_at DATETIME, last_login DATETIME)""")
con.commit(); con.close()
TID = "72f988bf-86f1-41af-91ab-2d7cd011db47"  # tenant công khai, chỉ để so endpoint discovery
os.environ.update(DATABASE_URL=f"sqlite:///{DB}", MASTER_KEY="0123456789abcdef0123456789abcdef", SESSION_SECRET="s",
  AUTH_MODES="oidc,local", OIDC_TENANT_ID=TID, OIDC_CLIENT_ID="cid", OIDC_CLIENT_SECRET="sec", USERS_STRICT="true",
  OIDC_REDIRECT_URI="https://inframon-hscoffice.msappproxy.net/api/auth/oidc/callback", OIDC_REQUIRE_MFA_CLAIM="true")
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from app import auth as sso, main
from app.db import SessionLocal, AppUser
from app.crypto import verify_principal
fails = 0
def chk(n, c, x=""):
    global fails; fails += 0 if c else 1; print("PASS" if c else "FAIL", n, x)

# 1) Endpoint khớp discovery thật của Microsoft
try:
    d = json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/v2.0/.well-known/openid-configuration", timeout=10))
    chk("authorize endpoint = discovery", sso.authorize_endpoint() == d["authorization_endpoint"], sso.authorize_endpoint())
    chk("token endpoint = discovery", sso.token_endpoint() == d["token_endpoint"])
    chk("jwks_uri = discovery", sso.jwks_uri() == d["jwks_uri"])
    chk("issuer = discovery", sso._issuer() == d["issuer"])
    st = urllib.request.urlopen(sso.jwks_uri(), timeout=10).status
    chk("jwks_uri trả 200", st == 200)
    chk("PyJWKClient tải được khóa thật", len(sso._jwks().get_jwk_set().keys) > 0)
    sso._jwks_client = None
except OSError as e:
    print("SKIP live discovery (không có mạng):", e)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
class K: pass
k = K(); k.key = key.public_key()
class FakeJWKS:
    def get_signing_key_from_jwt(self, t): return k
ISS = f"https://login.microsoftonline.com/{TID}/v2.0"
def mk(nonce, **o):
    now = int(time.time())
    c = {"iss": ISS, "aud": "cid", "sub": "s", "tid": TID, "iat": now, "exp": now + 600, "nonce": nonce,
         "oid": "oid-phu", "preferred_username": "Phu.LM@hsc.com.vn", "name": "Lương Minh Phú", "ver": "2.0"}
    c.update(o); [c.pop(x) for x, v in list(c.items()) if v is None]
    return jwt.encode(c, key, algorithm="RS256")
nxt = {}
class R:
    def __init__(s, b): s.status_code = 200; s.headers = {"content-type": "application/json"}; s._b = b; s.text = json.dumps(b)
    def json(s): return s._b
sso.httpx.post = lambda url, data, timeout: (nxt.update(url=url, data=data), R({"id_token": nxt["tok"](data)}))[1]
c = TestClient(main.app, base_url="https://testserver"); c.__enter__()
sso._jwks_client = FakeJWKS()
chk("migration thêm cột entra_oid", "entra_oid" in [r[1] for r in sqlite3.connect(DB).execute("PRAGMA table_info(app_users)")])

def run(fn):
    r = c.get("/api/auth/oidc/login", follow_redirects=False)
    loc = r.headers["location"]; q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    nxt["auth_url"] = loc
    nxt["tok"] = lambda d: fn(q["nonce"])
    r2 = c.get(f"/api/auth/oidc/callback?code=x&state={q['state']}", follow_redirects=False)
    l2 = urllib.parse.unquote(r2.headers["location"])
    p = verify_principal(l2.split("#sso=", 1)[1]) if "#sso=" in l2 else None
    return p, l2

def add(username, auth_type="microsoft", oid=None, admin=True):
    with SessionLocal() as db:
        db.add(AppUser(username=username, auth_type=auth_type, permission="write", is_admin=admin, enabled=True,
                       display_name="", password_hash="", note="", created_by="t", entra_oid=oid)); db.commit()
def oid_of(username):
    with SessionLocal() as db:
        return db.query(AppUser).filter_by(username=username).one().entra_oid

p, l = run(lambda n: mk(n))
chk("URL authorize gửi tới /oauth2/v2.0/authorize", "/oauth2/v2.0/authorize?" in nxt["auth_url"])
chk("đổi code tại /oauth2/v2.0/token", nxt["url"].endswith("/oauth2/v2.0/token"))
chk("redirect_uri gửi đi = callback", nxt["data"]["redirect_uri"].endswith("/api/auth/oidc/callback"))
chk("USERS_STRICT: UPN chưa có trong danh sách → từ chối", p is None and "chưa có trong danh sách" in l)

add("phu.lm@hsc.com.vn")
p, l = run(lambda n: mk(n))  # không có amr (đúng thực tế id_token v2) + REQUIRE_MFA_CLAIM=true
chk("id_token v2 không có amr vẫn đăng nhập được (MFA do Conditional Access)", p and p["u"] == "phu.lm@hsc.com.vn" and p["r"] == "admin", l[:90])
chk("gắn oid ở lần đầu", oid_of("phu.lm@hsc.com.vn") == "oid-phu")
p, l = run(lambda n: mk(n, amr=["pwd"]))
chk("token có amr nhưng thiếu mfa → từ chối", p is None and "MFA" in l)
p, l = run(lambda n: mk(n, amr=["pwd", "mfa"]))
chk("token có amr mfa → OK", p is not None)
p, l = run(lambda n: mk(n, preferred_username="phu.renamed@hsc.com.vn"))
chk("đổi UPN trên Entra: nhận theo oid, giữ username trong app", p and p["u"] == "phu.lm@hsc.com.vn", l[:90])
p, l = run(lambda n: mk(n, oid="oid-nguoi-khac"))
chk("UPN tái sử dụng cho người khác (oid khác) → từ chối", p is None and "tái sử dụng" in l)
p, l = run(lambda n: mk(n, idp="https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/", oid="oid-g"))
chk("tài khoản khách (idp khác iss) → từ chối", p is None and "khách" in l)
add("local.user@hsc.com.vn", auth_type="local")
p, l = run(lambda n: mk(n, preferred_username="local.user@hsc.com.vn", oid="oid-lu"))
chk("tài khoản mật khẩu trùng tên không dùng được cho Microsoft", p is None and "tài khoản mật khẩu" in l)
p, l = run(lambda n: mk(n, preferred_username=None, email="phu.lm@hsc.com.vn", oid="oid-x"))
chk("không fallback sang claim email", p is None and "preferred_username" in l)
p, l = run(lambda n: mk(n, oid=None))
chk("thiếu oid → từ chối", p is None and "oid" in l)
p, l = run(lambda n: mk(n, tid="other"))
chk("tenant khác → từ chối", p is None and "tenant" in l)
p, l = run(lambda n: mk(n, iss="https://login.microsoftonline.com/x/v2.0"))
chk("issuer sai → từ chối", p is None and "id_token" in l)
print("RESULT", "OK" if fails == 0 else f"{fails} FAIL")
