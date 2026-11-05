# Chạy: cd backend && PYTHONPATH=. python3 ../tests/oidc_flow_test.py  (cần: pip install -r requirements.txt httpx)
import os, time, urllib.parse, json
os.environ.update(DATABASE_URL="sqlite:////tmp/oidc_t.db", MASTER_KEY="0123456789abcdef0123456789abcdef",
  SESSION_SECRET="s", AUTH_MODES="oidc", OIDC_TENANT_ID="tid-hsc", OIDC_CLIENT_ID="cid-srb",
  OIDC_CLIENT_SECRET="sec", OIDC_REDIRECT_URI="https://socblock-hsc.msappproxy.net/api/auth/oidc/callback")
if os.path.exists("/tmp/oidc_t.db"): os.remove("/tmp/oidc_t.db")
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from app import auth as sso, main
from app.crypto import verify_principal
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
class K: pass
k=K(); k.key=key.public_key()
class FakeJWKS:
    def get_signing_key_from_jwt(self,t): return k
sso._jwks_client=FakeJWKS()
def mk(nonce, **over):
    now=int(time.time())
    c={"iss":"https://login.microsoftonline.com/tid-hsc/v2.0","aud":"cid-srb","sub":"abc","tid":"tid-hsc","iat":now,"exp":now+600,
       "nonce":nonce,"oid":"oid-phu","preferred_username":"Phu.Luong@hsc.com.vn","name":"Lương Minh Phú","roles":["SRB.Operator"],"amr":["pwd","mfa"]}
    c.update(over); return jwt.encode(c,key,algorithm="RS256")
nxt={}
class R:
    def __init__(s,b): s.status_code=200; s.headers={"content-type":"application/json"}; s._b=b; s.text=json.dumps(b)
    def json(s): return s._b
sso.httpx.post=lambda url,data,timeout: (nxt.__setitem__("data",data), R({"id_token":nxt["tok"](data)}))[1]
c=TestClient(main.app, base_url="https://testserver"); c.__enter__()
def run(tokfn, tamper_state=False):
    r=c.get("/api/auth/oidc/login",follow_redirects=False)
    q=urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)
    nxt["tok"]=lambda d: tokfn(q["nonce"][0])
    st="x" if tamper_state else q["state"][0]
    r2=c.get(f"/api/auth/oidc/callback?code=abc&state={st}",follow_redirects=False)
    return q, r2.headers["location"]
q,loc=run(lambda n: mk(n))
ok=loc.startswith("/#sso=")
p=verify_principal(urllib.parse.unquote(loc.split("=",1)[1])) if ok else None
print("PASS" if ok and p["r"]=="operator" and p["u"]=="phu.luong@hsc.com.vn" else "FAIL","oidc happy path", p and (p["u"],p["r"],p["m"]))
print("PASS" if q["code_challenge_method"]==["S256"] and nxt["data"]["code_verifier"] else "FAIL","PKCE S256 + verifier sent")
for name,fn,expect in [
  ("wrong nonce", lambda n: mk("other"), "nonce"),
  ("wrong tenant", lambda n: mk(n, tid="evil", iss="https://login.microsoftonline.com/tid-hsc/v2.0"), "tenant"),
  ("wrong audience", lambda n: mk(n, aud="other-app"), "id_token"),
  ("expired", lambda n: mk(n, exp=int(time.time())-3600, iat=int(time.time())-7200), "id_token"),
  ("no app role", lambda n: mk(n, roles=[]), "App Role"),
  ("forged signature", lambda n: jwt.encode({"x":1}, rsa.generate_private_key(public_exponent=65537,key_size=2048), algorithm="RS256"), "id_token"),
]:
    _,loc=run(fn); msg=urllib.parse.unquote(loc)
    print("PASS" if "sso_error" in loc and expect in msg else "FAIL", name, "→", msg[13:110])
_,loc=run(lambda n: mk(n), tamper_state=True); print("PASS" if "state" in urllib.parse.unquote(loc) else "FAIL","state mismatch")
from app.config import settings; settings.OIDC_REQUIRE_MFA_CLAIM=True
_,loc=run(lambda n: mk(n, amr=["pwd"])); print("PASS" if "MFA" in urllib.parse.unquote(loc) else "FAIL","require MFA claim")
r=c.post("/api/login",json={"password":"socadmin"}); print("PASS" if r.status_code==403 else "FAIL","local login disabled when AUTH_MODES=oidc")
