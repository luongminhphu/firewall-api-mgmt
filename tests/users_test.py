# Chạy: bash tests/run_e2e.sh tests/users_test.py
# v1.5: quản lý người dùng — thêm / sửa / xóa, quyền Write / Readonly, quản trị viên, hiệu lực tức thì.
import httpx

B = "http://127.0.0.1:8090"
c = httpx.Client(base_url=B, timeout=30)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")


def login(user, pw):
    return c.post("/api/login", json={"user": user, "password": pw})


def H(tok):
    return {"X-Auth-Token": tok}


# Admin bootstrap: header SSO (HEADER_ADMINS) — giống người quản trị đăng nhập Microsoft
adm = c.post("/api/auth/header", headers={"X-SRB-UPN": "phu.luong@hsc.com.vn"}).json()["token"]
A = H(adm)
chk("admin lists users (empty)", c.get("/api/users", headers=A).json()["users"] == [])

# ---- tạo
r = c.post("/api/users", json={"username": "SOC.Write", "display_name": "SOC Ca dem", "auth_type": "local",
                               "permission": "write", "password": "Tet2027Soc!"}, headers=A)
chk("create write user", r.status_code == 200 and r.json()["username"] == "soc.write"
    and r.json()["role"] == "operator", r.text)
w_id = r.json()["id"]
chk("password hash not exposed", "password_hash" not in r.json() and r.json()["has_password"])
r = c.post("/api/users", json={"username": "soc.view", "permission": "readonly", "password": "Readonly2027x"},
           headers=A)
chk("create readonly user", r.status_code == 200 and r.json()["role"] == "viewer", r.text)
v_id = r.json()["id"]
chk("duplicate username rejected", c.post("/api/users", json={"username": "soc.view", "password": "Abcdef12345"},
                                          headers=A).status_code == 400)
chk("weak password rejected", c.post("/api/users", json={"username": "weak1", "password": "abc"},
                                     headers=A).status_code == 400)
chk("password w/o digit rejected", c.post("/api/users", json={"username": "weak2", "password": "abcdefghijkl"},
                                          headers=A).status_code == 400)
chk("password containing username rejected",
    c.post("/api/users", json={"username": "minh", "password": "minh12345678"}, headers=A).status_code == 400)
chk("bad username rejected", c.post("/api/users", json={"username": "a b<script>", "password": "Abcdef12345"},
                                    headers=A).status_code == 400)
chk("bad permission rejected", c.post("/api/users", json={"username": "x1", "permission": "root",
                                                          "password": "Abcdef12345"}, headers=A).status_code == 400)
r = c.post("/api/users", json={"username": "ms.user@hsc.com.vn", "auth_type": "microsoft", "permission": "readonly",
                               "password": "Ignored12345"}, headers=A)
chk("create microsoft user (no password stored)", r.status_code == 200 and not r.json()["has_password"], r.text)
ms_id = r.json()["id"]

# ---- đăng nhập & quyền
r = login("soc.write", "Tet2027Soc!")
chk("write user login", r.status_code == 200, r.text)
wt = r.json()["token"]
cfg = c.get("/api/config", headers=H(wt)).json()
chk("config role operator + can change password", cfg["role"] == "operator" and cfg["can_change_password"])
chk("write user can block (dry-run, no fw -> 400 not 403)",
    c.post("/api/block", json={"values": ["45.1.1.1"], "dry_run": True}, headers=H(wt)).status_code == 400)
chk("write user cannot manage users", c.get("/api/users", headers=H(wt)).status_code == 403)
chk("write user cannot add firewall", c.post("/api/firewalls", json={"name": "x"}, headers=H(wt)).status_code == 403)

vt = login("soc.view", "Readonly2027x").json()["token"]
chk("readonly role viewer", c.get("/api/config", headers=H(vt)).json()["role"] == "viewer")
chk("readonly cannot block", c.post("/api/block", json={"values": ["45.1.1.1"]}, headers=H(vt)).status_code == 403)
chk("readonly cannot unblock", c.post("/api/unblock", json={"targets": ["45.1.1.1"]}, headers=H(vt)).status_code == 403)
chk("readonly can read audit", c.get("/api/audit", headers=H(vt)).status_code == 200)

chk("wrong password -> 401", login("soc.write", "sai-mat-khau1").status_code == 401)
chk("shared password cannot impersonate managed user", login("soc.write", "socadmin").status_code == 401)
chk("microsoft user cannot use password", login("ms.user@hsc.com.vn", "Ignored12345").status_code == 401)
r = login("break.glass", "socadmin")
chk("shared password still works for non-managed name (break-glass)", r.status_code == 200, r.text)
chk("break-glass token role = LOCAL_ROLE", c.get("/api/config", headers=H(r.json()["token"])).json()["role"] == "admin")

# ---- sửa: hiệu lực tức thì với token cũ
r = c.put(f"/api/users/{w_id}", json={"permission": "readonly"}, headers=A)
chk("downgrade write -> readonly", r.status_code == 200 and r.json()["role"] == "viewer", r.text)
chk("old token immediately readonly", c.post("/api/block", json={"values": ["45.1.1.1"]}, headers=H(wt)).status_code == 403)
c.put(f"/api/users/{w_id}", json={"enabled": False}, headers=A)
chk("disabled user's token rejected", c.get("/api/config", headers=H(wt)).status_code == 401)
chk("disabled user cannot login", login("soc.write", "Tet2027Soc!").status_code in (401, 403))
c.put(f"/api/users/{w_id}", json={"enabled": True, "permission": "write"}, headers=A)
wt = login("soc.write", "Tet2027Soc!").json()["token"]
chk("re-enabled + write again", c.get("/api/config", headers=H(wt)).json()["role"] == "operator")
r = c.put(f"/api/users/{w_id}", json={"password": "NewPass2027z"}, headers=A)
chk("admin reset password", r.status_code == 200 and login("soc.write", "NewPass2027z").status_code == 200, r.text)
chk("old password no longer valid", login("soc.write", "Tet2027Soc!").status_code == 401)
r = c.put(f"/api/users/{w_id}", json={"is_admin": True, "permission": "readonly"}, headers=A)
chk("admin flag forces write", r.json()["is_admin"] and r.json()["permission"] == "write" and r.json()["role"] == "admin")

# ---- tự đổi mật khẩu
vt = login("soc.view", "Readonly2027x").json()["token"]
chk("change own pw: wrong current rejected",
    c.post("/api/me/password", json={"current_password": "x", "new_password": "Another2027a"}, headers=H(vt)).status_code == 400)
chk("change own pw ok",
    c.post("/api/me/password", json={"current_password": "Readonly2027x", "new_password": "Another2027a"},
           headers=H(vt)).status_code == 200)
chk("login with new own pw", login("soc.view", "Another2027a").status_code == 200)

# ---- tự bảo vệ quản trị viên
wt = login("soc.write", "NewPass2027z").json()["token"]  # giờ là admin
chk("cannot self-demote", c.put(f"/api/users/{w_id}", json={"is_admin": False}, headers=H(wt)).status_code == 400)
chk("cannot self-disable", c.put(f"/api/users/{w_id}", json={"enabled": False}, headers=H(wt)).status_code == 400)
chk("cannot self-delete", c.delete(f"/api/users/{w_id}", headers=H(wt)).status_code == 400)
chk("cannot remove last admin (by other admin)",
    c.put(f"/api/users/{w_id}", json={"is_admin": False}, headers=A).status_code == 400)

# ---- SSO: người có trong danh sách -> quyền theo app
r = c.post("/api/auth/header", headers={"X-SRB-UPN": "ms.user@hsc.com.vn"}).json()
chk("SSO user in list -> app permission (readonly)", r["role"] == "viewer", r)
c.put(f"/api/users/{ms_id}", json={"permission": "write"}, headers=A)
chk("SSO token reflects new permission", c.get("/api/config", headers=H(r["token"])).json()["role"] == "operator")

# ---- xóa
chk("delete readonly user", c.delete(f"/api/users/{v_id}", headers=A).status_code == 200)
chk("deleted user's token rejected", c.get("/api/config", headers=H(vt)).status_code == 401)
chk("deleted user cannot login with own pw", login("soc.view", "Another2027a").status_code == 401)

# ---- audit
logs = c.get("/api/audit", params={"action": "user_mgmt"}, headers=A).json()
items = logs["rows"]
msgs = " | ".join(str(x) for x in items)
chk("audit has user_mgmt entries", len(items) >= 5 and "Xóa người dùng" in msgs and "Tạo người dùng" in msgs,
    msgs[:300])

# ---- chống dò mật khẩu
for _ in range(5):
    login("ms.brute", "wrong-000")
chk("lockout after 5 fails -> 429", login("ms.brute", "socadmin").status_code == 429)

print("RESULT", "OK" if not fails else f"{fails} FAIL")
