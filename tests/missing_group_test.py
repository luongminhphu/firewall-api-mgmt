# Chạy: cd backend && PYTHONPATH=. DATABASE_URL=sqlite:////tmp/mg.db MASTER_KEY=0123456789abcdef0123456789abcdef python3 ../tests/missing_group_test.py
# Firewall chưa có 'SCANPORT GROUP' → app phải báo lỗi rõ ràng và KHÔNG tự tạo group / IP Host.
import os
from app import service
from app.db import Firewall, SessionLocal, init_db
from app.crypto import encrypt

calls = []


class FakeCli:
    def get_group(self, name):
        calls.append(("get_group", name)); return None
    def __getattr__(self, n):
        def f(*a, **k): calls.append((n, a)); raise AssertionError(f"không được gọi {n}")
        return f


init_db()
service.client_for = lambda fw: FakeCli()
with SessionLocal() as db:
    fw = Firewall(name="FW-NEW", host="10.0.0.1", port=4444, username="api", password_enc=encrypt("x"))
    db.add(fw); db.commit()
    r = service.block_on_firewall(db, fw, [{"value": "1.2.3.4", "kind": "IP"}], reason="t")
    ok = (not r["ok"]) and "chưa tồn tại" in r["error"] and [c[0] for c in calls] == ["get_group"]
    print(("PASS" if ok else "FAIL"), "missing SCANPORT GROUP -> error, no create:", r["error"][:110])
