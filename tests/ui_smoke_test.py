# Chạy: bash tests/run_e2e.sh tests/ui_smoke_test.py
# Smoke test giao diện bằng Playwright (tests/ui_smoke.cjs) trên trình duyệt thật: đăng nhập, mọi tab,
# thêm firewall, chạy thử, chặn, bỏ chặn, lịch sử + chuỗi băm, audit, người dùng, viewer, điện thoại 390px.
# Không có Node/Playwright → in SKIP và thoát 0.
import os
import shutil
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
node = shutil.which("node")
if not node:
    print("SKIP không có Node.js")
    sys.exit(0)
# Token vai trò Rà soát (đại diện team không là người dùng app) — ký bằng cùng SESSION_SECRET của app đang chạy
sys.path.insert(0, os.path.join(os.path.dirname(here), "backend"))
from app.core.security import issue_token  # noqa: E402

env = {**os.environ, "REVIEWER_TOKEN": issue_token("rms.lead@hsc.com.vn", role="reviewer", method="entra-oidc",
                                                    name="Đại diện RMS")}
r = subprocess.run([node, os.path.join(here, "ui_smoke.cjs")], timeout=600, env=env)
sys.exit(r.returncode)
