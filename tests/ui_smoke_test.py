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
r = subprocess.run([node, os.path.join(here, "ui_smoke.cjs")], timeout=600)
sys.exit(r.returncode)
