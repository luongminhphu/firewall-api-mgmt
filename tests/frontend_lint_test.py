# Chạy: python3 tests/frontend_lint_test.py   (hoặc qua run_e2e.sh)
# ESLint frontend/js với tests/eslint.config.mjs: no-undef, no-unused-vars, no-redeclare.
# Không có Node/ESLint → SKIP.
import os
import shutil
import subprocess
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
node = shutil.which("node")
cands = [os.environ.get("ESLINT_JS", ""), "/opt/node22/lib/node_modules/eslint/bin/eslint.js",
         os.path.join(root, "node_modules/eslint/bin/eslint.js")]
eslint = next((c for c in cands if c and os.path.exists(c)), None)
if not node or not eslint:
    print("SKIP không có Node.js/ESLint")
    sys.exit(0)
r = subprocess.run([node, eslint, "--no-config-lookup", "-c", os.path.join(root, "tests/eslint.config.mjs"),
                    os.path.join(root, "frontend/js")], capture_output=True, text=True)
print(r.stdout.strip() or "")
print(("PASS" if r.returncode == 0 else "FAIL") + " ESLint frontend/js")
sys.exit(r.returncode)
