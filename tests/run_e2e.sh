#!/usr/bin/env bash
# Kiểm thử end-to-end v1.2: header SSO, RBAC, chặn/bỏ chặn, lịch sử thay đổi, drift, CSV, hash chain.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -f /tmp/mock_t.json /tmp/sb_t.db
MOCK_STATE=/tmp/mock_t.json python3 mock/mock_sophos.py --port 4460 >/tmp/mock_t.log 2>&1 &
MOCK=$!
export DATABASE_URL=sqlite:////tmp/sb_t.db MASTER_KEY=0123456789abcdef0123456789abcdef \
  SESSION_SECRET=testsecret APP_PASSWORD=socadmin AUTH_MODES=local,oidc,header \
  TRUSTED_PROXY_CIDRS=127.0.0.1/32 HEADER_ADMINS=phu.luong@hsc.com.vn FRONTEND_DIR="$ROOT/frontend"
(cd backend && exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8090 >/tmp/app_t.log 2>&1) &
APP=$!
trap 'kill $MOCK $APP 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s localhost:8090/api/health >/dev/null && break; sleep 0.5; done
PYTHONPATH=backend python3 tests/e2e_changelog_test.py
