#!/usr/bin/env bash
# Kiểm thử end-to-end v1.2: header SSO, RBAC, chặn/bỏ chặn, lịch sử thay đổi, drift, CSV, hash chain.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -f /tmp/mock_t.json /tmp/sb_t.db
MOCK_STATE=/tmp/mock_t.json python3 mock/mock_sophos.py --port 4460 >/tmp/mock_t.log 2>&1 &
MOCK=$!
python3 mock/mock_graph.py --port 4470 >/tmp/mock_graph.log 2>&1 &
GRAPH=$!
# E2E_DATABASE_URL=postgresql+psycopg2://... để chạy trên PostgreSQL (schema public được làm mới mỗi lần)
if [ -n "${E2E_DATABASE_URL:-}" ]; then
  python3 -c "import sqlalchemy as sa; e=sa.create_engine('$E2E_DATABASE_URL')
with e.begin() as c: c.execute(sa.text('DROP SCHEMA public CASCADE; CREATE SCHEMA public'))"
fi
export DATABASE_URL=${E2E_DATABASE_URL:-sqlite:////tmp/sb_t.db} MASTER_KEY=0123456789abcdef0123456789abcdef \
  SESSION_SECRET=testsecret APP_PASSWORD=socadmin AUTH_MODES=local,oidc,header \
  TRUSTED_PROXY_CIDRS=127.0.0.1/32 HEADER_ADMINS=phu.luong@hsc.com.vn FRONTEND_DIR="$ROOT/frontend" \
  GRAPH_BASE_URL=http://127.0.0.1:4470/v1.0 GRAPH_LOGIN_URL=http://127.0.0.1:4470 \
  AUTOBLOCK_POLL_SECONDS=${AUTOBLOCK_POLL_SECONDS:-0}
(cd backend && exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8090 >/tmp/app_t.log 2>&1) &
APP=$!
trap 'kill $MOCK $GRAPH $APP 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s localhost:8090/api/health >/dev/null && break; sleep 0.5; done
for i in $(seq 1 30); do curl -s localhost:4470/_calls >/dev/null && break; sleep 0.5; done
PYTHONPATH=backend python3 "${1:-tests/e2e_changelog_test.py}"
