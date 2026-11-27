#!/usr/bin/env bash
# Chạy toàn bộ tests/*_test.py. Biến môi trường riêng lấy từ dòng "# Chạy: VAR=x ... bash" đầu mỗi file;
# chờ app/mock của bộ trước nhả cổng (8090, 4460, 4470) để không báo FAIL giả.
cd "$(dirname "$0")/.."
fails=0
for t in tests/*_test.py; do
  for i in $(seq 1 60); do
    busy=0; for p in 8090 4460 4470; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && busy=1; done
    [ $busy = 0 ] && break; sleep 0.25
  done
  envs=$(sed -n '1,3s/^# Chạy: \(\([A-Z_]*=[^ ]* \)*\)bash.*/\1/p' "$t" | head -1)
  if env $envs bash tests/run_e2e.sh "$t" >/tmp/run_all_last.log 2>&1; then echo "ok   $t"
  else echo "FAIL $t"; tail -5 /tmp/run_all_last.log; fails=$((fails+1)); fi
done
echo "TỔNG: $fails bộ lỗi"; exit $((fails > 0))
