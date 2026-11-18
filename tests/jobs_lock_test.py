# Chạy: bash tests/run_e2e.sh tests/jobs_lock_test.py
#       E2E_DATABASE_URL=postgresql+psycopg2://... bash tests/run_e2e.sh tests/jobs_lock_test.py  (kiểm liên pod)
# core.jobs.lock: khóa giữa luồng (mọi DB) và giữa tiến trình/pod (PostgreSQL pg_advisory_lock).
# core.jobs.every: chạy ngay, lặp lại, mỗi vòng chỉ một tiến trình chạy.
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, "backend")
from app.core import jobs  # noqa: E402
from app.core.db import engine  # noqa: E402

PG = engine.dialect.name == "postgresql"
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


# --- giữa các luồng
with jobs.lock("t:a") as got:
    chk("giữ được khóa", got is True)
    res = {}
    t = threading.Thread(target=lambda: res.setdefault("v", jobs.lock("t:a", blocking=False).__enter__()))
    t.start(); t.join()
    chk("luồng khác không lấy được khóa (non-blocking)", res["v"] is False)
with jobs.lock("t:a", blocking=False) as got:
    chk("nhả xong lấy lại được", got is True)
with jobs.lock("t:b", blocking=False) as got:
    chk("khóa khác tên độc lập", got is True)

order = []


def worker(i):
    with jobs.lock("t:serial"):
        order.append(("in", i)); time.sleep(0.05); order.append(("out", i))


ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
chk("blocking: tuần tự, không chồng lấn", all(order[k][0] == "in" and order[k + 1] == ("out", order[k][1])
                                              for k in range(0, len(order), 2)))

# --- giữa các tiến trình (mô phỏng 2 pod) — chỉ PostgreSQL
if PG:
    holder = subprocess.Popen([sys.executable, "-c", (
        "import sys,time; sys.path.insert(0,'backend'); from app.core import jobs\n"
        "with jobs.lock('t:pod'):\n    print('held', flush=True); time.sleep(3)\n")],
        stdout=subprocess.PIPE, text=True, env=os.environ)
    chk("pod A giữ khóa", holder.stdout.readline().strip() == "held")
    with jobs.lock("t:pod", blocking=False) as got:
        chk("pod B không lấy được khóa khi pod A đang giữ", got is False)
    t0 = time.time()
    with jobs.lock("t:pod") as got:
        chk("pod B chờ (blocking) tới khi pod A nhả", got and time.time() - t0 > 1, f"{time.time() - t0:.1f}s")
    holder.wait()
    # pod chết giữa chừng → PostgreSQL tự nhả khóa phiên
    dead = subprocess.Popen([sys.executable, "-c", (
        "import sys,os,time; sys.path.insert(0,'backend'); from app.core import jobs\n"
        "l=jobs.lock('t:dead'); l.__enter__(); print('held', flush=True); time.sleep(30)\n")],
        stdout=subprocess.PIPE, text=True, env=os.environ)
    dead.stdout.readline(); dead.kill(); dead.wait(); time.sleep(0.5)
    with jobs.lock("t:dead", blocking=False) as got:
        chk("pod chết → khóa tự nhả", got is True)
else:
    print("SKIP liên tiến trình (không phải PostgreSQL)")

# --- every(): chạy ngay + lặp lại
hits = []
stop = threading.Event()
jobs.every("t-every", 0.2, lambda: hits.append(time.time()), stop=stop)
time.sleep(0.7); stop.set()
chk("every: chạy ngay và lặp lại", len(hits) >= 3, len(hits))
# một vòng lỗi không làm chết bộ lập lịch
n = {"c": 0}


def boom():
    n["c"] += 1
    raise RuntimeError("x")


import logging  # noqa: E402
logging.getLogger("jobs").setLevel(logging.CRITICAL)  # traceback có chủ đích của boom()
stop2 = threading.Event()
jobs.every("t-boom", 0.1, boom, stop=stop2)
time.sleep(0.45); stop2.set()
chk("every: vòng lỗi không dừng bộ lập lịch", n["c"] >= 3, n["c"])
if PG:  # đang có tiến trình khác giữ khóa vòng lặp → bỏ qua vòng đó
    other = subprocess.Popen([sys.executable, "-c", (
        "import sys,time; sys.path.insert(0,'backend'); from app.core import jobs\n"
        "with jobs.lock('every:t-one'):\n    print('held', flush=True); time.sleep(2)\n")],
        stdout=subprocess.PIPE, text=True, env=os.environ)
    other.stdout.readline()
    runs = []
    stop3 = threading.Event()
    jobs.every("t-one", 0.2, lambda: runs.append(1), stop=stop3)
    time.sleep(0.8); stop3.set(); other.wait()
    chk("every: pod khác đang chạy vòng này → pod này bỏ qua", runs == [], runs)

print("FAILS:", fails)
sys.exit(1 if fails else 0)
