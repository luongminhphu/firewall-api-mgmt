# Chạy: PYTHONPATH=backend python3 tests/vpn_rules_perf_test.py   (hoặc qua run_e2e.sh)
"""link_accounts mới (chỉ mục) phải cho kết quả y hệt bản cũ (kể cả thứ tự) và nhanh: 500 rule × 2000 tài khoản < 2 s."""
import json
import random
import sys
import time
from types import SimpleNamespace as NS

from app.modules.vpn.rules import _index, link_accounts


def old_link_accounts(identities, user_code, accounts):  # bản gốc trước tối ưu, làm tham chiếu
    if not accounts:
        return [], False
    idents = {i.lower() for i in identities}
    linked = [a for a in accounts if a.username_key in idents
              or idents & {g.lower() for g in json.loads(a.groups_json or "[]")}]
    if not linked and user_code:
        code = user_code.lower()
        linked = [a for a in accounts if a.username_key.split("@")[0] == code]
    user_like = [i for i in idents if "@" in i]
    missing_users = [i for i in user_like if i not in {a.username_key for a in accounts}]
    gone = (bool(linked) and all(a.removed_at is not None or a.status.lower() != "active" for a in linked)) or \
           (not linked and bool(missing_users))
    return linked, gone


rnd = random.Random(42)
GROUPS = [f"Grp{i}" for i in range(40)]


def acct(i):
    st = rnd.choice(["Active", "Active", "Active", "Disabled", "LOCKED"])
    return NS(username_key=f"user{i}@corp.vn" if i % 3 else f"user{i}", status=st,
              removed_at=rnd.choice([None, None, None, "x"]),
              groups_json=json.dumps(rnd.sample(GROUPS, rnd.randint(0, 3)) if i % 5 else []))


ACCS = [acct(i) for i in range(2000)]
dead = [NS(username_key=f"d{i}@corp.vn", status="Disabled", removed_at="x", groups_json='["Dead"]') for i in range(3)]


def rand_ident():
    kind = rnd.random()
    if kind < .3:
        return f"user{rnd.randint(0, 2100)}@corp.vn"
    if kind < .4:
        return f"USER{rnd.randint(0, 2100)}"
    if kind < .8:
        return rnd.choice(GROUPS).swapcase()
    return f"ghost{rnd.randint(0, 9)}@corp.vn"


cases = [([rand_ident() for _ in range(rnd.randint(0, 4))], rnd.choice(["", f"user{rnd.randint(0, 2100)}", "NOPE"]))
         for _ in range(500)]
cases += [(["Dead"], ""), (["d1@corp.vn"], ""), (["ghost@x.vn"], ""), ([], "user1"), ([], "USER4"), (["GRP1"], "user4")]
sets = [ACCS, dead, []]

fails = 0
t_old = t_new = 0.0
for accs in sets:
    t = time.perf_counter()
    exp = [old_link_accounts(i, c, accs) for i, c in cases]
    t_old += time.perf_counter() - t
    t = time.perf_counter()
    idx = _index(accs)
    got = [link_accounts(i, c, idx) for i, c in cases]
    t_new += time.perf_counter() - t
    for (i, c), e, g in zip(cases, exp, got):
        if [id(a) for a in e[0]] != [id(a) for a in g[0]] or e[1] != g[1]:
            fails += 1
            print("FAIL lệch", i, c)
print(f"thời gian cũ {t_old:.2f}s · mới {t_new:.2f}s")
if t_new >= 2 or t_new * 5 > t_old:  # tuyệt đối + tương đối: gỡ tối ưu thì FAIL
    fails += 1
    print("FAIL chậm >= 2 s")
print("PASS" if not fails else f"FAIL ({fails})")
sys.exit(1 if fails else 0)
