#!/usr/bin/env python3
"""Lấy MẪU cấu hình VPN thật từ Sophos Firewall (CHỈ ĐỌC) và CHE dữ liệu nhạy cảm — để dựng mock/parser đúng thực tế.

Cách dùng (chạy ở máy được phép gọi API firewall, tài khoản API nên là read-only):

    SOPHOS_PASSWORD='***' python3 tools/sophos_sample.py --host 172.31.38.31 --port 4444 --user apiro \\
        --out sophos-sample --rule-group VPN --limit 10 [--insecure]

Kết quả: thư mục --out gồm <Entity>.xml + README.txt. Gửi lại thư mục này (đã che) cho người phát triển.

Che dữ liệu (nhất quán trong một lần chạy: cùng một người → cùng một mã giả ở mọi file):
  - Trường bí mật (Password, PasswordHash, PresharedKey, RSA key, OTP…) → "***"
  - Email / tên đăng nhập → nvXX.yy@example.invalid; mã người trong tên rule (THAM.NQ) → NVXX.YY
  - Họ tên, mô tả → "Người dùng N" / "[đã che]"; tên miền công ty → example.invalid
  - IPv4 → 10.a.b.<octet cuối giữ nguyên> (subnet mask giữ nguyên); địa chỉ MAC → 02:00:00:00:00:00
  - GIỮ: tên team, chữ "expire", ngày tháng, tên schedule/zone/service, cấu trúc XML — phục vụ parser.
Lệnh gửi firewall đi qua integrations/sophos/policy.py: chỉ Get, mọi thao tác ghi bị chặn trước khi gửi.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import xmltodict  # noqa: E402

from app.integrations.sophos import SophosClient  # noqa: E402
from app.integrations.sophos.policy import VPN_RULE_GROUPS_ALLOWED  # noqa: E402
from app.integrations.sophos.sanitize import SECRET_KEY_RE  # noqa: E402
from app.integrations.sophos.xmlutil import _as_list  # noqa: E402

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
CODE_RE = re.compile(r"\b[A-Za-z]{2,}(?:\.[A-Za-z]{1,6})+\b")  # THAM.NQ, chau.nb, nhan.ndt
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
PERSON_FIELDS = {"Name"}  # trong User: họ tên
FREE_TEXT = {"Description"}


def _letters(n: int, width: int = 2) -> str:
    s = ""
    for _ in range(width):
        s = chr(ord("a") + n % 26) + s
        n //= 26
    return s


class Redactor:
    def __init__(self) -> None:
        self.codes: dict[str, str] = {}
        self.nets: dict[str, str] = {}
        self.people: dict[str, str] = {}
        self.domains: set[str] = set()

    def code(self, raw: str) -> str:
        key = raw.lower()
        if key not in self.codes:
            i = len(self.codes)
            self.codes[key] = f"nv{_letters(i)}.{_letters(i * 7 + 3)}"
        alias = self.codes[key]
        return alias.upper() if raw.isupper() else alias

    def ip(self, m: re.Match) -> str:
        parts = [int(x) for x in m.groups()]
        if any(p > 255 for p in parts) or parts[0] in (0, 255):  # không phải IP / là subnet mask
            return m.group(0)
        net = ".".join(map(str, parts[:3]))
        if net not in self.nets:
            i = len(self.nets) + 1
            self.nets[net] = f"10.{i // 256}.{i % 256}"
        return f"{self.nets[net]}.{parts[3]}"

    def text(self, s: str) -> str:
        def email(m: re.Match) -> str:
            local, _, domain = m.group(0).partition("@")
            self.domains.add(domain.lower())
            return f"{self.code(local)}@example.invalid"

        s = EMAIL_RE.sub(email, s)
        for d in sorted(self.domains, key=len, reverse=True):
            s = re.sub(re.escape(d), "example.invalid", s, flags=re.I)
        def code(m: re.Match) -> str:
            tok = m.group(0)
            done = tok.lower() in self.codes.values() or tok.lower().startswith("example.")
            return tok if done else self.code(tok)

        s = CODE_RE.sub(code, s)
        s = MAC_RE.sub("02:00:00:00:00:00", s)  # MAC = định danh thiết bị cá nhân
        return IP_RE.sub(self.ip, s)

    def node(self, obj, key: str = "", entity: str = ""):
        if isinstance(obj, dict):
            return {k: self.node(v, k, entity) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.node(x, key, entity) for x in obj]
        if obj is None:
            return None
        s = str(obj)
        if SECRET_KEY_RE.search(key) or key.lower().endswith("key") and key not in ("Key",):
            return "***"
        if entity == "User" and key in PERSON_FIELDS:
            self.people.setdefault(s, f"Người dùng {len(self.people) + 1}")
            return self.people[s]
        if key in FREE_TEXT and s.strip():
            return "[đã che]"
        return self.text(s)


def _name(node: dict, path: str) -> str:
    cur = node
    for p in path.split("/"):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return str(cur or "")


def collect(cli: SophosClient, rule_group: str, limit: int, timeout: int) -> dict[str, list[dict]]:
    groups = [g for g in cli._get_all("FirewallRuleGroup", timeout) if g.get("Name") == rule_group]
    if not groups:
        raise SystemExit(f"Không thấy Rule Group '{rule_group}' trên firewall")
    names = [str(x) for x in _as_list((groups[0].get("SecurityPolicyList") or {}).get("SecurityPolicy"))]
    # lấy mẫu đa dạng: rule có/không chữ expire, có/không ngày, gắn schedule
    picked = set(names[:limit])
    all_rules = {r.get("Name"): r for r in cli._get_all("FirewallRule", timeout)}
    rules = [all_rules[n] for n in names if n in picked and n in all_rules]
    pol = lambda r: r.get("UserPolicy") or r.get("NetworkPolicy") or {}  # noqa: E731
    sched_names = {str(pol(r).get("Schedule") or "") for r in rules}
    members = {str(m) for r in rules for m in _as_list((pol(r).get("Identity") or {}).get("Member"))}
    schedules = [s for s in cli._get_all("Schedule", timeout) if s.get("Name") in sched_names]
    users_all = cli._get_all("User", timeout)
    groups_all = cli._get_all("UserGroup", timeout)
    ugroups = [g for g in groups_all if _name(g, "GroupDetail/Name") in members][:limit]
    group_members = {str(u) for g in ugroups for u in _as_list((g.get("GroupMembers") or {}).get("UserName"))}
    users = [u for u in users_all if u.get("Username") in members | group_members][:limit]
    users += [u for u in users_all if u not in users][: max(0, 3 - len(users))]
    return {
        "FirewallRuleGroup": [{**groups[0], "SecurityPolicyList": {"SecurityPolicy": [n for n in names if n in picked]}}],
        "FirewallRule": rules,
        "Schedule": schedules,
        "User": users,
        "UserGroup": ugroups,
        "SSLVPNPolicy": cli._get_all("SSLVPNPolicy", timeout)[:3],
        "VPNIPSecConnection": [c for c in cli._get_all("VPNIPSecConnection", timeout)
                               if _name(c, "Configuration/ConnectionType") == "RemoteAccess"][:3],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-env", default="SOPHOS_PASSWORD", help="biến môi trường chứa mật khẩu (mặc định "
                    "SOPHOS_PASSWORD); không có thì hỏi khi chạy")
    ap.add_argument("--rule-group", default="VPN")
    ap.add_argument("--limit", type=int, default=10, help="số rule / user / nhóm tối đa lấy mẫu")
    ap.add_argument("--out", default="sophos-sample")
    ap.add_argument("--insecure", action="store_true", help="bỏ kiểm tra chứng chỉ TLS (firewall dùng cert tự ký)")
    ap.add_argument("--timeout", type=int, default=180)
    a = ap.parse_args()
    if a.rule_group not in VPN_RULE_GROUPS_ALLOWED:
        raise SystemExit(f"Rule Group '{a.rule_group}' không nằm trong whitelist {VPN_RULE_GROUPS_ALLOWED}")
    pw = os.environ.get(a.password_env) or getpass.getpass(f"Mật khẩu API cho {a.user}@{a.host}: ")
    red = Redactor()
    with SophosClient(host=a.host, port=a.port, username=a.user, password=pw, verify_ssl=not a.insecure,
                      timeout=a.timeout, connect_timeout=15) as cli:
        data = collect(cli, a.rule_group, a.limit, a.timeout)
    os.makedirs(a.out, exist_ok=True)
    lines = []
    for entity, nodes in data.items():
        clean = [red.node(n, entity=entity) for n in nodes]
        xml = xmltodict.unparse({"Response": {entity: clean}} if clean else {"Response": None}, pretty=True)
        with open(os.path.join(a.out, f"{entity}.xml"), "w", encoding="utf-8") as fh:
            fh.write(xml)
        lines.append(f"{entity}: {len(clean)}")
    with open(os.path.join(a.out, "README.txt"), "w", encoding="utf-8") as fh:
        fh.write("Mẫu cấu hình VPN đã che dữ liệu — tạo bởi tools/sophos_sample.py (chỉ đọc).\n"
                 f"Rule Group: {a.rule_group}\n" + "\n".join(lines) + "\n"
                 f"Mã người đã đổi: {len(red.codes)}, dải IP đã đổi: {len(red.nets)}\n"
                 "Kiểm tra lại trước khi gửi: không còn email, họ tên, IP thật hay mật khẩu.\n")
    print("Đã ghi", a.out, "—", ", ".join(lines))


if __name__ == "__main__":
    main()
