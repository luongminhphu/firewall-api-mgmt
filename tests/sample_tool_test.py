# Chạy: bash tests/run_e2e.sh tests/sample_tool_test.py
# tools/sophos_sample.py: chỉ đọc (không lệnh Set/Remove nào tới firewall), che bí mật / email / mã người / IP /
# họ tên một cách nhất quán, giữ cấu trúc tên rule (team, "expire", ngày) và chỉ lấy rule trong Rule Group VPN.
import os
import re
import subprocess
import sys
import tempfile

import httpx

mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


mk.post("/_reset_stats")
out = tempfile.mkdtemp(prefix="sample-")
r = subprocess.run([sys.executable, "tools/sophos_sample.py", "--host", "127.0.0.1", "--port", "4460",
                    "--user", "apiadmin", "--insecure", "--out", out, "--limit", "20"],
                   env={**os.environ, "SOPHOS_PASSWORD": "Sophos@123"}, capture_output=True, text=True, timeout=120)
chk("chạy thành công", r.returncode == 0, (r.stdout + r.stderr)[-300:])
st = mk.get("/_stats").json()
chk("không gửi lệnh ghi nào tới firewall", st["set_requests"] == 0, st)

files = {f: open(os.path.join(out, f), encoding="utf-8").read() for f in os.listdir(out)}
allx = "\n".join(files.values())
for f in ("FirewallRule.xml", "FirewallRuleGroup.xml", "Schedule.xml", "User.xml", "UserGroup.xml",
          "SSLVPNPolicy.xml", "VPNIPSecConnection.xml", "README.txt"):
    chk(f"có {f}", f in files)
chk("không lộ mật khẩu/hash/khóa giả lập", "MOCK-SECRET" not in allx)
chk("trường bí mật thay bằng ***", "<Password>***</Password>" in files["User.xml"]
    and "<PresharedKey>***</PresharedKey>" in files["VPNIPSecConnection.xml"])
chk("không lộ tên miền công ty", "hsc.com.vn" not in allx.lower())
chk("không lộ mã người thật", not re.search(r"tham\.nq|chau\.nb|nhan\.ndt", allx, re.I))
chk("không lộ họ tên", "Nguyễn Quang Thắm" not in allx and "Ngô Bảo Châu" not in allx)
chk("không lộ IP nội bộ thật", "192.168.82.46" not in allx)
chk("không lộ địa chỉ MAC", "00:11:22:33:44:55" not in allx)
rules = files["FirewallRule.xml"]
chk("chỉ rule trong Rule Group VPN (không có LAN to WAN)", "LAN to WAN" not in allx)
chk("giữ cấu trúc tên rule: team + expire + ngày",
    re.search(r"<Name>RMS RESEARCH - NV[A-Z]{2}\.[A-Z]{2} expire 19/10/2027</Name>", rules) is not None)
chk("giữ rule không có ngày", "VPN - RMS RESEARCH GROUP access Factset Server" in rules)
chk("giữ ##ALL_SSLVPN_RW và schedule", "##ALL_SSLVPN_RW" in rules and "VPN-THAM-2027" in rules)
m = re.search(r"<Name>(NV[A-Z]{2}\.[A-Z]{2}) expire 23/04/2027</Name>", rules)
code = m.group(1).lower() if m else "?"
chk("mã giả nhất quán: tên rule ↔ identity ↔ User", f"{code}@example.invalid" in rules
    and f"<Username>{code}@example.invalid</Username>" in files["User.xml"], code)
chk("Schedule giữ ngày hết hạn", "2027-04-23 23:59:00" in files["Schedule.xml"])
print("FAILS:", fails)
sys.exit(1 if fails else 0)
