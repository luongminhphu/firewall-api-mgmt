# Chạy: bash tests/run_e2e.sh tests/policy_guard_test.py
# integrations/sophos/policy.py là điểm chặn duy nhất: mọi lệnh ngoài allowlist bị chặn TRƯỚC khi gửi
# (firewall không nhận được request nào) và ghi audit `policy_violation`.
import sys

import httpx

sys.path.insert(0, "backend")
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.models import AuditLog  # noqa: E402
from app.integrations.sophos import SophosClient  # noqa: E402
from app.integrations.sophos.policy import (  # noqa: E402
    GroupPolicyError, PolicyViolation, check_request,
)

init_db()
mk = httpx.Client(base_url="https://127.0.0.1:4460", verify=False, timeout=10)
cli = SophosClient(host="127.0.0.1", port=4460, username="apiadmin", password="Sophos@123", timeout=10)
fails = 0


def chk(name, cond, extra=""):
    global fails
    fails += 0 if cond else 1
    print(("PASS " if cond else "FAIL ") + name, extra)


def requests_sent():
    return mk.get("/_stats").json()["requests"]


def violations():
    with SessionLocal() as db:
        return db.query(AuditLog).filter(AuditLog.action == "policy_violation").count()


# ------------------------------------------------------------- được phép
ok_cases = {
    "Get IPHostGroup": "<Get><IPHostGroup></IPHostGroup></Get>",
    "Get IPHost theo tên": '<Get><IPHost><Filter><key name="Name" criteria="=">1.2.3.4</key></Filter></IPHost></Get>',
    "Set add IPHost (gộp 2)": '<Set operation="add"><IPHost transactionid="t0"><Name>1.2.3.4</Name></IPHost>'
                              '<IPHost transactionid="t1"><Name>1.2.3.5</Name></IPHost></Set>',
    "Set update SCANPORT GROUP": '<Set operation="update"><IPHostGroup><Name>SCANPORT GROUP</Name></IPHostGroup></Set>',
    "Remove IPHost": "<Remove><IPHost><Name>1.2.3.4</Name></IPHost></Remove>",
    # Module VPN — chỉ đọc
    "Get User": "<Get><User></User></Get>",
    "Get UserGroup": "<Get><UserGroup></UserGroup></Get>",
    "Get SSLVPNPolicy": "<Get><SSLVPNPolicy></SSLVPNPolicy></Get>",
    "Get VPNIPSecConnection": "<Get><VPNIPSecConnection></VPNIPSecConnection></Get>",
    "Get Schedule": "<Get><Schedule></Schedule></Get>",
    "Get FirewallRule": "<Get><FirewallRule></FirewallRule></Get>",
    "Get FirewallRuleGroup (tất cả)": "<Get><FirewallRuleGroup></FirewallRuleGroup></Get>",
    "Get FirewallRuleGroup VPN": '<Get><FirewallRuleGroup><Filter><key name="Name" criteria="=">VPN</key>'
                                 "</Filter></FirewallRuleGroup></Get>",
}
for name, xml in ok_cases.items():
    try:
        check_request(xml)
        chk(f"cho phép: {name}", True)
    except PolicyViolation as exc:
        chk(f"cho phép: {name}", False, str(exc))

# ------------------------------------------------- bị chặn (gửi thật qua client)
deny_cases = {
    "Set add FirewallRule": '<Set operation="add"><FirewallRule><Name>ALLOW ALL</Name></FirewallRule></Set>',
    "Set update FirewallRule (tắt rule VPN)":
        '<Set operation="update"><FirewallRule><Name>THAM.NQ expire 23/04/2027</Name>'
        "<Status>Disable</Status></FirewallRule></Set>",
    "Remove FirewallRule": "<Remove><FirewallRule><Name>THAM.NQ expire 23/04/2027</Name></FirewallRule></Remove>",
    "Set add User": '<Set operation="add"><User><Username>hacker</Username></User></Set>',
    "Set update User": '<Set operation="update"><User><Username>tham.nq</Username></User></Set>',
    "Remove User": "<Remove><User><Name>tham.nq</Name></User></Remove>",
    "Set update group khác": '<Set operation="update"><IPHostGroup><Name>SOC_BLOCKED_IPS</Name></IPHostGroup></Set>',
    "Set add IPHostGroup": '<Set operation="add"><IPHostGroup><Name>SCANPORT GROUP</Name></IPHostGroup></Set>',
    "Remove IPHostGroup": "<Remove><IPHostGroup><Name>SCANPORT GROUP</Name></IPHostGroup></Remove>",
    "Set update IPHost": '<Set operation="update"><IPHost><Name>1.2.3.4</Name></IPHost></Set>',
    "lẫn một entity cấm trong lệnh gộp": '<Set operation="add"><IPHost><Name>1.2.3.4</Name></IPHost>'
                                         "<FirewallRule><Name>X</Name></FirewallRule></Set>",
    "Get AdminSettings (cấu hình hệ thống, không mở)": "<Get><AdminSettings></AdminSettings></Get>",
    "Get Rule Group ngoài whitelist": '<Get><FirewallRuleGroup><Filter><key name="Name" criteria="=">Default</key>'
                                      "</Filter></FirewallRuleGroup></Get>",
    "Set update FirewallRuleGroup VPN": '<Set operation="update"><FirewallRuleGroup><Name>VPN</Name>'
                                        "</FirewallRuleGroup></Set>",
    "Set update Schedule": '<Set operation="update"><Schedule><Name>VPN-THAM-2027</Name></Schedule></Set>',
    "Remove UserGroup": "<Remove><UserGroup><Name>RMS RESEARCH</Name></UserGroup></Remove>",
    "Set update SSLVPNPolicy": '<Set operation="update"><SSLVPNPolicy><TunnelPolicy><Name>X</Name></TunnelPolicy>'
                               "</SSLVPNPolicy></Set>",
    "XML hỏng": "<Set operation='add'><IPHost>",
    "chèn Login thứ hai": "<Login><Username>x</Username></Login>",
}
for name, xml in deny_cases.items():
    before_req, before_v = requests_sent(), violations()
    try:
        cli._post(xml)
        chk(f"chặn: {name}", False, "lệnh đã được gửi!")
        continue
    except PolicyViolation:
        pass
    chk(f"chặn: {name} — không gửi gì tới firewall", requests_sent() == before_req)
    chk(f"chặn: {name} — có audit policy_violation", violations() == before_v + 1)

# ---------------------------------------------- xóa object không do app tạo
before_req = requests_sent()
try:
    cli.delete_ip_host("PARTNER_VPN_GW", "203.113.88.9")
    chk("không xóa object không do app tạo", False)
except GroupPolicyError:
    chk("không xóa object không do app tạo (không gửi gì)", requests_sent() == before_req)

# client cấp cao vẫn chặn đúng group cố định (lớp phòng thủ thứ hai)
try:
    cli.set_group_hosts("SOC_BLOCKED_IPS", [])
    chk("set_group_hosts group khác bị chặn", False)
except GroupPolicyError:
    chk("set_group_hosts group khác bị chặn", True)

cli.close()
print("FAILS:", fails)
sys.exit(1 if fails else 0)
