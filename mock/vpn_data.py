"""Dữ liệu VPN giả lập cho mock Sophos (cấu trúc theo tài liệu XML API SFOS 22.0 — docs/architecture.md §5.1).

Rule Group "VPN" chứa các rule theo đúng mẫu tên đang vận hành ở HSC (có/không chữ "expire", không có ngày,
rule tắt, rule hết hạn vẫn bật, rule gắn Schedule lệch ngày với tên). Có cả trường BÍ MẬT giả (Password,
PasswordHash, PresharedKey…) để kiểm tra app không bao giờ lưu/log/trả về chúng.
"""
from __future__ import annotations

SECRET = "MOCK-SECRET-KHONG-DUOC-LO"
DOMAIN = "hsc.com.vn"


def _user(username, name, *, group="Open Group", status="Active", user_type="User", sslvpn="No Policy Applied",
          email=True):
    return {
        "Username": username,
        "Name": name,
        "Password": SECRET,
        "PasswordHash": "$2a$10$" + SECRET,
        "UserType": user_type,
        "Profile": "Administrator" if user_type == "Administrator" else None,
        "EmailList": {"EmailID": username if "@" in username else f"{username}@{DOMAIN}"} if email else None,
        "Group": group,
        "Description": f"Tài khoản {name}",
        "SSLVPNPolicy": sslvpn,
        "ClientlessPolicy": "No Policy Applied",
        "L2TP": "Disable",
        "PPTP": "Disable",
        "MACAddressList": {"MACAddress": "00:11:22:33:44:55"},
        "Status": status,
    }


USERS = [
    _user(f"tham.nq@{DOMAIN}", "Nguyễn Quang Thắm", group="IT Staff", sslvpn="SSLVPN-STAFF"),
    _user(f"chau.nb@{DOMAIN}", "Ngô Bảo Châu", group="RMS RESEARCH"),
    _user(f"nhan.ndt@{DOMAIN}", "Nguyễn Đức Thành Nhân", group="RMS RESEARCH"),
    _user(f"hr.test1@{DOMAIN}", "HR Test 1", group="HR HRIS TEST", sslvpn="SSLVPN-STAFF"),
    _user(f"old.user@{DOMAIN}", "Nhân viên đã nghỉ", group="IT Staff", status="Deactive", sslvpn="SSLVPN-STAFF"),
    _user("admin", "Quản trị firewall", user_type="Administrator", group="Open Group", email=False),
]

USER_GROUPS = [
    {"GroupDetail": {"Name": "RMS RESEARCH", "GroupType": "Normal", "SSLVPNPolicy": "SSLVPN-STAFF",
                     "QoSPolicy": "None"},
     "GroupMembers": {"GroupName": "RMS RESEARCH", "UserName": [f"chau.nb@{DOMAIN}", f"nhan.ndt@{DOMAIN}"]}},
    {"GroupDetail": {"Name": "HR HRIS TEST", "GroupType": "Normal", "SSLVPNPolicy": "No Policy Applied"},
     "GroupMembers": {"GroupName": "HR HRIS TEST", "UserName": f"hr.test1@{DOMAIN}"}},
    {"GroupDetail": {"Name": "IT Staff", "GroupType": "Normal", "SSLVPNPolicy": "No Policy Applied"},
     "GroupMembers": {"GroupName": "IT Staff", "UserName": [f"tham.nq@{DOMAIN}", f"old.user@{DOMAIN}"]}},
]

SSLVPN_POLICIES = [
    {"TunnelPolicy": {"Name": "SSLVPN-STAFF", "Description": "Nhân viên làm việc từ xa",
                      "PolicyMembers": {"Member": [f"tham.nq@{DOMAIN}", "RMS RESEARCH", f"hr.test1@{DOMAIN}"]},
                      "UseAsDefaultGateway": "off",
                      "PermittedNetworkResourcesIPv4": {"Resource": ["G_HSC_DNS_LOCAL", "192.168.82.46"]}}},
]

IPSEC_CONNECTIONS = [
    {"Configuration": {"Name": "IPSEC-RA", "Description": "IPsec remote access", "ConnectionType": "RemoteAccess",
                       "Policy": "DefaultRemoteAccess", "AuthenticationType": "PresharedKey",
                       "PresharedKey": SECRET, "RemoteRSAKey": SECRET, "UserAuthenticationMode": "AsServer",
                       "AllowedUser": {"User": [f"chau.nb@{DOMAIN}"]}, "Status": "Active"}},
    {"Configuration": {"Name": "S2S-CHI-NHANH", "ConnectionType": "SiteToSite", "Policy": "DefaultSite",
                       "AuthenticationType": "PresharedKey", "PresharedKey": SECRET, "Status": "Active"}},
]

SCHEDULES = [
    {"Name": "All The Time", "Description": "", "Type": "Recurring"},
    {"Name": "VPN-THAM-2027", "Description": "Hạn VPN THAM.NQ", "Type": "OneTime",
     "ScheduleDetails": {"StartDate": "2026-01-01 00:00:00", "EndDate": "2027-04-23 23:59:00"}},
    # Lệch với tên rule (tên ghi 19/10/2027) → app phải gắn cờ "Lệch thời hạn"
    {"Name": "VPN-CHAU-2027", "Description": "", "Type": "OneTime",
     "ScheduleDetails": {"StartDate": "2026-01-01 00:00:00", "EndDate": "2027-09-30 23:59:00"}},
    {"Name": "Work hours (5 Day week)", "Type": "Recurring",
     "ScheduleDetails": {"ScheduleDetail": {"Days": "WeekDays", "StartTime": "08:00", "StopTime": "18:00"}}},
]


def _rule(name, *, members, dst_nets, services, schedule="All The Time", status="Enable", dst_zones=("LAN",),
          description="", log="Enable"):
    return {
        "Name": name, "Description": description, "Status": status, "IPFamily": "IPv4", "Position": "Bottom",
        "PolicyType": "User",
        "UserPolicy": {
            "Action": "Accept", "LogTraffic": log, "SkipLocalDestined": "Disable",
            "SourceZones": {"Zone": "VPN"},
            "SourceNetworks": {"Network": "##ALL_SSLVPN_RW"},
            "Services": {"Service": list(services)},
            "Schedule": schedule,
            "DestinationZones": {"Zone": list(dst_zones)},
            "DestinationNetworks": {"Network": list(dst_nets)},
            "MatchIdentity": "Enable",
            "Identity": {"Member": list(members)},
        },
    }


FIREWALL_RULES = [
    _rule("THAM.NQ expire 23/04/2027", members=[f"tham.nq@{DOMAIN}"], dst_nets=["THAM.NQ - IT"],
          services=["RDP"], schedule="VPN-THAM-2027"),
    _rule("RMS RESEARCH - CHAU.NB expire 19/10/2027", members=[f"chau.nb@{DOMAIN}"], dst_nets=["192.168.82.46"],
          services=["RDP", "HTTPS"], schedule="VPN-CHAU-2027"),
    _rule("RMS RESEARCH - NHAN.NDT 30/06/2027", members=[f"nhan.ndt@{DOMAIN}"], dst_nets=["RMS"],
          services=["DNS", "LDAP", "TCP-8080", "Kerberos-88", "TCP-5001", "LDAP-GC-3268"]),
    _rule("HR team testing HRIS - expire 31/12/2026", members=["HR HRIS TEST"], dst_nets=["HRIS-SERVER"],
          services=["HTTPS", "HTTP"]),
    _rule("VPN - RMS RESEARCH GROUP access Factset Server", members=["RMS RESEARCH"], dst_nets=["FACTSET-SRV"],
          services=["HTTPS"], description="Truy cập Factset"),
    _rule("OLD.USER expire 01/01/2025", members=[f"old.user@{DOMAIN}"], dst_nets=["G_HSC_DNS_LOCAL"],
          services=["DNS"]),
    _rule("TEMP.VENDOR expire 15/03/2026", members=[f"tham.nq@{DOMAIN}"], dst_nets=["VENDOR-NET"],
          services=["SSH"], status="Disable"),
    _rule("ABC expire 31/02/2027", members=[f"tham.nq@{DOMAIN}"], dst_nets=["LAB"], services=["HTTPS"]),
    # Rule ngoài Rule Group VPN — app KHÔNG được đọc vào module VPN
    {"Name": "LAN to WAN", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
     "NetworkPolicy": {"Action": "Accept", "SourceZones": {"Zone": "LAN"}, "DestinationZones": {"Zone": "WAN"},
                       "Schedule": "All The Time"}},
]

RULE_GROUPS = [
    {"Name": "VPN", "Description": "Quyền truy cập VPN theo người/nhóm",
     "SecurityPolicyList": {"SecurityPolicy": [r["Name"] for r in FIREWALL_RULES if r["Name"] != "LAN to WAN"]},
     "SourceZones": {"Zone": "VPN"}, "Policytype": "User rule"},
    {"Name": "Default", "Description": "", "SecurityPolicyList": {"SecurityPolicy": ["LAN to WAN"]},
     "Policytype": "Network rule"},
]

# entity → (danh sách, hàm lấy tên để Filter Name)
ENTITIES = {
    "User": (USERS, lambda x: x["Username"]),
    "UserGroup": (USER_GROUPS, lambda x: x["GroupDetail"]["Name"]),
    "SSLVPNPolicy": (SSLVPN_POLICIES, lambda x: x["TunnelPolicy"]["Name"]),
    "VPNIPSecConnection": (IPSEC_CONNECTIONS, lambda x: x["Configuration"]["Name"]),
    "Schedule": (SCHEDULES, lambda x: x["Name"]),
    "FirewallRule": (FIREWALL_RULES, lambda x: x["Name"]),
    "FirewallRuleGroup": (RULE_GROUPS, lambda x: x["Name"]),
}
