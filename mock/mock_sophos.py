"""Mock Sophos Firewall XML API — chỉ dùng để test mini app khi không có firewall thật.

Chạy: python mock/mock_sophos.py --port 4444 (tự sinh cert self-signed)
Hỗ trợ: Login, Get IPHost/IPHostGroup (+Filter), Set add/update, Remove.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import subprocess
import tempfile
from typing import Any

import uvicorn
import xmltodict
from fastapi import FastAPI, Form
from fastapi.responses import Response

USER = os.getenv("MOCK_USER", "apiadmin")
PASSWORD = os.getenv("MOCK_PASSWORD", "Sophos@123")
STATE_FILE = os.getenv("MOCK_STATE", "/tmp/mock_sophos_state.json")

app = FastAPI(title="Mock Sophos Firewall")


def _load() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as fh:
            return json.load(fh)
    return {
        "hosts": {
            "SOC_BLOCK_45_155_204_11": {"HostType": "IP", "IPAddress": "45.155.204.11",
                                        "Description": "Scan SSH tet 2026"},
            "PARTNER_VPN_GW": {"HostType": "IP", "IPAddress": "203.113.88.9",
                               "Description": "Doi tac"},
        },
        "groups": {
            # Group cố định mà SOC Rapid Block được phép thao tác (gắn sẵn vào rule chặn trên firewall thật)
            "SCANPORT GROUP": {"Description": "Chan IP do quet port - SOC", "IPFamily": "IPv4",
                               "HostList": ["SOC_BLOCK_45_155_204_11"]},
            # Các group khác: app KHÔNG được đọc/sửa
            "SOC_BLOCKED_IPS": {"Description": "Nhom IP bi chan boi SOC", "IPFamily": "IPv4",
                                "HostList": ["PARTNER_VPN_GW"]},
            "SOC_BLOCKED_IPV6": {"Description": "Nhom IPv6", "IPFamily": "IPv6", "HostList": []},
            "SOC_BLOCKED_IPS_HANOI": {"Description": "Chi nhanh Ha Noi", "IPFamily": "IPv4",
                                      "HostList": []},
        },
    }


def _save(state: dict) -> None:
    with open(STATE_FILE, "w") as fh:
        json.dump(state, fh, indent=2)


STATE = _load()

import copy  # noqa: E402

import vpn_data  # noqa: E402 — chạy bằng `python mock/mock_sophos.py` nên thư mục mock nằm trong sys.path

VPN = {k: copy.deepcopy(v[0]) for k, v in vpn_data.ENTITIES.items()}
# Mô phỏng firewall chậm: số giây trễ khi Get toàn bộ IPHost (không Filter)
FULL_DELAY = float(os.getenv("MOCK_FULL_IPHOST_DELAY", "0"))
# Mô phỏng firewall phản hồi chậm ở MỌI lệnh (giây/lệnh) — dùng để tái hiện lỗi 504 khi chặn nhiều IP
REQ_DELAY = float(os.getenv("MOCK_REQ_DELAY", "0"))
STATS = {"iphost_full": 0, "iphost_one": 0, "requests": 0, "set_requests": 0, "iphost_set_entities": 0}


@app.get("/_stats")
def stats():
    return STATS


@app.post("/_delay")
def set_delay(seconds: float = 0, per_request: float | None = None):
    global FULL_DELAY, REQ_DELAY
    FULL_DELAY = seconds
    if per_request is not None:
        REQ_DELAY = per_request
    return {"delay": FULL_DELAY, "per_request": REQ_DELAY}


@app.post("/_vpn/reset")
def vpn_reset():
    for k, v in vpn_data.ENTITIES.items():
        VPN[k] = copy.deepcopy(v[0])
    return {"ok": True}


@app.post("/_vpn/user")
def vpn_user(username: str, action: str = "remove"):
    """Test: action=remove xóa user; action=disable/enable đổi Status."""
    users = VPN["User"]
    if action == "remove":
        VPN["User"] = [u for u in users if u["Username"] != username]
    else:
        for u in users:
            if u["Username"] == username:
                u["Status"] = "Deactive" if action == "disable" else "Active"
    return {"users": [u["Username"] for u in VPN["User"]]}


@app.post("/_vpn/rule")
def vpn_rule(name: str, action: str = "set", new_name: str = "", dst: str = "", status: str = "",
             schedule: str = "", schedule_end: str = ""):
    """Test: action=remove xóa rule (khỏi group); set: đổi tên / đích / bật-tắt / schedule / EndDate schedule."""
    rules = VPN["FirewallRule"]
    grp = next(g for g in VPN["FirewallRuleGroup"] if g["Name"] == "VPN")
    lst = grp["SecurityPolicyList"]["SecurityPolicy"]
    if action == "remove":
        VPN["FirewallRule"] = [r for r in rules if r["Name"] != name]
        grp["SecurityPolicyList"]["SecurityPolicy"] = [n for n in lst if n != name]
        return {"ok": True}
    r = next(x for x in rules if x["Name"] == name)
    pol = r.get("UserPolicy") or r.get("NetworkPolicy")
    if new_name:
        lst[lst.index(name)] = new_name
        r["Name"] = new_name
    if dst:
        pol["DestinationNetworks"] = {"Network": dst.split(",")}
    if status:
        r["Status"] = status
    if schedule:
        pol["Schedule"] = schedule
    if schedule_end:
        sc = next(x for x in VPN["Schedule"] if x["Name"] == pol["Schedule"])
        sc["ScheduleDetails"]["EndDate"] = schedule_end
    return {"ok": True}


@app.post("/_reset_stats")
def reset_stats():
    for k in STATS:
        STATS[k] = 0
    return STATS


def _resp(body: str) -> Response:
    return Response(
        content=f'<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2200.1">'
        f"<Login><status>Authetication Successful</status></Login>{body}</Response>",
        media_type="application/xml",
    )


def _status(tag: str, code: str, text: str, tid: str = "") -> str:
    return f'<{tag} transactionid="{_x(tid)}"><Status code="{code}">{text}</Status></{tag}>'


def _x(v) -> str:
    from xml.sax.saxutils import escape

    return escape(str(v or ""))


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@app.post("/webconsole/APIController")
@app.get("/webconsole/APIController")
def controller(reqxml: str = Form(default="")):
    STATS["requests"] += 1
    if REQ_DELAY:
        time.sleep(REQ_DELAY)
    req = xmltodict.parse(reqxml).get("Request", {})
    login = req.get("Login") or {}
    if login.get("Username") != USER or login.get("Password") != PASSWORD:
        return Response(
            content='<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2200.1">'
            "<Login><status>Authentication Failure</status></Login></Response>",
            media_type="application/xml",
        )

    # ------------------------------------------------------------------ GET
    if "Get" in req:
        get = req["Get"] or {}
        for ent, (_, key_fn) in vpn_data.ENTITIES.items():
            if ent not in get:
                continue
            node = get.get(ent) or {}
            name_filter = None
            if isinstance(node, dict) and node.get("Filter"):
                key = node["Filter"].get("key") or node["Filter"].get("Key")
                if isinstance(key, dict):
                    name_filter = key.get("#text")
            items = [x for x in VPN[ent] if name_filter is None or key_fn(x) == name_filter]
            if not items:
                return _resp(_status(ent, "526", "Number of records Zero."))
            body = "".join(
                xmltodict.unparse({ent: {"@transactionid": "", **{k: v for k, v in x.items() if v is not None}}},
                                  full_document=False)
                for x in items
            )
            return _resp(body)
        if "IPHostGroup" in get:
            node = get.get("IPHostGroup") or {}
            name_filter = None
            if isinstance(node, dict) and node.get("Filter"):
                key = node["Filter"].get("key") or node["Filter"].get("Key")
                if isinstance(key, dict):
                    name_filter = key.get("#text")
            out = []
            for name, g in STATE["groups"].items():
                if name_filter and name != name_filter:
                    continue
                hosts = "".join(f"<Host>{h}</Host>" for h in g["HostList"])
                out.append(
                    f'<IPHostGroup transactionid=""><Name>{name}</Name>'
                    f"<IPFamily>{g['IPFamily']}</IPFamily>"
                    f"<Description>{_x(g['Description'])}</Description>"
                    f"<HostList>{hosts}</HostList></IPHostGroup>"
                )
            if not out:
                return _resp(_status("IPHostGroup", "526", "Number of records Zero."))
            return _resp("".join(out))

        if "IPHost" in get:
            node = get.get("IPHost") or {}
            name_filter = None
            if isinstance(node, dict) and node.get("Filter"):
                key = node["Filter"].get("key") or node["Filter"].get("Key")
                if isinstance(key, dict):
                    name_filter = key.get("#text")
            STATS["iphost_full" if name_filter is None else "iphost_one"] += 1
            if name_filter is None and FULL_DELAY:
                time.sleep(FULL_DELAY)  # mô phỏng firewall nhiều object trả toàn bộ IP Host rất chậm
            out = []
            for name, h in STATE["hosts"].items():
                if name_filter is not None and name != name_filter:
                    continue
                out.append(
                    f'<IPHost transactionid=""><Name>{name}</Name><IPFamily>IPv4</IPFamily>'
                    f"<HostType>{h['HostType']}</HostType>"
                    f"<IPAddress>{h.get('IPAddress','')}</IPAddress>"
                    + (f"<Subnet>{h['Subnet']}</Subnet>" if h.get("Subnet") else "")
                    + f"<Description>{h.get('Description','')}</Description></IPHost>"
                )
            if not out:
                return _resp(_status("IPHost", "526", "Number of records Zero."))
            return _resp("".join(out))

    # ------------------------------------------------------------------ SET
    if "Set" in req:
        STATS["set_requests"] += 1
        st = req["Set"] or {}
        op = (st.get("@operation") or "add").lower()

        if "IPHost" in st:
            # Sophos cho phép nhiều entity trong một <Set>; mỗi entity trả về một Status, kèm transactionid
            return _resp("".join(_set_iphost(h, op) for h in _as_list(st["IPHost"])))

        if "IPHostGroup" in st:
            g = st["IPHostGroup"]
            name = g["Name"]
            # Kiểm tra đúng mẫu tài liệu: Name → IPFamily → Description → HostList
            expected = ["Name", "IPFamily", "Description", "HostList"]
            keys = [k for k in g.keys() if not k.startswith("@")]
            if keys != [k for k in expected if k in keys] or any(k not in expected for k in keys):
                return _resp(_status("IPHostGroup", "500", f"Unexpected element order: {keys}"))
            fam = g.get("IPFamily") or "IPv4"
            if fam not in ("IPv4", "IPv6"):
                return _resp(_status("IPHostGroup", "500", f"Invalid IPFamily: {fam}"))
            if "," in name:
                return _resp(_status("IPHostGroup", "500", "Comma not allowed in Name"))
            hosts = _as_list((g.get("HostList") or {}).get("Host")) if g.get("HostList") else []
            unknown = [h for h in hosts if h not in STATE["hosts"]]
            if unknown:
                return _resp(_status("IPHostGroup", "500",
                                     f"Referred host not found: {', '.join(unknown)}"))
            wrong = [h for h in hosts if STATE["hosts"][h].get("IPFamily", "IPv4") != fam]
            if wrong:
                return _resp(_status("IPHostGroup", "500",
                                     f"Host family mismatch with group {fam}: {', '.join(wrong)}"))
            if op == "update" and STATE["groups"].get(name, {}).get("IPFamily", fam) != fam:
                return _resp(_status("IPHostGroup", "500", "IPFamily of an existing group cannot be changed"))
            if op == "add" and name in STATE["groups"]:
                return _resp(_status("IPHostGroup", "502",
                                     "Entity having same name already exists."))
            STATE["groups"][name] = {
                "Description": g.get("Description", ""),
                "IPFamily": g.get("IPFamily", "IPv4"),
                "HostList": hosts,
            }
            _save(STATE)
            code = "200" if op == "add" else "202"
            return _resp(_status("IPHostGroup", code,
                                 f'Host group "{name}" has been updated successfully.'))

    # --------------------------------------------------------------- REMOVE
    if "Remove" in req:
        rm = req["Remove"] or {}
        if "IPHost" in rm:
            name = (rm["IPHost"] or {}).get("Name")
            if name not in STATE["hosts"]:
                return _resp(_status("IPHost", "526", "Record does not exist."))
            for g in STATE["groups"].values():
                if name in g["HostList"]:
                    return _resp(_status("IPHost", "504",
                                         "Operation failed. Deleting entity referred by another entity."))
            STATE["hosts"].pop(name)
            _save(STATE)
            return _resp(_status("IPHost", "200", "Host has been deleted successfully."))

    return _resp(_status("Request", "529", "Invalid XML request for entity/entities."))


def _set_iphost(h: dict, op: str) -> str:
    STATS["iphost_set_entities"] += 1
    tid = h.get("@transactionid") or ""
    name = h["Name"]
    if "," in name or name[:1] in ("#", ",") or len(name) > 60:
        return _status("IPHost", "500", "Invalid Name (no comma, not start with #, max 60)", tid)
    if op == "add" and name in STATE["hosts"]:
        return _status("IPHost", "502", f'Host "{name}" already exists.', tid)
    same_ip = [
        n for n, v in STATE["hosts"].items()
        if v.get("IPAddress") == h.get("IPAddress") and v.get("Subnet", "") == h.get("Subnet", "") and n != name
    ]
    if op == "add" and same_ip:
        return _status("IPHost", "503", "Entity having same parameter details already exists.", tid)
    STATE["hosts"][name] = {
        "HostType": h.get("HostType", "IP"),
        "IPFamily": h.get("IPFamily", "IPv4"),
        "IPAddress": h.get("IPAddress", ""),
        "Subnet": h.get("Subnet", ""),
        "Description": h.get("Description", ""),
    }
    _save(STATE)
    return _status("IPHost", "200", f'Host "{name}" has been added successfully.', tid)


def _self_signed() -> tuple[str, str]:
    tmp = tempfile.mkdtemp(prefix="mockfw-")
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
         "-out", crt, "-days", "365", "-subj", "/CN=mock-sophos"],
        check=True, capture_output=True,
    )
    return key, crt


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4444)
    args = ap.parse_args()
    k, c = _self_signed()
    uvicorn.run(app, host="127.0.0.1", port=args.port, ssl_keyfile=k, ssl_certfile=c,
                log_level="warning")
