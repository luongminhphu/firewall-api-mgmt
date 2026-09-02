"""Mock Sophos Firewall XML API — chỉ dùng để test mini app khi không có firewall thật.

Chạy: python mock/mock_sophos.py --port 4444 (tự sinh cert self-signed)
Hỗ trợ: Login, Get IPHost/IPHostGroup (+Filter), Set add/update, Remove.
"""
from __future__ import annotations

import argparse
import json
import os
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
            "SOC_BLOCKED_IPS": {"Description": "Nhom IP bi chan boi SOC", "IPFamily": "IPv4",
                                "HostList": ["SOC_BLOCK_45_155_204_11"]},
            "SOC_BLOCKED_IPS_HANOI": {"Description": "Chi nhanh Ha Noi", "IPFamily": "IPv4",
                                      "HostList": []},
        },
    }


def _save(state: dict) -> None:
    with open(STATE_FILE, "w") as fh:
        json.dump(state, fh, indent=2)


STATE = _load()


def _resp(body: str) -> Response:
    return Response(
        content=f'<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2200.1">'
        f"<Login><status>Authetication Successful</status></Login>{body}</Response>",
        media_type="application/xml",
    )


def _status(tag: str, code: str, text: str) -> str:
    return f'<{tag} transactionid=""><Status code="{code}">{text}</Status></{tag}>'


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@app.post("/webconsole/APIController")
@app.get("/webconsole/APIController")
def controller(reqxml: str = Form(default="")):
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
                    f"<Description>{g['Description']}</Description>"
                    f"<IPFamily>{g['IPFamily']}</IPFamily>"
                    f"<HostList>{hosts}</HostList></IPHostGroup>"
                )
            if not out:
                return _resp(_status("IPHostGroup", "526", "Number of records Zero."))
            return _resp("".join(out))

        if "IPHost" in get:
            out = []
            for name, h in STATE["hosts"].items():
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
        st = req["Set"] or {}
        op = (st.get("@operation") or "add").lower()

        if "IPHost" in st:
            h = st["IPHost"]
            name = h["Name"]
            if op == "add" and name in STATE["hosts"]:
                return _resp(_status("IPHost", "502",
                                     f'Host "{name}" already exists.'))
            same_ip = [
                n for n, v in STATE["hosts"].items()
                if v.get("IPAddress") == h.get("IPAddress") and n != name
            ]
            if op == "add" and same_ip:
                return _resp(_status("IPHost", "503",
                                     "Entity having same parameter details already exists."))
            STATE["hosts"][name] = {
                "HostType": h.get("HostType", "IP"),
                "IPAddress": h.get("IPAddress", ""),
                "Subnet": h.get("Subnet", ""),
                "Description": h.get("Description", ""),
            }
            _save(STATE)
            return _resp(_status("IPHost", "200", f'Host "{name}" has been added successfully.'))

        if "IPHostGroup" in st:
            g = st["IPHostGroup"]
            name = g["Name"]
            hosts = _as_list((g.get("HostList") or {}).get("Host")) if g.get("HostList") else []
            unknown = [h for h in hosts if h not in STATE["hosts"]]
            if unknown:
                return _resp(_status("IPHostGroup", "500",
                                     f"Referred host not found: {', '.join(unknown)}"))
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
