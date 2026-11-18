"""Microsoft Graph + Entra token endpoint giả lập cho test tự động chặn (HTTP, không TLS).

Chạy: python mock/mock_graph.py --port 4470
- POST /{tenant}/oauth2/v2.0/token        client_credentials; client_secret phải là "graph-secret"
- GET  /v1.0/chats/{chat_id}/messages     tin mới → cũ, 50 tin/trang + @odata.nextLink; chat khác CHAT → 404
- POST /_post   {"sender_id","name","html","edited","deleted","type","minutes_ago"}  thêm tin vào chat
- POST /_workflow  webhook Teams Workflows giả lập (trả lời vào group chat) · GET /_workflow danh sách đã nhận ·
  POST /_workflow/fail?on=true  làm webhook lỗi 500 (kiểm thử thử lại)
- POST /_reset  xóa toàn bộ tin · GET /_calls  số lần gọi messages (kiểm tra chu kỳ đọc)
"""
from __future__ import annotations

import argparse
import datetime as dt
import uuid

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request

CHAT = "19:mockchat@thread.v2"
app = FastAPI()
MSGS: list[dict] = []
CALLS = {"messages": 0, "last_filter": "", "last_orderby": "", "returned": 0}
FILTER = {"reject": False}  # giả lập tenant không nhận $filter (400)
TENANT_DEFAULT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUPS: dict[str, dict] = {}  # id → {"name", "members": [{"id","displayName"}], "deny": bool}
WORKFLOW: list[dict] = []   # tin Teams Workflows đã nhận (webhook trả lời vào group chat)
WF = {"fail": False}


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@app.post("/{tenant}/oauth2/v2.0/token")
def token(tenant: str, client_id: str = Form(""), client_secret: str = Form(""), grant_type: str = Form("")):
    if client_secret != "graph-secret" or grant_type != "client_credentials":
        raise HTTPException(401, detail={"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"})
    return {"access_token": f"tok-{tenant}-{client_id}", "expires_in": 3600, "token_type": "Bearer"}


@app.get("/v1.0/chats/{chat_id}/messages")
def messages(chat_id: str, request: Request, skip: int = 0):
    """Hỗ trợ như Graph: $orderby=createdDateTime|lastModifiedDateTime desc, $filter=lastModifiedDateTime gt <ISO>."""
    if not request.headers.get("authorization", "").startswith("Bearer tok-"):
        raise HTTPException(401)
    if chat_id != CHAT:
        raise HTTPException(404)
    q = request.query_params
    flt, order = q.get("$filter", ""), q.get("$orderby", "createdDateTime desc")
    if flt and FILTER["reject"]:
        raise HTTPException(400, detail={"error": {"code": "BadRequest", "message": "Filter not supported"}})
    CALLS["messages"] += 1
    CALLS["last_filter"], CALLS["last_orderby"] = flt, order
    field = order.split()[0]
    rows = list(MSGS)
    if flt:
        f, op, val = flt.split(" ", 2)
        assert f == "lastModifiedDateTime" and op == "gt" and field == f, flt
        cut = dt.datetime.fromisoformat(val.replace("Z", "+00:00"))
        rows = [m for m in rows if dt.datetime.fromisoformat(m["lastModifiedDateTime"].replace("Z", "+00:00")) > cut]
    rows.sort(key=lambda m: m[field], reverse=True)
    page = rows[skip: skip + 50]
    CALLS["returned"] = len(page) if skip == 0 else CALLS["returned"] + len(page)
    out = {"value": page}
    if skip + 50 < len(rows):
        from urllib.parse import urlencode

        nxt = urlencode({**dict(q), "skip": skip + 50})
        out["@odata.nextLink"] = f"{str(request.base_url).rstrip('/')}/v1.0/chats/{chat_id}/messages?{nxt}"
    return out


@app.post("/_touch")
async def touch(request: Request):
    """Giả lập thả cảm xúc / sửa nhẹ: chỉ đổi lastModifiedDateTime (createdDateTime giữ nguyên)."""
    d = await request.json()
    for m in MSGS:
        if m["id"] == d["id"]:
            m["lastModifiedDateTime"] = _iso(dt.datetime.now(dt.timezone.utc))
            return m
    raise HTTPException(404)


@app.post("/_delete")
async def delete_msg(request: Request):
    """Giả lập người gửi XÓA tin: deletedDateTime + lastModifiedDateTime = bây giờ, nội dung rỗng (như Graph)."""
    d = await request.json()
    for m in MSGS:
        if m["id"] == d["id"]:
            now = _iso(dt.datetime.now(dt.timezone.utc))
            m.update(deletedDateTime=now, lastModifiedDateTime=now, body={"contentType": "html", "content": ""})
            return m
    raise HTTPException(404)


@app.post("/_edit")
async def edit_msg(request: Request):
    d = await request.json()
    for m in MSGS:
        if m["id"] == d["id"]:
            now = _iso(dt.datetime.now(dt.timezone.utc))
            m.update(lastEditedDateTime=now, lastModifiedDateTime=now, body={"contentType": "html", "content": d.get("html", "")})
            return m
    raise HTTPException(404)


@app.get("/v1.0/groups/{gid}")
def group(gid: str, request: Request):
    if not request.headers.get("authorization", "").startswith("Bearer tok-"):
        raise HTTPException(401)
    g = GROUPS.get(gid)
    if g is None:
        raise HTTPException(404)
    if g.get("deny"):
        raise HTTPException(403)
    return {"id": gid, "displayName": g["name"]}


@app.get("/v1.0/groups/{gid}/transitiveMembers/microsoft.graph.user")
def group_members(gid: str, request: Request):
    if not request.headers.get("authorization", "").startswith("Bearer tok-"):
        raise HTTPException(401)
    g = GROUPS.get(gid)
    if g is None:
        raise HTTPException(404)
    if g.get("deny"):
        raise HTTPException(403)
    CALLS["group_reads"] = CALLS.get("group_reads", 0) + 1
    return {"value": g["members"]}


@app.post("/_group")
async def set_group(request: Request):
    """{"id","name","members":[{"id","displayName"}],"deny":false} — tạo / thay nhóm Entra giả lập."""
    d = await request.json()
    GROUPS[d["id"]] = {"name": d.get("name", ""), "members": d.get("members", []), "deny": bool(d.get("deny"))}
    return GROUPS[d["id"]]


@app.post("/_filter")
def set_filter(reject: bool = False):
    FILTER["reject"] = reject
    return FILTER


@app.post("/_post")
async def post(request: Request):
    d = await request.json()
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=float(d.get("minutes_ago", 0)))
    m = {
        "id": d.get("id") or str(int(now.timestamp() * 1000)) + uuid.uuid4().hex[:4],
        "messageType": d.get("type", "message"),
        "createdDateTime": _iso(now),
        "lastModifiedDateTime": _iso(now),
        "lastEditedDateTime": _iso(now) if d.get("edited") else None,
        "deletedDateTime": _iso(now) if d.get("deleted") else None,
        "from": {"user": {"id": d.get("sender_id"), "displayName": d.get("name", ""),
                          "userIdentityType": d.get("identity_type", "aadUser"),
                          "tenantId": d.get("tenant_id", TENANT_DEFAULT)}} if d.get("sender_id") else None,
        "body": {"contentType": "html", "content": d.get("html", "")},
    }
    MSGS.append(m)
    return m


@app.post("/_workflow")
async def workflow(request: Request):
    if WF["fail"]:
        raise HTTPException(500)
    WORKFLOW.append(await request.json())
    return {"ok": True}


@app.get("/_workflow")
def workflow_list():
    return WORKFLOW


@app.post("/_workflow/fail")
def workflow_fail(on: bool = True):
    WF["fail"] = on
    return WF


@app.post("/_reset")
def reset():
    MSGS.clear()
    WORKFLOW.clear()
    WF["fail"] = False
    FILTER["reject"] = False
    GROUPS.clear()
    CALLS["messages"] = 0
    return {"ok": True}


@app.get("/_calls")
def calls():
    return CALLS


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4470)
    args = ap.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
