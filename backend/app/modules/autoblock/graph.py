"""Client Microsoft Graph tối thiểu: token client-credentials + đọc tin nhắn của MỘT group chat (chỉ đọc).

Quyền cần (application): ChatMessage.Read.Chat (RSC — cấp riêng cho group chat đó, khuyến nghị) hoặc Chat.Read.All.
App không gửi gì lên Teams, không đọc chat nào khác ngoài chat_id đã cấu hình.
"""
from __future__ import annotations

import datetime as dt
import threading
import time
from urllib.parse import quote

import httpx

from ...core.config import settings
from ...core.security import decrypt

_tokens: dict[tuple, tuple[str, float]] = {}
_guard = threading.Lock()
TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class GraphError(Exception):
    pass


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, verify=settings.GRAPH_VERIFY_TLS)


def token(cfg: dict) -> str:
    key = (cfg["tenant_id"], cfg["client_id"], cfg["secret_enc"])
    with _guard:
        hit = _tokens.get(key)
        if hit and hit[1] > time.time() + 60:
            return hit[0]
    url = f"{settings.GRAPH_LOGIN_URL}/{quote(cfg['tenant_id'])}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": cfg["client_id"],
            "client_secret": decrypt(cfg["secret_enc"]), "scope": "https://graph.microsoft.com/.default"}
    try:
        with _client() as c:
            r = c.post(url, data=data)
    except httpx.HTTPError as exc:
        raise GraphError(f"Không kết nối được Entra ID ({type(exc).__name__})") from exc
    if r.status_code != 200:
        try:
            err = r.json().get("error_description", "")[:200]
        except ValueError:
            err = ""
        raise GraphError(f"Entra ID từ chối cấp token ({r.status_code}) {err}".strip())
    j = r.json()
    with _guard:
        _tokens[key] = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
    return j["access_token"]


def _parse_ts(v: str | None) -> dt.datetime | None:
    if not v:
        return None
    return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))


def _iso_z(t: dt.datetime) -> str:
    """Định dạng mốc thời gian như Graph trả về (UTC, mili giây): 2026-11-18T17:41:35.757Z."""
    t = t.astimezone(dt.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def changed_since(cfg: dict, since: dt.datetime, *, max_pages: int = 20) -> tuple[list[dict], bool, bool]:
    """Tin mới / vừa thay đổi SAU mốc `since` — LỌC PHÍA MICROSOFT GRAPH, không đọc lại lịch sử chat.

    GET /chats/{id}/messages?$filter=lastModifiedDateTime gt {since}&$orderby=lastModifiedDateTime desc&$top=50
    (Graph chỉ hỗ trợ lọc theo lastModifiedDateTime với `gt`, và phải đi kèm orderby cùng trường.)
    Chu kỳ không có tin mới → Graph trả 0 tin. Tenant không nhận bộ lọc (400) → quay về đọc theo createdDateTime.
    Trả (tin cũ → mới theo createdDateTime, truncated = còn tin chưa đọc hết sau max_pages, filtered = đã lọc server).
    """
    base = f"{settings.GRAPH_BASE_URL}/chats/{quote(cfg['chat_id'], safe='')}/messages"
    url = (f"{base}?$top=50&$orderby=lastModifiedDateTime%20desc"
           f"&$filter=lastModifiedDateTime%20gt%20{_iso_z(since)}")
    try:
        msgs, truncated = _read(cfg, url, since, "lastModifiedDateTime", max_pages)
        return msgs, truncated, True
    except _FilterRejected:
        msgs, truncated = _read(cfg, f"{base}?$top=50&$orderby=createdDateTime%20desc", since, "createdDateTime",
                                max_pages)
        return msgs, truncated, False


class _FilterRejected(Exception):
    pass


def _read(cfg: dict, url: str, since: dt.datetime, field: str, max_pages: int) -> tuple[list[dict], bool]:
    tok = token(cfg)
    out: list[dict] = []
    truncated = False
    with _client() as c:
        for page in range(max_pages):
            try:
                r = c.get(url, headers={"Authorization": f"Bearer {tok}"})
            except httpx.HTTPError as exc:
                raise GraphError(f"Không kết nối được Microsoft Graph ({type(exc).__name__})") from exc
            if r.status_code == 403:
                raise GraphError("Graph từ chối (403): app chưa được cấp quyền đọc group chat này "
                                 "(ChatMessage.Read.Chat / Chat.Read.All)")
            if r.status_code == 404:
                raise GraphError("Không tìm thấy group chat (404) — kiểm tra Chat ID")
            if r.status_code == 400 and "$filter" in url and page == 0:
                raise _FilterRejected()
            if r.status_code != 200:
                raise GraphError(f"Graph lỗi {r.status_code}")
            j = r.json()
            stop = False
            for m in j.get("value", []):
                t = _parse_ts(m.get(field)) or _parse_ts(m.get("createdDateTime"))
                if t is None or t <= since:  # phòng hờ: server đã lọc, app vẫn kiểm lại
                    stop = True
                    continue
                out.append(m)
            url = j.get("@odata.nextLink")
            if stop or not url:
                break
        else:
            truncated = bool(url)
    out.sort(key=lambda m: m.get("createdDateTime") or "")
    return out, truncated


def list_messages(cfg: dict, since: dt.datetime, *, max_pages: int = 5) -> list[dict]:
    """Tin TẠO sau `since` (dùng cho Kiểm tra kết nối — đọc thử, không xử lý)."""
    base = f"{settings.GRAPH_BASE_URL}/chats/{quote(cfg['chat_id'], safe='')}/messages"
    return _read(cfg, f"{base}?$top=50&$orderby=createdDateTime%20desc", since, "createdDateTime", max_pages)[0]
