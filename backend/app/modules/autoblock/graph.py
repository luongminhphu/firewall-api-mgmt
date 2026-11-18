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


def list_messages(cfg: dict, since: dt.datetime, *, max_pages: int = 5) -> list[dict]:
    """Tin của group chat tạo SAU `since` (cũ → mới). Graph trả mới → cũ; dừng khi gặp tin cũ hơn `since`."""
    tok = token(cfg)
    url = (f"{settings.GRAPH_BASE_URL}/chats/{quote(cfg['chat_id'], safe='')}/messages"
           f"?$top=50&$orderby=createdDateTime%20desc")
    out: list[dict] = []
    with _client() as c:
        for _ in range(max_pages):
            try:
                r = c.get(url, headers={"Authorization": f"Bearer {tok}"})
            except httpx.HTTPError as exc:
                raise GraphError(f"Không kết nối được Microsoft Graph ({type(exc).__name__})") from exc
            if r.status_code == 403:
                raise GraphError("Graph từ chối (403): app chưa được cấp quyền đọc group chat này "
                                 "(ChatMessage.Read.Chat / Chat.Read.All)")
            if r.status_code == 404:
                raise GraphError("Không tìm thấy group chat (404) — kiểm tra Chat ID")
            if r.status_code != 200:
                raise GraphError(f"Graph lỗi {r.status_code}")
            j = r.json()
            stop = False
            for m in j.get("value", []):
                created = _parse_ts(m.get("createdDateTime"))
                if created is None or created <= since:
                    stop = True
                    continue
                out.append(m)
            url = j.get("@odata.nextLink")
            if stop or not url:
                break
    out.sort(key=lambda m: m.get("createdDateTime") or "")
    return out
