"""Cấu hình tự động chặn (app_settings['autoblock.settings']) + trạng thái bộ đọc (app_settings['autoblock.state']).

- Client secret của App registration mã hóa bằng MASTER_KEY, API không bao giờ trả lại (chỉ has_secret).
- Tài khoản SOC hợp lệ định danh bằng Object ID Entra (from.user.id trong Graph) — tên hiển thị có thể trùng / đổi.
- Công tắc khẩn cấp (auto_enabled): ai có quyền Write cũng TẮT được ngay (hướng an toàn); chỉ quản trị viên BẬT lại.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re

from sqlalchemy.orm import Session

from ...core.audit import audit
from ...core.config import settings
from ...core.errors import AppError
from ...core.models import AppSetting
from ...core.security import MasterKeyMissing, encrypt
from ..notify.smtp import parse_emails

KEY = "autoblock.settings"
STATE_KEY = "autoblock.state"
VN_TZ = dt.timezone(dt.timedelta(hours=7))
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
CHAT_ID = re.compile(r"^19:[A-Za-z0-9_\-.@:]{3,200}$")
DEFAULTS = {
    "enabled": False,          # bộ đọc tin Teams
    "auto_enabled": True,      # công tắc khẩn cấp: False = mọi lệnh chuyển sang chờ duyệt
    "tenant_id": "", "client_id": "", "secret_enc": "", "chat_id": "",
    "soc_senders": [],         # [{"id": "<object id>", "name": "..."}]
    "window_enabled": True,    # chỉ tự chặn trong lịch ngoài giờ; trong giờ hành chính → chờ duyệt
    "window_start": "18:00", "window_end": "08:00",   # ngoài giờ ngày thường (qua đêm)
    "weekend_full": True,      # thứ 7 + Chủ nhật: tự chặn cả ngày
    "holidays": [],            # [{"from": "2027-02-05", "to": "2027-02-11", "name": "Tết"}] — tự chặn cả ngày
    "hourly_limit": 20,
    "admin_emails": [],
    "firewall_ids": [],        # rỗng = mọi firewall đang bật
    # chu kỳ đọc tin (giây) — quản trị viên chỉnh trên giao diện; mặc định ban đầu từ AUTOBLOCK_POLL_SECONDS
    "poll_seconds": min(3600, max(60, settings.AUTOBLOCK_POLL_SECONDS or 300)),
    # Whitelist: lệnh chặn IP thuộc các danh sách này KHÔNG tự chặn → chờ quản trị viên Approve
    # Trả lời "INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>" vào group chat qua Teams Workflows (webhook)
    "reply_enabled": False, "reply_url_enc": "",
    "whitelists": [{"name": "HSC", "entries": []}, {"name": "Akamai", "entries": []},
                   {"name": "Đối tác", "entries": []}],
}
WL_MAX_LISTS, WL_MAX_ENTRIES = 20, 5000
POLL_MIN, POLL_MAX = 60, 3600


def _load(db: Session, key: str, defaults: dict) -> dict:
    cfg = json.loads(json.dumps(defaults))
    row = db.get(AppSetting, key)
    if row and row.value:
        try:
            cfg.update({k: v for k, v in json.loads(row.value).items() if k in defaults})
        except ValueError:
            pass
    return cfg


def _save(db: Session, key: str, value: dict, actor: str) -> None:
    row = db.get(AppSetting, key) or AppSetting(key=key)
    row.value = json.dumps(value, ensure_ascii=False)
    row.updated_by = actor[:120]
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.merge(row)
    db.flush()  # lưu nhiều lần trong cùng phiên (vd đổi Chat ID + bật lần đầu) không được INSERT trùng khóa


def raw(db: Session) -> dict:
    return _load(db, KEY, DEFAULTS)


def configured(cfg: dict) -> bool:
    return bool(cfg["tenant_id"] and cfg["client_id"] and cfg["secret_enc"] and cfg["chat_id"])


def get(db: Session) -> dict:
    cfg = raw(db)
    out = {k: v for k, v in cfg.items() if k not in ("secret_enc", "reply_url_enc")}
    out["has_secret"] = bool(cfg["secret_enc"])
    out["has_reply_url"] = bool(cfg["reply_url_enc"])
    out["reply_url_host"] = _reply_host(cfg)
    out["configured"] = configured(cfg)
    row = db.get(AppSetting, KEY)
    out["updated_by"] = row.updated_by if row else ""
    out["updated_at"] = row.updated_at.isoformat() if row and row.updated_at else None
    return out


def _guid(v: str, label: str) -> str:
    v = str(v or "").strip()
    if v and not GUID.match(v):
        raise AppError(400, f"{label} phải có dạng GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
    return v.lower()


def update(db: Session, data: dict, *, actor: str, client_ip: str) -> dict:
    cfg = raw(db)
    first_enable = False
    if data.get("tenant_id") is not None:
        cfg["tenant_id"] = _guid(data["tenant_id"], "Tenant ID")
    if data.get("client_id") is not None:
        cfg["client_id"] = _guid(data["client_id"], "Client ID")
    if data.get("chat_id") is not None:
        cid = str(data["chat_id"]).strip()
        if cid and not CHAT_ID.match(cid):
            raise AppError(400, "Chat ID không hợp lệ (dạng 19:…@thread.v2 — lấy từ link group chat Teams)")
        if cid != cfg["chat_id"]:
            reset_cursor(db)  # đổi group chat → chỉ đọc tin mới từ bây giờ, không xử lý lịch sử
        cfg["chat_id"] = cid
    if data.get("clear_secret"):
        cfg["secret_enc"] = ""
    elif data.get("client_secret"):
        try:
            cfg["secret_enc"] = encrypt(str(data["client_secret"]))
        except MasterKeyMissing as exc:
            raise AppError(400, str(exc)) from exc
    if data.get("soc_senders") is not None:
        senders, seen = [], set()
        for s in data["soc_senders"]:
            sid = _guid(s.get("id"), "Object ID tài khoản SOC")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            senders.append({"id": sid, "name": str(s.get("name") or "").strip()[:120]})
        cfg["soc_senders"] = senders[:50]
    for k in ("window_start", "window_end"):
        if data.get(k) is not None:
            if not HHMM.match(str(data[k])):
                raise AppError(400, "Giờ phải có dạng HH:MM (vd 18:00)")
            cfg[k] = str(data[k])
    if data.get("weekend_full") is not None:
        cfg["weekend_full"] = bool(data["weekend_full"])
    if data.get("holidays") is not None:
        cfg["holidays"] = parse_holidays(data["holidays"])
    if data.get("window_enabled") is not None:
        cfg["window_enabled"] = bool(data["window_enabled"])
    if data.get("hourly_limit") is not None:
        n = data["hourly_limit"]
        if not isinstance(n, int) or not 1 <= n <= 200:
            raise AppError(400, "Giới hạn số IP mỗi giờ phải từ 1 đến 200")
        cfg["hourly_limit"] = n
    if data.get("poll_seconds") is not None:
        n = data["poll_seconds"]
        if not isinstance(n, int) or not POLL_MIN <= n <= POLL_MAX:
            raise AppError(400, "Chu kỳ đọc tin phải từ 60 giây (1 phút) đến 3600 giây (60 phút)")
        cfg["poll_seconds"] = n
    if data.get("clear_reply_url"):
        cfg["reply_url_enc"] = ""
    elif data.get("reply_webhook_url"):
        url = str(data["reply_webhook_url"]).strip()
        if not valid_reply_url(url):
            raise AppError(400, "URL webhook phải là https://… (lấy từ Teams Workflows: Post to a chat when a "
                                "webhook request is received)")
        try:
            cfg["reply_url_enc"] = encrypt(url)
        except MasterKeyMissing as exc:
            raise AppError(400, str(exc)) from exc
    if data.get("reply_enabled") is not None:
        cfg["reply_enabled"] = bool(data["reply_enabled"])
    if cfg["reply_enabled"] and not cfg["reply_url_enc"]:
        raise AppError(400, "Cần nhập URL webhook của Teams Workflows trước khi bật trả lời vào group chat")
    if data.get("whitelists") is not None:
        cfg["whitelists"] = parse_whitelists(data["whitelists"])
    if data.get("admin_emails") is not None:
        cfg["admin_emails"] = parse_emails(data["admin_emails"])
    if data.get("firewall_ids") is not None:
        cfg["firewall_ids"] = sorted({int(i) for i in data["firewall_ids"]})
    if data.get("enabled") is not None:
        first_enable = bool(data["enabled"]) and not cfg["enabled"]
        cfg["enabled"] = bool(data["enabled"])
    if cfg["enabled"]:
        if not configured(cfg):
            raise AppError(400, "Cần nhập đủ Tenant ID, Client ID, Client secret và Chat ID trước khi bật")
        if not cfg["soc_senders"]:
            raise AppError(400, "Cần khai báo ít nhất một tài khoản SOC được phép gửi lệnh")
    if first_enable:
        reset_cursor(db)  # bật lần đầu / bật lại: chỉ xử lý tin gửi SAU thời điểm này
    _save(db, KEY, cfg, actor)
    audit(db, action="settings_cud", fw=None, target="autoblock", result="ok", actor=actor, client_ip=client_ip,
          message=(f"Tự động chặn: bộ đọc {'bật' if cfg['enabled'] else 'tắt'} · {len(cfg['soc_senders'])} tài khoản SOC"
                   f" · lịch {schedule_text(cfg)}"
                   f" · tối đa {cfg['hourly_limit']} IP/giờ · đọc mỗi {cfg['poll_seconds']} giây"
                   f" · whitelist {', '.join('%s (%d)' % (w['name'], len(w['entries'])) for w in cfg['whitelists'])}"))
    db.commit()
    return get(db)


def valid_reply_url(url: str) -> bool:
    """https://… (Power Automate / Teams Workflows). http chỉ cho localhost — dùng trong kiểm thử."""
    from urllib.parse import urlparse

    try:
        u = urlparse(url)
    except ValueError:
        return False
    if len(url) > 2000 or not u.hostname or any(ch in url for ch in "\r\n "):
        return False
    return u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"))


def _reply_host(cfg: dict) -> str:
    """Chỉ hiện tên máy của URL webhook (URL đầy đủ chứa chữ ký sig=… là bí mật)."""
    if not cfg.get("reply_url_enc"):
        return ""
    from urllib.parse import urlparse

    from ...core.security import decrypt

    try:
        return urlparse(decrypt(cfg["reply_url_enc"])).hostname or ""
    except Exception:  # noqa: BLE001 — MASTER_KEY đổi: không hiển thị được, không làm hỏng trang cấu hình
        return "(không giải mã được — nhập lại URL)"


def parse_whitelists(items) -> list[dict]:
    """[{name, entries: list hoặc chuỗi (phân cách xuống dòng , ; khoảng trắng; '#' = ghi chú)}] → chuẩn hóa IPv4/CIDR."""
    out, names = [], set()
    if not isinstance(items, list) or len(items) > WL_MAX_LISTS:
        raise AppError(400, f"Tối đa {WL_MAX_LISTS} danh sách whitelist")
    for it in items:
        name = str((it or {}).get("name") or "").strip()[:60]
        if not name:
            raise AppError(400, "Mỗi danh sách whitelist cần có tên")
        if name.lower() in names:
            raise AppError(400, f"Trùng tên danh sách whitelist: {name}")
        names.add(name.lower())
        raw = it.get("entries") or []
        if isinstance(raw, str):
            raw = [ln.split("#", 1)[0] for ln in raw.splitlines()]
            raw = [x for ln in raw for x in re.split(r"[,;\s]+", ln)]
        entries = []
        for v in raw:
            v = str(v).strip()
            if not v:
                continue
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError as exc:
                raise AppError(400, f"Whitelist '{name}': '{v[:60]}' không phải IPv4 / CIDR hợp lệ") from exc
            if net.version != 4:
                raise AppError(400, f"Whitelist '{name}': chỉ hỗ trợ IPv4 ('{v[:60]}')")
            e = str(net) if net.prefixlen < 32 else str(net.network_address)
            if e not in entries:
                entries.append(e)
        if len(entries) > WL_MAX_ENTRIES:
            raise AppError(400, f"Whitelist '{name}' vượt {WL_MAX_ENTRIES} dòng")
        out.append({"name": name, "entries": entries})
    return out


def whitelist_hit(cfg: dict, ip: str) -> tuple[str, str] | None:
    """IP thuộc whitelist nào → (tên danh sách, dòng khớp); không thuộc → None."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for wl in cfg.get("whitelists") or []:
        for e in wl.get("entries", []):
            try:
                if addr in ipaddress.ip_network(e, strict=False):
                    return wl["name"], e
            except ValueError:
                continue
    return None


def set_switch(db: Session, on: bool, *, actor: str, client_ip: str) -> dict:
    cfg = raw(db)
    cfg["auto_enabled"] = bool(on)
    _save(db, KEY, cfg, actor)
    audit(db, action="autoblock_switch", fw=None, target="autoblock", result="ok", actor=actor, client_ip=client_ip,
          message="BẬT tự động chặn" if on else "TẮT KHẨN CẤP tự động chặn — mọi lệnh chuyển sang chờ duyệt")
    db.commit()
    return get(db)


# ------------------------------------------------------------------ khung giờ
def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


HOLIDAYS_MAX = 100


def parse_holidays(items) -> list[dict]:
    """[{from, to?, name?}] (YYYY-MM-DD) → chuẩn hóa, sắp xếp; khoảng tối đa 31 ngày; bỏ ngày đã qua hơn 1 năm."""
    if not isinstance(items, list) or len(items) > HOLIDAYS_MAX:
        raise AppError(400, f"Tối đa {HOLIDAYS_MAX} ngày lễ")
    out = []
    for it in items:
        try:
            d1 = dt.date.fromisoformat(str((it or {}).get("from") or "")[:10])
            d2 = dt.date.fromisoformat(str(it.get("to") or it.get("from"))[:10])
        except ValueError as exc:
            raise AppError(400, "Ngày lễ phải có dạng YYYY-MM-DD") from exc
        if d2 < d1:
            raise AppError(400, f"Ngày lễ {d1:%d/%m/%Y}: ngày kết thúc trước ngày bắt đầu")
        if (d2 - d1).days > 31:
            raise AppError(400, "Mỗi đợt nghỉ lễ tối đa 31 ngày")
        if d2 < dt.date.today() - dt.timedelta(days=366):
            continue
        out.append({"from": d1.isoformat(), "to": d2.isoformat(), "name": str(it.get("name") or "").strip()[:80]})
    return sorted(out, key=lambda h: h["from"])


def _holiday(cfg: dict, day: dt.date) -> dict | None:
    for h in cfg.get("holidays") or []:
        if h["from"] <= day.isoformat() <= h["to"]:
            return h
    return None


def window_reason(cfg: dict, now: dt.datetime | None = None) -> str:
    """Lý do đang được TỰ CHẶN theo lịch (giờ VN): "" = trong giờ hành chính (lệnh chờ duyệt).

    Thứ tự: lịch tắt (24/7) · ngày lễ (cả ngày) · thứ 7 / Chủ nhật (cả ngày, nếu bật) · ngoài giờ ngày thường
    (start > end = qua đêm, vd 18:00–08:00; start == end = cả ngày). Đêm trước / sau ngày nghỉ vẫn theo khung ngoài giờ.
    """
    if not cfg.get("window_enabled"):
        return "24/7"
    t = (now or dt.datetime.now(dt.timezone.utc)).astimezone(VN_TZ)
    h = _holiday(cfg, t.date())
    if h:
        return f"Ngày lễ{': ' + h['name'] if h['name'] else ''}"
    if cfg.get("weekend_full", True) and t.weekday() >= 5:
        return "Cuối tuần"
    cur, s, e = t.hour * 60 + t.minute, _minutes(cfg["window_start"]), _minutes(cfg["window_end"])
    if s == e or (s <= cur < e if s < e else (cur >= s or cur < e)):
        return f"Ngoài giờ {cfg['window_start']}–{cfg['window_end']}"
    return ""


def in_window(cfg: dict, now: dt.datetime | None = None) -> bool:
    return bool(window_reason(cfg, now))


def schedule_text(cfg: dict) -> str:
    if not cfg.get("window_enabled"):
        return "24/7"
    parts = [f"ngày thường {cfg['window_start']}–{cfg['window_end']}"]
    if cfg.get("weekend_full", True):
        parts.append("cả ngày T7 & CN")
    if cfg.get("holidays"):
        parts.append(f"{len(cfg['holidays'])} đợt nghỉ lễ")
    return ", ".join(parts)


def off_hours_span(cfg: dict, now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
    """Ca ngoài giờ gần nhất (đang diễn ra hoặc vừa kết thúc), giờ VN — vd 18:00 thứ 6 → 08:00 thứ 2 khi bật cuối tuần.

    Lịch 24/7 → 24 giờ qua. Quét theo phút, tối đa 40 ngày (đủ cho đợt nghỉ lễ dài nhất 31 ngày + cuối tuần).
    """
    t = (now or dt.datetime.now(dt.timezone.utc)).astimezone(VN_TZ).replace(second=0, microsecond=0)
    if not cfg.get("window_enabled"):
        return t - dt.timedelta(hours=24), t + dt.timedelta(minutes=1)
    step, limit = dt.timedelta(minutes=1), 40 * 24 * 60
    cur = t
    if not in_window(cfg, cur):  # đang giờ hành chính → lùi về phút cuối của ca trước
        for _ in range(limit):
            cur -= step
            if in_window(cfg, cur):
                break
        else:
            return t - dt.timedelta(hours=24), t
    start = cur
    for _ in range(limit):
        if not in_window(cfg, start - step):
            break
        start -= step
    end = cur
    for _ in range(limit):
        end += step
        if not in_window(cfg, end):
            break
    return start, end


def night_shift(now: dt.datetime | None = None, cfg: dict | None = None) -> tuple[dt.datetime, dt.datetime]:
    """Tương thích: ca ngoài giờ theo lịch mặc định (18:00–08:00, cuối tuần cả ngày)."""
    return off_hours_span(cfg or DEFAULTS, now)


# ------------------------------------------------------------------ trạng thái
STATE_DEFAULTS = {"cursor": "", "start_at": "", "last_poll_at": "", "last_ok": None, "last_error": "", "breaker_tripped_at": "",
                  "breaker_reason": "", "seen_senders": {}, "digest_date": ""}


def state(db: Session) -> dict:
    return _load(db, STATE_KEY, STATE_DEFAULTS)


def save_state(db: Session, st: dict) -> None:
    _save(db, STATE_KEY, st, "autoblock")


def reset_cursor(db: Session) -> None:
    st = state(db)
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    st["cursor"] = st["start_at"] = now
    save_state(db, st)
