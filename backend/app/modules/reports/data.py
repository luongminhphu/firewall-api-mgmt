"""Tổng hợp số liệu báo cáo chặn IP trong N ngày gần nhất (7 / 14 / 30), giờ Việt Nam.

Nguồn:
  - group_changes (lịch sử thay đổi SCANPORT GROUP, có chuỗi băm): mỗi dòng change_type="add" là một lượt chặn
    một IP trên một firewall; "remove" / "drift_remove" sau đó = đã gỡ.
  - autoblock_requests + autoblock_messages: lệnh SOC gửi qua Teams, thời gian từ lúc SOC gửi tới lúc chặn xong.

Phương thức chặn:
  - "auto"   — app TỰ chặn từ lệnh SOC (tác nhân `autoblock`).
  - "manual" — con người thao tác: chặn tay (dán Teams / nhập tay / CSV) hoặc Approve lệnh SOC chờ duyệt.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.models import AutoBlockMessage, AutoBlockRequest, GroupChange

VN_TZ = dt.timezone(dt.timedelta(hours=7))
PERIODS = (7, 14, 30)   # mốc nhanh; ngoài ra chọn khoảng ngày bất kỳ trên lịch (tối đa MAX_DAYS)
MAX_DAYS = 366
METHOD_LABEL = {"manual": "Thủ công", "auto": "Tự động"}
SOURCE_LABEL = {"paste": "Dán từ Teams", "manual": "Nhập tay", "csv": "CSV / TXT", "teams-auto": "Lệnh SOC (Teams)",
                "": "—"}


def _utc(t: dt.datetime | None) -> dt.datetime | None:
    if t is None:
        return None
    return t.replace(tzinfo=dt.timezone.utc) if t.tzinfo is None else t.astimezone(dt.timezone.utc)


def vn(t: dt.datetime | None) -> dt.datetime | None:
    """Datetime giờ VN (có tz) — None giữ nguyên."""
    return _utc(t).astimezone(VN_TZ) if t else None


def fmt(t: dt.datetime | None) -> str:
    return vn(t).strftime("%d/%m/%Y %H:%M:%S") if t else ""


def fmt_dur(sec: float | None) -> str:
    if sec is None:
        return "—"
    sec = int(round(sec))
    if sec < 60:
        return f"{sec} giây"
    if sec < 3600:
        return f"{sec // 60} phút {sec % 60:02d} giây"
    return f"{sec // 3600} giờ {sec % 3600 // 60:02d} phút"


def period(days: int, now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
    """[00:00 của (hôm nay − days + 1), hiện tại] theo giờ VN — "7 ngày" gồm hôm nay và 6 ngày trước."""
    now_vn = (now or dt.datetime.now(dt.timezone.utc)).astimezone(VN_TZ)
    start = dt.datetime.combine(now_vn.date() - dt.timedelta(days=days - 1), dt.time(0, 0), VN_TZ)
    return start, now_vn


class RangeError(ValueError):
    pass


def resolve(days: int | None = None, date_from: str | None = None, date_to: str | None = None,
            now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime, int, str]:
    """Kỳ báo cáo → (bắt đầu, kết thúc, số ngày, nhãn). Có from/to (YYYY-MM-DD, chọn trên lịch) thì dùng khoảng đó:
    00:00 ngày đầu → 24:00 ngày cuối (hoặc hiện tại nếu ngày cuối là hôm nay); ngược lại dùng mốc 7 / 14 / 30 ngày."""
    now_vn = (now or dt.datetime.now(dt.timezone.utc)).astimezone(VN_TZ)
    if date_from or date_to:
        try:
            d1 = dt.date.fromisoformat(str(date_from or date_to)[:10])
            d2 = dt.date.fromisoformat(str(date_to or date_from)[:10])
        except ValueError as exc:
            raise RangeError("Ngày phải có dạng YYYY-MM-DD") from exc
        if d2 < d1:
            raise RangeError("Ngày kết thúc phải sau hoặc bằng ngày bắt đầu")
        if d1 > now_vn.date():
            raise RangeError("Ngày bắt đầu không được ở tương lai")
        d2 = min(d2, now_vn.date())
        n = (d2 - d1).days + 1
        if n > MAX_DAYS:
            raise RangeError(f"Khoảng báo cáo tối đa {MAX_DAYS} ngày")
        start = dt.datetime.combine(d1, dt.time(0, 0), VN_TZ)
        end = min(dt.datetime.combine(d2 + dt.timedelta(days=1), dt.time(0, 0), VN_TZ), now_vn)
        label = f"{d1:%d/%m/%Y}" if n == 1 else f"{d1:%d/%m/%Y} – {d2:%d/%m/%Y}"
        return start, end, n, label
    days = days or 7
    if days not in PERIODS:
        raise RangeError("Kỳ báo cáo chỉ nhận 7, 14, 30 ngày hoặc khoảng ngày chọn trên lịch")
    start, end = period(days, now)
    return start, end, days, f"{days} ngày gần nhất"


def method_of(ch: GroupChange) -> str:
    return "auto" if ch.actor == "autoblock" else "manual"


def source_of(ch: GroupChange) -> str:
    if ch.source == "teams-auto" and ch.actor != "autoblock":
        return "Duyệt lệnh SOC (Teams)"
    return SOURCE_LABEL.get(ch.source or "", ch.source)


def build(db: Session, days: int | None = 7, now: dt.datetime | None = None, *, date_from: str | None = None,
          date_to: str | None = None) -> dict:
    start, end, days, label = resolve(days, date_from, date_to, now)
    s_utc, e_utc = start.astimezone(dt.timezone.utc), end.astimezone(dt.timezone.utc)
    adds = list(db.scalars(select(GroupChange).where(GroupChange.change_type == "add", GroupChange.ts >= s_utc,
                                                     GroupChange.ts < e_utc).order_by(GroupChange.ts, GroupChange.id)))
    # mọi lần gỡ sau đầu kỳ (kể cả sửa ngoài app) — để biết IP còn đang bị chặn không
    removes = list(db.scalars(select(GroupChange).where(
        GroupChange.change_type.in_(("remove", "drift_remove")), GroupChange.ts >= s_utc).order_by(GroupChange.ts)))
    rm_by: dict[tuple, list[GroupChange]] = defaultdict(list)
    for r in removes:
        rm_by[(r.firewall_id, r.value)].append(r)

    entries = []
    for a in adds:
        later = next((r for r in rm_by[(a.firewall_id, a.value)] if _utc(r.ts) >= _utc(a.ts)), None)
        m = method_of(a)
        entries.append({
            "ts": vn(a.ts), "ip": a.value, "object": a.object_name, "firewall": a.firewall_name,
            "method": m, "method_label": METHOD_LABEL[m], "actor": a.actor,
            "actor_name": "Tự động chặn (Teams)" if m == "auto" else (a.actor_name or a.actor),
            "source": source_of(a), "reason": a.reason or "",
            "removed_at": vn(later.ts) if later else None,
            "removed_by": (later.actor_name or later.actor or "ngoài app") if later else "",
            "status": "Đã gỡ" if later else "Đang chặn",
        })

    # ---- theo IP (gộp nhiều firewall)
    by_ip: dict[str, dict] = {}
    for e in entries:
        d = by_ip.setdefault(e["ip"], {"ip": e["ip"], "first": e["ts"], "last": e["ts"], "methods": set(),
                                       "firewalls": [], "actors": [], "sources": [], "reason": e["reason"],
                                       "blocked_fw": 0, "count": 0})
        d["last"] = e["ts"]
        d["count"] += 1
        d["methods"].add(e["method"])
        for k, v in (("firewalls", e["firewall"]), ("actors", e["actor_name"]), ("sources", e["source"])):
            if v and v not in d[k]:
                d[k].append(v)
        if e["status"] == "Đang chặn":
            d["blocked_fw"] += 1
    ips = []
    for d in by_ip.values():
        meth = "auto" if d["methods"] == {"auto"} else "manual" if d["methods"] == {"manual"} else "mixed"
        ips.append({**d, "methods": sorted(d["methods"]), "method": meth,
                    "method_label": {"auto": "Tự động", "manual": "Thủ công", "mixed": "Thủ công + Tự động"}[meth],
                    "status": "Đang chặn" if d["blocked_fw"] else "Đã gỡ"})
    ips.sort(key=lambda x: x["first"], reverse=True)

    # ---- theo ngày (IP duy nhất trong ngày, theo phương thức)
    daily_sets: dict[dt.date, dict[str, set]] = {}
    for i in range(days):
        daily_sets[start.date() + dt.timedelta(days=i)] = {"manual": set(), "auto": set()}
    for e in entries:
        daily_sets.setdefault(e["ts"].date(), {"manual": set(), "auto": set()})[e["method"]].add(e["ip"])
    daily = [{"date": d, "manual": len(v["manual"]), "auto": len(v["auto"]),
              "total": len(v["manual"] | v["auto"])} for d, v in sorted(daily_sets.items())]

    # ---- theo người thực hiện
    actor_ips: dict[str, set] = defaultdict(set)
    actor_n: Counter = Counter()
    actor_m: dict[str, str] = {}
    for e in entries:
        actor_ips[e["actor_name"]].add(e["ip"])
        actor_n[e["actor_name"]] += 1
        actor_m[e["actor_name"]] = e["method_label"]
    actors = sorted(({"actor": k, "method_label": actor_m[k], "ips": len(v), "actions": actor_n[k]}
                     for k, v in actor_ips.items()), key=lambda x: (-x["ips"], x["actor"]))

    # ---- tự động chặn (lệnh SOC qua Teams)
    reqs = list(db.scalars(select(AutoBlockRequest).where(AutoBlockRequest.created_at >= s_utc,
                                                          AutoBlockRequest.created_at < e_utc)))
    msg_ts = {}
    if reqs:
        ids = {r.message_id for r in reqs}
        msg_ts = {m.id: _utc(m.created_at) for m in db.scalars(select(AutoBlockMessage).where(AutoBlockMessage.id.in_(ids)))}
    lat = [(_utc(r.blocked_at) - msg_ts[r.message_id]).total_seconds() for r in reqs
           if r.mode == "auto" and r.blocked_at and msg_ts.get(r.message_id)]
    lat = [x for x in lat if x >= 0]
    st = Counter(r.status for r in reqs)
    ab = {
        "requests": len(reqs),
        "auto": sum(1 for r in reqs if r.mode == "auto"),
        "approved": sum(1 for r in reqs if r.mode == "pending" and r.decided_by and r.status in ("blocked", "unblocked")),
        "pending": st.get("pending", 0), "rejected": st.get("rejected", 0),
        "invalid": st.get("invalid", 0), "duplicate": st.get("duplicate", 0),
        "whitelist": sum(1 for r in reqs if r.whitelist), "failed": st.get("failed", 0),
        "latency_avg": (sum(lat) / len(lat)) if lat else None,
        "latency_median": median(lat) if lat else None,
        "latency_max": max(lat) if lat else None,
    }

    uniq_manual = {e["ip"] for e in entries if e["method"] == "manual"}
    uniq_auto = {e["ip"] for e in entries if e["method"] == "auto"}
    summary = {
        "unique_ips": len(by_ip), "actions": len(entries),
        "manual_ips": len(uniq_manual), "auto_ips": len(uniq_auto),
        "manual_actions": sum(1 for e in entries if e["method"] == "manual"),
        "auto_actions": sum(1 for e in entries if e["method"] == "auto"),
        "firewalls": len({e["firewall"] for e in entries}),
        "still_blocked": sum(1 for i in ips if i["status"] == "Đang chặn"),
        "removed_in_period": sum(1 for r in removes if _utc(r.ts) < e_utc),
        "auto_share": round(100 * len(uniq_auto) / len(by_ip)) if by_ip else 0,
    }
    return {"days": days, "label": label, "start": start, "end": end, "summary": summary, "daily": daily, "actors": actors,
            "autoblock": ab, "ips": ips, "entries": entries}


def to_json(rep: dict, limit: int = 1000) -> dict:
    """Bản JSON cho giao diện xem trước (danh sách IP tối đa `limit`)."""
    iso = lambda t: t.isoformat() if t else None  # noqa: E731
    ab = dict(rep["autoblock"])
    for k in ("latency_avg", "latency_median", "latency_max"):
        ab[k + "_text"] = fmt_dur(ab[k])
    return {
        "days": rep["days"], "label": rep["label"], "start": iso(rep["start"]), "end": iso(rep["end"]),
        "summary": rep["summary"],
        "executive": executive(rep),
        "daily": [{**d, "date": d["date"].isoformat()} for d in rep["daily"]],
        "actors": rep["actors"], "autoblock": ab,
        "ips": [{"ip": i["ip"], "first": iso(i["first"]), "last": iso(i["last"]), "method": i["method"],
                 "method_label": i["method_label"], "firewalls": i["firewalls"], "actors": i["actors"],
                 "sources": i["sources"], "reason": i["reason"], "status": i["status"], "count": i["count"]}
                for i in rep["ips"][:limit]],
        "ips_total": len(rep["ips"]),
    }


def executive(rep: dict) -> dict:
    """Tóm tắt điều hành: câu tổng quan + nhận định nổi bật + điểm cần lưu ý, sinh từ số liệu (không đoán)."""
    s, ab, days = rep["summary"], rep["autoblock"], rep["days"]
    last = rep["end"] - dt.timedelta(microseconds=1)
    period_txt = f"{rep['start']:%d/%m/%Y} – {last:%d/%m/%Y}"
    if not s["unique_ips"]:
        headline = f"Trong {days} ngày ({period_txt}) không có IP nào bị đưa vào nhóm chặn SCANPORT GROUP."
    else:
        headline = (f"Trong {days} ngày ({period_txt}) đã chặn {s['unique_ips']} IP ({s['actions']} lượt trên "
                    f"{s['firewalls']} firewall): {s['manual_ips']} IP chặn thủ công và {s['auto_ips']} IP tự động chặn "
                    f"theo lệnh SOC — tự động chiếm {s['auto_share']}%.")
    highlights = []
    busy = max(rep["daily"], key=lambda d: d["total"], default=None)
    if busy and busy["total"]:
        highlights.append(f"Ngày cao điểm {busy['date']:%d/%m/%Y}: {busy['total']} IP "
                          f"({busy['manual']} thủ công, {busy['auto']} tự động).")
    if s["unique_ips"]:
        avg = s["unique_ips"] / days
        highlights.append(f"Trung bình {avg:.1f} IP/ngày; {s['still_blocked']} IP vẫn đang bị chặn cuối kỳ, "
                          f"{s['removed_in_period']} lượt gỡ chặn trong kỳ.")
    if ab["requests"]:
        highlights.append(f"Nhận {ab['requests']} lệnh SOC qua Teams: {ab['auto']} tự chặn ngay, {ab['approved']} "
                          f"được duyệt sau khi chờ, {ab['rejected']} bị từ chối.")
    if ab["latency_avg"] is not None:
        highlights.append(f"Thời gian từ lúc SOC gửi lệnh tới lúc chặn xong: trung bình {fmt_dur(ab['latency_avg'])}, "
                          f"lâu nhất {fmt_dur(ab['latency_max'])}.")
    if rep["actors"]:
        top = rep["actors"][0]
        highlights.append(f"Tác nhân chặn nhiều nhất: {top['actor']} ({top['ips']} IP).")
    attention = []
    if ab["pending"]:
        attention.append(f"{ab['pending']} lệnh SOC đang chờ duyệt — cần xử lý ở tab Tự động chặn.")
    if ab["whitelist"]:
        attention.append(f"{ab['whitelist']} lệnh đề xuất chặn IP thuộc whitelist (HSC / Akamai / đối tác) — "
                         "rà soát nguồn cảnh báo để tránh chặn nhầm.")
    if ab["failed"]:
        attention.append(f"{ab['failed']} lệnh tự động chặn lỗi trên firewall — kiểm tra kết nối / quyền API.")
    if ab["invalid"]:
        attention.append(f"{ab['invalid']} lệnh không hợp lệ (IP nội bộ, sai định dạng) — nhắc SOC đúng cú pháp.")
    if s["unique_ips"] and s["auto_share"] == 0 and not ab["requests"]:
        attention.append("Chưa có lệnh nào đi qua tự động chặn — cân nhắc bật để rút ngắn thời gian phản hồi ban đêm.")
    if not attention:
        attention.append("Không có điểm bất thường cần xử lý.")
    return {"headline": headline, "highlights": highlights, "attention": attention}
