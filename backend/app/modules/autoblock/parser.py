"""Bóc lệnh chặn từ tin nhắn Teams.

Cú pháp DUY NHẤT được nhận (đã thống nhất với SOC, viết IN HOA để dễ nhận dạng):

    ĐỀ XUẤT CỦA SOC: BLOCK IP 195.178.110.102

- Một dòng chỉ chứa đúng lệnh này; một tin có thể có nhiều dòng lệnh.
- Phân biệt hoa/thường: "Đề xuất của SOC: block ip …" KHÔNG được nhận (tránh bắt nhầm câu trong đoạn phân tích).
- Chỉ một địa chỉ IPv4 đơn (/32) mỗi dòng — không nhận CIDR, dải, IPv6, tên miền.
- Chấp nhận khác biệt vô hại: khoảng trắng thừa, dấu cách không ngắt (&nbsp;), Unicode dựng sẵn / tổ hợp (NFC/NFD).
"""
from __future__ import annotations

import html
import ipaddress
import re
import unicodedata

PREFIX = "ĐỀ XUẤT CỦA SOC: BLOCK IP"
_LINE = re.compile(r"^ĐỀ XUẤT CỦA SOC\s*:\s*BLOCK IP\s+(\S+)$")
_BREAKS = re.compile(r"<\s*(br|/p|/div|/li|/h[1-6]|/tr)\s*/?\s*>", re.I)
_TAGS = re.compile(r"<[^>]+>")


def html_to_text(content: str, content_type: str = "html") -> str:
    """Nội dung tin Graph (thường là HTML) → văn bản thuần, giữ xuống dòng."""
    s = content or ""
    if (content_type or "").lower() == "html":
        s = _BREAKS.sub("\n", s)
        s = _TAGS.sub("", s)
        s = html.unescape(s)
    s = unicodedata.normalize("NFC", s).replace(" ", " ").replace("​", "")
    return s


def find_commands(text: str) -> list[dict]:
    """Trả [{"raw": dòng lệnh, "value": phần sau BLOCK IP, "ip": IPv4 hợp lệ hoặc "", "error": ...}] theo thứ tự."""
    out = []
    text = unicodedata.normalize("NFC", text or "").replace("\u00a0", " ")
    for line in text.splitlines():
        line = re.sub(r"[ \t]+", " ", line.strip())
        m = _LINE.match(line)
        if not m:
            continue
        val = m.group(1)
        item = {"raw": line[:200], "value": val[:64], "ip": "", "error": ""}
        try:
            ip = ipaddress.IPv4Address(val)
            item["ip"] = str(ip)
        except ValueError:
            item["error"] = "Không phải một địa chỉ IPv4 đơn (lệnh tự động không nhận CIDR / dải / tên miền)"
        out.append(item)
    return out
