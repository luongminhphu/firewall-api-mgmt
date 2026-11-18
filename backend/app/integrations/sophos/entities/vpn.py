"""Đọc tài khoản / nhóm / chính sách VPN (CHỈ ĐỌC — mọi thao tác ghi bị policy.py chặn).

Kết quả đã qua `sanitize` (allowlist trường): không bao giờ chứa mật khẩu, hash, khóa chia sẻ.
"""
from __future__ import annotations

from ..client import SophosError
from .. import sanitize
from ..xmlutil import _as_list


class VPNReadMixin:
    def _get_all(self, entity: str, timeout: int | None = None) -> list[dict]:
        """`<Get><Entity/></Get>` → danh sách node thô (chỉ dùng nội bộ, không trả ra ngoài lớp này)."""
        try:
            data = self._post(f"<Get><{entity}></{entity}></Get>", timeout=timeout)
        except SophosError as exc:
            if exc.code == "526":  # Number of records Zero
                return []
            raise
        nodes = [x for x in _as_list(data.get(entity)) if isinstance(x, dict)]
        # Phản hồi "không có bản ghi" dạng <Entity><Status code="526">…</Status></Entity>
        return [x for x in nodes if not (set(x) <= {"@transactionid", "Status"})]

    def get_users(self, timeout: int | None = None) -> list[dict]:
        return [u for u in (sanitize.user(n) for n in self._get_all("User", timeout)) if u["username"]]

    def get_user_groups(self, timeout: int | None = None) -> list[dict]:
        return [g for g in (sanitize.user_group(n) for n in self._get_all("UserGroup", timeout)) if g["name"]]

    def get_sslvpn_policies(self, timeout: int | None = None) -> list[dict]:
        return [p for p in (sanitize.sslvpn_policy(n) for n in self._get_all("SSLVPNPolicy", timeout)) if p["name"]]

    def get_ipsec_connections(self, timeout: int | None = None) -> list[dict]:
        return [c for c in (sanitize.ipsec_connection(n) for n in self._get_all("VPNIPSecConnection", timeout))
                if c["name"]]
