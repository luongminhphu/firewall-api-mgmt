"""IPHostGroup: đọc group, ghi lại HostList của group cố định."""
from __future__ import annotations

from ..client import OpResult, SophosError
from ..policy import BLOCK_GROUP, GroupPolicyError
from ..xmlutil import _as_list, _esc, build_iphostgroup_xml


class IPHostGroupMixin:
    # ------------------------------------------------------------- read: group
    def list_groups(self) -> list[dict]:
        data = self._post("<Get><IPHostGroup></IPHostGroup></Get>")
        groups = []
        for g in _as_list(data.get("IPHostGroup")):
            if not isinstance(g, dict) or g.get("Name") != BLOCK_GROUP:
                continue
            hosts = _as_list((g.get("HostList") or {}).get("Host")) if g.get("HostList") else []
            groups.append(
                {
                    "name": g.get("Name"),
                    "description": g.get("Description") or "",
                    "ip_family": g.get("IPFamily") or "IPv4",
                    "hosts": [h for h in hosts if isinstance(h, str)],
                }
            )
        return groups

    def get_group(self, name: str) -> dict | None:
        inner = (
            "<Get><IPHostGroup><Filter>"
            f'<key name="Name" criteria="=">{_esc(name)}</key>'
            "</Filter></IPHostGroup></Get>"
        )
        try:
            data = self._post(inner)
        except SophosError as exc:
            if exc.code == "526":
                return None
            raise
        for g in _as_list(data.get("IPHostGroup")):
            if isinstance(g, dict) and g.get("Name") == name:
                hosts = _as_list((g.get("HostList") or {}).get("Host")) if g.get("HostList") else []
                return {
                    "name": g.get("Name"),
                    "description": g.get("Description") or "",
                    "ip_family": g.get("IPFamily") or "IPv4",
                    "hosts": [h for h in hosts if isinstance(h, str)],
                }
        return None

    # ----------------------------------------------------------- write: group
    # Không có hàm tạo group: app không được phép tạo IP Host Group mới trên firewall.

    def set_group_hosts(
        self, name: str, hosts: list[str], description: str = "", ip_family: str = "IPv4"
    ) -> OpResult:
        """Ghi lại toàn bộ HostList của group cố định (Sophos không có API add/remove từng phần tử).

        Giữ nguyên Description và IPFamily hiện có của group để không làm thay đổi cấu hình ngoài ý muốn.
        """
        if name != BLOCK_GROUP:  # phòng thủ nhiều lớp — không phụ thuộc lớp API
            raise GroupPolicyError(f"Chỉ được cập nhật IP Host Group '{BLOCK_GROUP}'")
        body = build_iphostgroup_xml(name, hosts, description, ip_family)
        data = self._post(f'<Set operation="update">{body}</Set>')
        return self._entity_status(data, "IPHostGroup")
