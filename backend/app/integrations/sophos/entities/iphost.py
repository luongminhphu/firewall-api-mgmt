"""IPHost: đọc / tạo (đơn lẻ hoặc gộp có transactionid) / xóa object do app tạo."""
from __future__ import annotations

import logging

from ....core.config import settings
from ..client import OpResult, SophosError
from .. import policy
from ..xmlutil import _as_list, _esc

log = logging.getLogger("sophos")


class IPHostMixin:
    @staticmethod
    def _host_dict(h: dict) -> dict:
        return {
            "name": h.get("Name"),
            "host_type": h.get("HostType") or "",
            "ip_address": h.get("IPAddress") or "",
            "subnet": h.get("Subnet") or "",
            "start_ip": h.get("StartIPAddress") or "",
            "end_ip": h.get("EndIPAddress") or "",
            "description": h.get("Description") or "",
        }

    def get_hosts(self, names: list[str] | None = None, timeout: int | None = None) -> list[dict]:
        """Đọc TOÀN BỘ IP Host trên firewall rồi lọc theo `names` (nặng với firewall nhiều object).

        Chỉ dùng cho lượt quét đầy đủ chạy nền (kèm timeout dài) hoặc trường hợp hiếm cần tra theo địa chỉ.
        Thao tác tương tác dùng `get_host` / `service.resolve_hosts`.
        """
        data = self._post("<Get><IPHost></IPHost></Get>", timeout=timeout)
        wanted = set(names or [])
        out = []
        for h in _as_list(data.get("IPHost")):
            if not isinstance(h, dict) or not h.get("Name"):
                continue
            if wanted and h["Name"] not in wanted:
                continue
            out.append(self._host_dict(h))
        return out

    def get_host(self, name: str) -> dict | None:
        """Đọc đúng một IP Host theo tên (Filter Name =) — nhẹ, không phụ thuộc số object trên firewall."""
        inner = (
            "<Get><IPHost><Filter>"
            f'<key name="Name" criteria="=">{_esc(name)}</key>'
            "</Filter></IPHost></Get>"
        )
        try:
            data = self._post(inner)
        except SophosError as exc:
            if exc.code == "526":
                return None
            raise
        for h in _as_list(data.get("IPHost")):
            if isinstance(h, dict) and h.get("Name") == name:
                return self._host_dict(h)
        return None

    # ------------------------------------------------------------ write: host
    @staticmethod
    def _iphost_body(name: str, kind: str, value: str, description: str = "") -> str:
        if kind == "Network":
            import ipaddress

            net = ipaddress.ip_network(value, strict=False)
            body = (
                f"<Name>{_esc(name)}</Name><IPFamily>IPv4</IPFamily>"
                f"<HostType>Network</HostType>"
                f"<IPAddress>{net.network_address}</IPAddress>"
                f"<Subnet>{net.netmask}</Subnet>"
            )
        else:
            body = (
                f"<Name>{_esc(name)}</Name><IPFamily>IPv4</IPFamily>"
                f"<HostType>IP</HostType><IPAddress>{_esc(value)}</IPAddress>"
            )
        if description:
            body += f"<Description>{_esc(description[:255])}</Description>"
        return body

    def add_ip_host(self, name: str, kind: str, value: str, description: str = "") -> OpResult:
        """Tạo IP Host. kind = IP | Network. value = '1.2.3.4' hoặc '1.2.3.0/24'."""
        body = self._iphost_body(name, kind, value, description)
        data = self._post(f'<Set operation="add"><IPHost>{body}</IPHost></Set>')
        return self._entity_status(data, "IPHost")

    def add_ip_hosts(self, items: list[tuple[str, str, str]], description: str = "",
                     batch_size: int | None = None) -> list[OpResult]:
        """Tạo nhiều IP Host trong ít lệnh nhất: mỗi lệnh `<Set operation="add">` chứa tối đa
        `batch_size` entity, mỗi entity gắn `transactionid` để ghép đúng kết quả (Sophos trả về
        một `<IPHost transactionid="…"><Status/></IPHost>` cho từng entity).

        `items` = [(name, kind, value)]. Trả list OpResult cùng thứ tự với `items`.
        Phản hồi không ghép được (firmware lạ) → tự chuyển sang tạo từng object, không đoán bừa.
        """
        size = max(1, batch_size or settings.SOPHOS_BATCH_SIZE)
        if size == 1:
            return [self.add_ip_host(n, k, v, description) for n, k, v in items]
        out: list[OpResult] = []
        for start in range(0, len(items), size):
            chunk = items[start:start + size]
            body = "".join(
                f'<IPHost transactionid="t{i}">{self._iphost_body(n, k, v, description)}</IPHost>'
                for i, (n, k, v) in enumerate(chunk)
            )
            data = self._post(f'<Set operation="add">{body}</Set>')
            mapped = self._batch_status(data, "IPHost", len(chunk))
            if mapped is None:
                log.warning("Phản hồi batch IPHost không ghép được (%d entity) — tạo từng object", len(chunk))
                mapped = [self.add_ip_host(n, k, v, description) for n, k, v in chunk]
            out.extend(mapped)
        return out

    @classmethod
    def _batch_status(cls, data: dict, tag: str, n: int) -> list[OpResult] | None:
        """Ghép Status theo transactionid ("t0".."tN"); không có id thì theo thứ tự nếu đủ số lượng."""
        nodes = [x for x in _as_list(data.get(tag)) if isinstance(x, dict)]
        by_id: dict[int, OpResult] = {}
        for node in nodes:
            tid = str(node.get("@transactionid") or "")
            if tid.startswith("t") and tid[1:].isdigit():
                by_id[int(tid[1:])] = cls._entity_status({tag: node}, tag)
        if len(by_id) == n and set(by_id) == set(range(n)):
            return [by_id[i] for i in range(n)]
        if len(nodes) == n:
            return [cls._entity_status({tag: node}, tag) for node in nodes]
        return None

    def delete_ip_host(self, name: str, actual_value: str | None = None) -> OpResult:
        # Chỉ được xóa IP Host do app tạo — quyết định nằm ở policy.py
        policy.check_remove_iphost(name, actual_value)
        data = self._post(f"<Remove><IPHost><Name>{_esc(name)}</Name></IPHost></Remove>")
        return self._entity_status(data, "IPHost")
