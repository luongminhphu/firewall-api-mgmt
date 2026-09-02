"""Client XML API của Sophos Firewall (SFOS).

Endpoint: https://<firewall>:<admin-https-port>/webconsole/APIController
Payload gửi qua form field `reqxml`.
Tham khảo: docs.sophos.com/nsg/sophos-firewall/*/api/apiContentPage.html
"""
from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from typing import Any

import httpx
import xmltodict

log = logging.getLogger("sophos")

# Mã lỗi đặc thù ở tầng request (không nằm trong entity)
ERR_API_DISABLED = "532"  # API access chưa được bật
ERR_IP_NOT_ALLOWED = "534"  # IP nguồn chưa nằm trong Allowed IP của API access

STATUS_TEXT = {
    "200": "Áp dụng cấu hình thành công",
    "202": "Cập nhật thành công",
    "500": "Không thực hiện được trên đối tượng",
    "501": "Tham số cấu hình không hợp lệ",
    "502": "Đối tượng cùng tên đã tồn tại",
    "503": "Đối tượng cùng tham số đã tồn tại",
    "521": "XML request không tương thích API version",
    "526": "Đối tượng không tồn tại",
    "532": "API access chưa được bật trên firewall",
    "534": "IP của máy chủ mini app chưa được thêm vào Allowed IP của API access",
    "599": "Tài khoản không có quyền thêm/sửa cấu hình",
}


class SophosError(Exception):
    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message


class SophosAuthError(SophosError):
    pass


@dataclass
class OpResult:
    ok: bool
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"ok": self.ok, "code": self.code, "message": self.message}


def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class SophosClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.url = f"https://{host}:{port}/webconsole/APIController"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # ------------------------------------------------------------------ core
    def _login_block(self) -> str:
        return (
            "<Login>"
            f"<Username>{_esc(self.username)}</Username>"
            f"<Password>{_esc(self.password)}</Password>"
            "</Login>"
        )

    def _post(self, inner_xml: str) -> dict:
        reqxml = f"<Request>{self._login_block()}{inner_xml}</Request>"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                resp = client.post(
                    self.url,
                    data={"reqxml": reqxml},
                    headers={"Accept": "application/xml"},
                )
        except httpx.ConnectError as exc:
            raise SophosError(f"Không kết nối được tới {self.url} ({exc})") from exc
        except httpx.TimeoutException as exc:
            raise SophosError(f"Hết thời gian chờ khi gọi {self.url}") from exc
        except httpx.HTTPError as exc:  # cert, proxy, ...
            raise SophosError(f"Lỗi HTTP khi gọi firewall: {exc}") from exc

        if resp.status_code != 200:
            raise SophosError(f"Firewall trả về HTTP {resp.status_code}")

        try:
            data = xmltodict.parse(resp.text).get("Response", {}) or {}
        except Exception as exc:  # noqa: BLE001
            raise SophosError(f"Không đọc được XML phản hồi: {exc}") from exc

        login = data.get("Login") or {}
        status = (login.get("status") or "").strip()
        # Sophos có typo "Authetication Successful" ở một số bản firmware.
        if status and not status.lower().startswith(("authetication successful", "authentication successful")):
            raise SophosAuthError(f"Đăng nhập firewall thất bại: {status}")

        top = data.get("Status")
        if isinstance(top, dict):
            code = str(top.get("@code", ""))
            text = top.get("#text", "")
            if code in (ERR_API_DISABLED, ERR_IP_NOT_ALLOWED):
                raise SophosError(STATUS_TEXT.get(code, text), code)
            if code and not code.startswith("2"):
                raise SophosError(f"{code}: {STATUS_TEXT.get(code, text)}", code)
        return data

    @staticmethod
    def _entity_status(data: dict, tag: str) -> OpResult:
        node = data.get(tag) or {}
        if isinstance(node, list):
            node = node[0]
        st = node.get("Status") if isinstance(node, dict) else None
        if isinstance(st, dict):
            code = str(st.get("@code", ""))
            text = st.get("#text") or STATUS_TEXT.get(code, "")
        elif isinstance(st, str):
            code, text = "200", st
        else:
            code, text = "", "Không có Status trong phản hồi"
        return OpResult(ok=code.startswith("2"), code=code, message=text or STATUS_TEXT.get(code, ""))

    # ------------------------------------------------------------------ probe
    def test_login(self) -> OpResult:
        """Kiểm tra đăng nhập + quyền đọc object."""
        self._post("<Get><IPHostGroup></IPHostGroup></Get>")
        return OpResult(True, "200", "Đăng nhập và gọi API thành công")

    # ------------------------------------------------------------- read: group
    def list_groups(self) -> list[dict]:
        data = self._post("<Get><IPHostGroup></IPHostGroup></Get>")
        groups = []
        for g in _as_list(data.get("IPHostGroup")):
            if not isinstance(g, dict) or not g.get("Name"):
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

    def get_hosts(self, names: list[str] | None = None) -> list[dict]:
        """Đọc chi tiết IP Host. Nếu `names` rỗng thì lấy toàn bộ."""
        inner = "<Get><IPHost></IPHost></Get>"
        data = self._post(inner)
        wanted = set(names or [])
        out = []
        for h in _as_list(data.get("IPHost")):
            if not isinstance(h, dict) or not h.get("Name"):
                continue
            if wanted and h["Name"] not in wanted:
                continue
            out.append(
                {
                    "name": h.get("Name"),
                    "host_type": h.get("HostType") or "",
                    "ip_address": h.get("IPAddress") or "",
                    "subnet": h.get("Subnet") or "",
                    "start_ip": h.get("StartIPAddress") or "",
                    "end_ip": h.get("EndIPAddress") or "",
                    "description": h.get("Description") or "",
                }
            )
        return out

    # ------------------------------------------------------------ write: host
    def add_ip_host(self, name: str, kind: str, value: str, description: str = "") -> OpResult:
        """Tạo IP Host. kind = IP | Network. value = '1.2.3.4' hoặc '1.2.3.0/24'."""
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
        data = self._post(f'<Set operation="add"><IPHost>{body}</IPHost></Set>')
        return self._entity_status(data, "IPHost")

    def delete_ip_host(self, name: str) -> OpResult:
        data = self._post(f"<Remove><IPHost><Name>{_esc(name)}</Name></IPHost></Remove>")
        return self._entity_status(data, "IPHost")

    # ----------------------------------------------------------- write: group
    def create_group(
        self, name: str, hosts: list[str], description: str = "", ip_family: str = "IPv4"
    ) -> OpResult:
        host_xml = "".join(f"<Host>{_esc(h)}</Host>" for h in hosts)
        body = (
            f"<Name>{_esc(name)}</Name>"
            f"<Description>{_esc(description or 'Tạo bởi SOC Rapid Block')}</Description>"
            f"<IPFamily>{ip_family}</IPFamily>"
            f"<HostList>{host_xml}</HostList>"
        )
        data = self._post(f'<Set operation="add"><IPHostGroup>{body}</IPHostGroup></Set>')
        return self._entity_status(data, "IPHostGroup")

    def set_group_hosts(
        self, name: str, hosts: list[str], description: str = "", ip_family: str = "IPv4"
    ) -> OpResult:
        """Ghi lại toàn bộ HostList của group (Sophos không có API add/remove từng phần tử)."""
        host_xml = "".join(f"<Host>{_esc(h)}</Host>" for h in hosts)
        body = (
            f"<Name>{_esc(name)}</Name>"
            f"<Description>{_esc(description or 'Quản lý bởi SOC Rapid Block')}</Description>"
            f"<IPFamily>{ip_family}</IPFamily>"
            f"<HostList>{host_xml}</HostList>"
        )
        data = self._post(f'<Set operation="update"><IPHostGroup>{body}</IPHostGroup></Set>')
        return self._entity_status(data, "IPHostGroup")
