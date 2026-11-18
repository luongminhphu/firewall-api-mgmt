"""Client XML API của Sophos Firewall (SFOS).

Endpoint: https://<firewall>:<admin-https-port>/webconsole/APIController
Payload gửi qua form field `reqxml`.
Tham khảo: docs.sophos.com/nsg/sophos-firewall/22.0/api/
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
import xmltodict

from . import policy
from .xmlutil import _esc

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


class BaseClient:
    """Kết nối + đăng nhập + gửi một lệnh XML; mọi lệnh đi qua `policy.check_request` trước khi gửi."""
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout: int = 30,
        connect_timeout: int | None = None,
    ):
        self.url = f"https://{host}:{port}/webconsole/APIController"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.connect_timeout = min(connect_timeout or timeout, timeout)
        self._http: httpx.Client | None = None

    # ------------------------------------------------------------- lifecycle
    # Một kết nối HTTPS (keep-alive) dùng lại cho mọi lệnh của client: bỏ được bắt tay TCP/TLS lặp lại
    # cho từng IP — trước v1.7 mỗi lệnh mở kết nối mới, 10 IP × 3 firewall ≈ 40 lần bắt tay.
    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout, connect=self.connect_timeout),
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            )
        return self._http

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ core
    def _login_block(self) -> str:
        return (
            "<Login>"
            f"<Username>{_esc(self.username)}</Username>"
            f"<Password>{_esc(self.password)}</Password>"
            "</Login>"
        )

    def _post(self, inner_xml: str, timeout: int | None = None) -> dict:
        policy.check_request(inner_xml)  # điểm chặn duy nhất — ngoài allowlist thì không gửi gì
        reqxml = f"<Request>{self._login_block()}{inner_xml}</Request>"
        read_t = timeout or self.timeout
        tmo = httpx.Timeout(read_t, connect=min(self.connect_timeout, read_t))
        try:
            resp = self._client().post(
                self.url,
                data={"reqxml": reqxml},
                headers={"Accept": "application/xml"},
                timeout=tmo,
            )
        except httpx.ConnectError as exc:
            raise SophosError(f"Không kết nối được tới {self.url} ({exc})") from exc
        except httpx.ConnectTimeout as exc:
            raise SophosError(f"Không kết nối được tới {self.url} trong {self.connect_timeout} giây", "timeout") from exc
        except httpx.TimeoutException as exc:
            raise SophosError(f"Hết thời gian chờ ({read_t} giây) khi gọi {self.url}", "timeout") from exc
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
