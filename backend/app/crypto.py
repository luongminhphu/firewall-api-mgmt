"""Mã hóa mật khẩu firewall bằng AES-256-GCM, khóa dẫn xuất từ MASTER_KEY."""
import base64
import hashlib
import hmac
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

_PREFIX = "v1"


class MasterKeyMissing(RuntimeError):
    pass


def _key() -> bytes:
    mk = (settings.MASTER_KEY or "").strip()
    if not mk:
        raise MasterKeyMissing(
            "Chưa cấu hình MASTER_KEY. Đặt biến môi trường MASTER_KEY (>= 16 ký tự) trước khi lưu credential."
        )
    if len(mk) < 16:
        raise MasterKeyMissing("MASTER_KEY phải dài tối thiểu 16 ký tự.")
    # HKDF-SHA256 rút gọn (một lần expand) để lấy khóa 32 byte.
    prk = hmac.new(b"sophos-blocker-salt", mk.encode(), hashlib.sha256).digest()
    return hmac.new(prk, b"fw-credential-v1\x01", hashlib.sha256).digest()


def encrypt(plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plaintext.encode(), b"fw-credential")
    return f"{_PREFIX}:{base64.b64encode(nonce + ct).decode()}"


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        _, blob = token.split(":", 1)
        raw = base64.b64decode(blob)
        return AESGCM(_key()).decrypt(raw[:12], raw[12:], b"fw-credential").decode()
    except MasterKeyMissing:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            "Không giải mã được credential. MASTER_KEY có thể đã thay đổi so với lúc lưu."
        ) from exc


# ---------------------------------------------------------------- session token
# Token = base64url(JSON {u, r, m, n, exp}) + "." + HMAC-SHA256.
#   u: định danh (UPN hoặc tên người trực), r: vai trò, m: phương thức đăng nhập, n: tên hiển thị
ROLES = ("viewer", "operator", "admin")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(body: str) -> str:
    return hmac.new(settings.SESSION_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()


def issue_token(user: str = "soc", role: str = "admin", method: str = "local", name: str = "",
                src: str = "") -> str:
    import json

    role = role if role in ROLES else "viewer"
    payload = {
        "u": user, "r": role, "m": method, "n": name or user, "s": src,
        "exp": int(time.time()) + settings.SESSION_TTL_HOURS * 3600,
    }
    body = _b64(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())
    return f"{body}.{_sign(body)}"


def verify_principal(token: str) -> dict | None:
    import json

    try:
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        data = json.loads(_unb64(body))
        if int(data.get("exp", 0)) < time.time():
            return None
        if data.get("r") not in ROLES:
            return None
        return data
    except Exception:  # noqa: BLE001
        return None


def verify_token(token: str) -> str | None:
    p = verify_principal(token or "")
    return p["u"] if p else None
