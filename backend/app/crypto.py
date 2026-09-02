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
def issue_token(user: str = "soc") -> str:
    exp = int(time.time()) + settings.SESSION_TTL_HOURS * 3600
    body = f"{user}.{exp}"
    sig = hmac.new(settings.SESSION_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> str | None:
    try:
        user, exp, sig = token.rsplit(".", 2)
        body = f"{user}.{exp}"
        good = hmac.new(
            settings.SESSION_SECRET.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        if int(exp) < time.time():
            return None
        return user
    except Exception:  # noqa: BLE001
        return None
