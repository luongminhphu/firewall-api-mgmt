"""Cấu hình ứng dụng — đọc từ biến môi trường."""
import os
import secrets


def _bool(v: str, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    # Kết nối DB. Mặc định PostgreSQL (docker-compose). Có thể trỏ SQLite để demo.
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql+psycopg2://sophos:sophos@db:5432/sophos_blocker"
    )

    # Khóa chính dùng để mã hóa mật khẩu firewall (AES-256-GCM qua HKDF).
    # BẮT BUỘC đặt trong .env ở môi trường thật.
    MASTER_KEY: str = os.getenv("MASTER_KEY", "")

    # Mật khẩu đăng nhập mini app (một tài khoản dùng chung cho team SOC/NOC).
    APP_PASSWORD: str = os.getenv("APP_PASSWORD", "socadmin")

    # Bí mật ký session cookie.
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "") or secrets.token_hex(32)
    SESSION_TTL_HOURS: int = int(os.getenv("SESSION_TTL_HOURS", "8"))

    # Tiền tố tên IP Host tạo trên firewall.
    HOST_PREFIX: str = os.getenv("HOST_PREFIX", "SOC_BLOCK_")

    # Timeout gọi API firewall (giây).
    API_TIMEOUT: int = int(os.getenv("API_TIMEOUT", "30"))

    # Danh sách IP/CIDR không bao giờ được chặn (an toàn), phân tách bằng dấu phẩy.
    SAFE_LIST: str = os.getenv(
        "SAFE_LIST",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,8.8.8.8,1.1.1.1",
    )

    # Cho phép chặn IP private hay không (mặc định: không).
    ALLOW_PRIVATE: bool = _bool(os.getenv("ALLOW_PRIVATE"), False)

    APP_NAME: str = "SOC Rapid Block"
    APP_VERSION: str = "1.0.0"


settings = Settings()
