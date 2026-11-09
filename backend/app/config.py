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
    # Timeout bắt tay TCP/TLS (giây) — firewall chết/không route thì báo lỗi nhanh, không chờ hết API_TIMEOUT.
    API_CONNECT_TIMEOUT: int = int(os.getenv("API_CONNECT_TIMEOUT", "10"))
    # Timeout đọc riêng cho lượt quét đầy đủ chạy nền (đọc mọi IP Host trên firewall) — firewall nhiều object cần lâu hơn.
    GROUP_SCAN_TIMEOUT: int = int(os.getenv("GROUP_SCAN_TIMEOUT", "180"))
    # Tra cứu chi tiết theo tên tối đa N object mỗi lượt; nhiều hơn thì đọc cả danh sách IP Host (GROUP_SCAN_TIMEOUT).
    HOST_LOOKUP_LIMIT: int = int(os.getenv("HOST_LOOKUP_LIMIT", "25"))

    # Danh sách IP/CIDR không bao giờ được chặn (an toàn), phân tách bằng dấu phẩy.
    SAFE_LIST: str = os.getenv(
        "SAFE_LIST",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,8.8.8.8,1.1.1.1",
    )

    # Cho phép chặn IP private hay không (mặc định: không).
    ALLOW_PRIVATE: bool = _bool(os.getenv("ALLOW_PRIVATE"), False)

    # ------------------------------------------------------------ xác thực
    # Các phương thức đăng nhập được bật, phân tách bằng dấu phẩy:
    #   local  — mật khẩu dùng chung APP_PASSWORD (chỉ nên dùng trong LAN / lab)
    #   oidc   — đăng nhập Microsoft Entra ID (OpenID Connect), khuyến nghị khi đi qua App Proxy
    #   header — tin header danh tính do Entra Application Proxy chèn (header-based SSO)
    AUTH_MODES: str = os.getenv("AUTH_MODES", "local")

    # Vai trò mặc định khi đăng nhập bằng APP_PASSWORD (giữ tương thích v1.0: admin).
    LOCAL_ROLE: str = os.getenv("LOCAL_ROLE", "admin")

    # --- Entra ID OIDC (App registration) ---
    OIDC_TENANT_ID: str = os.getenv("OIDC_TENANT_ID", "")
    OIDC_CLIENT_ID: str = os.getenv("OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET: str = os.getenv("OIDC_CLIENT_SECRET", "")
    # URL callback công khai qua App Proxy, vd https://socblock-hsc.msappproxy.net/api/auth/oidc/callback
    OIDC_REDIRECT_URI: str = os.getenv("OIDC_REDIRECT_URI", "")
    OIDC_AUTHORITY: str = os.getenv("OIDC_AUTHORITY", "https://login.microsoftonline.com")
    # Tên App Role (khai báo trong App registration) -> vai trò trong app
    ROLE_ADMIN: str = os.getenv("ROLE_ADMIN", "SRB.Admin")
    ROLE_OPERATOR: str = os.getenv("ROLE_OPERATOR", "SRB.Operator")
    ROLE_VIEWER: str = os.getenv("ROLE_VIEWER", "SRB.Viewer")
    # Bắt buộc token có claim amr chứa "mfa" (Conditional Access vẫn là lớp chính).
    OIDC_REQUIRE_MFA_CLAIM: bool = _bool(os.getenv("OIDC_REQUIRE_MFA_CLAIM"), False)
    # Cache IP Host Group (v1.6): quá TTL thì vẫn trả cache ngay và quét lại nền (stale-while-revalidate)
    # v1.6.1: mặc định 24 giờ. Sau mỗi lần chặn/bỏ chặn vẫn cập nhật ngay; TTL chỉ quyết định chu kỳ quét đầy đủ định kỳ.
    GROUP_CACHE_TTL_MINUTES: int = int(os.getenv("GROUP_CACHE_TTL_MINUTES", "1440"))
    # Giờ quét đầy đủ hằng ngày theo giờ Việt Nam (HH:MM), vd "02:00". Để trống = chỉ theo TTL.
    GROUP_CACHE_DAILY_AT: str = os.getenv("GROUP_CACHE_DAILY_AT", "").strip()
    # Chu kỳ bộ lập lịch kiểm tra cache (phút) và thời gian chờ trước khi thử lại firewall đang lỗi (phút).
    GROUP_CACHE_CHECK_MINUTES: int = int(os.getenv("GROUP_CACHE_CHECK_MINUTES", "10"))
    GROUP_CACHE_ERROR_RETRY_MINUTES: int = int(os.getenv("GROUP_CACHE_ERROR_RETRY_MINUTES", "30"))
    # Bấm "Quét lại": chờ tối đa N giây để trả kết quả mới, quá thì trả cache + tiếp tục quét nền (tránh timeout App Proxy/NGINX).
    GROUP_CACHE_REFRESH_WAIT: int = int(os.getenv("GROUP_CACHE_REFRESH_WAIT", "8"))
    GROUP_CACHE_MIN_REFRESH_SECONDS: int = int(os.getenv("GROUP_CACHE_MIN_REFRESH_SECONDS", "5"))
    GROUP_CACHE_WARMUP: bool = _bool(os.getenv("GROUP_CACHE_WARMUP"), True)
    LOGO_MAX_KB: int = int(os.getenv("LOGO_MAX_KB", "300"))
    OIDC_ALLOW_GUESTS: bool = _bool(os.getenv("OIDC_ALLOW_GUESTS"), False)
    # SSO một lần (v1.5.1):
    #  OIDC_AUTO_LOGIN=true → mở app là tự chuyển sang Microsoft; đã đăng nhập ở App Proxy thì Entra trả về ngay, không hỏi lại.
    #  OIDC_PROMPT="" (mặc định) → dùng phiên Microsoft hiện có. "select_account" = luôn hiện chọn tài khoản, "login" = luôn nhập lại.
    #  OIDC_DOMAIN_HINT=hsc.com.vn → bỏ bước dò tenant theo email.
    OIDC_AUTO_LOGIN: bool = _bool(os.getenv("OIDC_AUTO_LOGIN"), True)
    OIDC_PROMPT: str = os.getenv("OIDC_PROMPT", "").strip().lower()
    OIDC_DOMAIN_HINT: str = os.getenv("OIDC_DOMAIN_HINT", "").strip()

    # --- Header-based SSO qua Entra Application Proxy ---
    HEADER_USER: str = os.getenv("HEADER_USER", "X-SRB-UPN")
    HEADER_NAME: str = os.getenv("HEADER_NAME", "X-SRB-NAME")
    # CHỈ tin header khi request đến từ các dải này (IP máy cài Private Network Connector).
    TRUSTED_PROXY_CIDRS: str = os.getenv("TRUSTED_PROXY_CIDRS", "")
    HEADER_DEFAULT_ROLE: str = os.getenv("HEADER_DEFAULT_ROLE", "viewer")

    # Quản lý người dùng (v1.5.0)
    # USERS_STRICT=true → đăng nhập Microsoft chỉ chấp nhận tài khoản có trong danh sách người dùng của app.
    USERS_STRICT: bool = os.getenv("USERS_STRICT", "false").lower() in ("1", "true", "yes")
    # SHARED_PASSWORD_LOGIN=false → tắt đăng nhập bằng mật khẩu chung APP_PASSWORD (chỉ còn tài khoản riêng / Microsoft).
    SHARED_PASSWORD_LOGIN: bool = os.getenv("SHARED_PASSWORD_LOGIN", "true").lower() in ("1", "true", "yes")
    PASSWORD_MIN_LENGTH: int = int(os.getenv("PASSWORD_MIN_LENGTH", "10"))
    LOGIN_MAX_FAILS: int = int(os.getenv("LOGIN_MAX_FAILS", "5"))
    LOGIN_LOCK_MINUTES: int = int(os.getenv("LOGIN_LOCK_MINUTES", "10"))
    HEADER_ADMINS: str = os.getenv("HEADER_ADMINS", "")      # UPN, phân tách dấu phẩy
    HEADER_OPERATORS: str = os.getenv("HEADER_OPERATORS", "")

    APP_NAME: str = "SOC Rapid Block"
    APP_VERSION: str = "1.6.1"

    @property
    def auth_modes(self) -> list[str]:
        return [m.strip().lower() for m in self.AUTH_MODES.split(",") if m.strip()]


settings = Settings()
