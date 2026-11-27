# CLAUDE.md — SOC Rapid Block (firewall-api-mgmt)

Ứng dụng web chặn IP trên **nhiều Sophos Firewall** qua XML API (đẩy IP vào IP Host Group `SCANPORT GROUP`), tự động chặn theo lệnh
của SOC trong group chat Teams (Microsoft Graph), báo cáo PDF / Excel và quản lý quyền VPN **chỉ đọc** cho rà soát ISO/IEC 27001.
Tổng quan, triển khai, phân quyền: `README.md`. Thiết kế, quyết định đã duyệt và nhật ký từng phase: `docs/architecture.md`.

## Stack

- **Backend**: Python, FastAPI, SQLAlchemy 2.0, PostgreSQL (test chạy được trên SQLite), httpx + xmltodict (Sophos XML API),
  PyJWT (OIDC Entra ID + PKCE), cryptography (AES-256-GCM cho bí mật), reportlab (PDF), openpyxl (Excel).
- **Frontend**: HTML + JS module thuần + CSS, **không có build step** (`frontend/`).
- **Triển khai**: Docker image (`backend/Dockerfile`) push lên GHCR qua `.github/workflows/build-image.yml`; Docker Compose hoặc Kubernetes (`deploy/`).

## Bản đồ code

| Khu vực | File chính |
|---|---|
| Sophos XML API | `backend/app/integrations/sophos/` (`client.py`, `policy.py` điểm chặn duy nhất cho lệnh ghi, `sanitize.py` lọc trường bí mật, `naming.py`, `entities/`) |
| Chặn IP | `backend/app/modules/ipblock/` (bóc IP, chặn / bỏ chặn, cache group, lịch sử thay đổi + phát hiện sửa trên WebAdmin) |
| Tự động chặn từ Teams | `backend/app/modules/autoblock/` (`graph.py`, `parser.py`, `service.py`, `reply.py`, `settings.py`) |
| VPN (chỉ đọc) & rà soát | `backend/app/modules/vpn/`, `backend/app/modules/review/` |
| Báo cáo, email | `backend/app/modules/reports/`, `backend/app/modules/notify/` (outbox, SMTP) |
| Nền tảng | `backend/app/core/` (`db.py`, `models.py`, `jobs.py` advisory lock, `hashchain.py`, `audit.py`, `security.py`, `logging.py`), `backend/app/auth/` |
| Giả lập + công cụ | `mock/` (Sophos, Graph, SMTP), `tools/sophos_sample.py` (lấy mẫu cấu hình thật, chỉ đọc, đã che) |

## Lệnh thường dùng

```bash
pip install -r backend/requirements.txt
bash tests/run_e2e.sh tests/<tên>_test.py      # một bộ test (dựng mock + app trên SQLite)
E2E_DATABASE_URL=postgresql+psycopg2://u:p@127.0.0.1:5432/srb bash tests/run_e2e.sh tests/<tên>_test.py
```
Chạy cục bộ với mock: README mục 9.

## Quy tắc bắt buộc

1. **Mọi lệnh ghi lên firewall đi qua `policy.py`.** Chỉ được tạo IP Host, ghi `SCANPORT GROUP` (tên gắn cứng), xoá IP Host do app tạo,
   và `Get` dữ liệu VPN. Mở rộng allowlist phải có lý do được chủ sản phẩm duyệt và test trong `policy_guard_test.py`.
2. **VPN chỉ đọc**: app không bao giờ sửa rule hay user trên firewall.
3. **Không tự khoá**: safe-list / IP private / IP nội bộ không bao giờ bị chặn; chỉ chặn `/32`; luôn còn ít nhất một quản trị viên.
4. **Tự động chặn giữ đủ 4 lớp kiểm soát** (whitelist, lịch, ngưỡng IP/giờ, công tắc khẩn cấp); chỉ nhận lệnh từ người được ủy quyền
   đích danh, bỏ qua tin đã sửa và lệnh quá cũ.
5. **Bí mật**: mật khẩu firewall / SMTP, client secret, URL webhook mã hoá AES-256-GCM, không bao giờ trả về client hay ghi log.
   Không commit `.env`, `deploy/k8s/overlays/prod/local-config.yaml`.
6. **Toàn vẹn**: nhật ký dùng chuỗi băm SHA-256; thay đổi bản ghi hoặc schema không được làm gãy chuỗi cũ (`db_migrate_test.py`).
7. **Schema**: bảng / cột tự tạo khi khởi động, không dùng công cụ migrate; cột mới phải chạy được cả SQLite và PostgreSQL.
8. **API ổn định**: `contract_test.py` khoá danh sách API và hình dạng response; chỉ ghi lại snapshot khi cố ý đổi API.
9. **Quyền kiểm tra ở mỗi request** (vai trò Rà soát / Readonly / Write / Quản trị viên); ẩn ở giao diện không thay cho kiểm tra ở API.
10. **Test không gọi hệ thống thật**: dùng `mock/`. Hành vi mới phải có test.
11. **Ngôn ngữ**: giao diện, báo cáo, tài liệu tiếng Việt có dấu; tên biến và code tiếng Anh. Báo cáo PDF / Excel theo HSC Design System.

## Vòng Cowork (Opus · Sonnet · Fable)

Mọi yêu cầu có thay đổi code chạy theo vòng cowork: phiên chính (Opus) lập kế hoạch và điều phối, subagent `sonnet-coder` code,
subagent `fable-critic` phản biện. Quy trình đầy đủ:

@.claude/cowork.md
