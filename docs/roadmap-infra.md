# SOC Rapid Block — Đánh giá tổng thể & lộ trình cho IT Infrastructure Manager

> Ngày đánh giá: 27/11/2026 · phiên bản 2.2.1 · Trạng thái: **ĐỀ XUẤT, chờ duyệt** (M1 đã làm, xem `docs/architecture.md` §22).
> Ghi chú: mục nào có dấu **[P]** cần nới allowlist `policy.py`, tức phải được chủ sản phẩm duyệt kèm test `policy_guard_test.py`
> (Quy tắc 1, `CLAUDE.md`).

## 1. Đánh giá hiện trạng

| Khía cạnh | Đánh giá | Bằng chứng |
|---|---|---|
| An toàn thao tác firewall | **Tốt**. Mọi lệnh ghi đi qua một điểm kiểm soát duy nhất, tên group gắn cứng, safe-list, chỉ chặn `/32` | `integrations/sophos/policy.py`, `policy_guard_test.py` |
| Tự động chặn từ Teams | **Tốt**. Có đủ 4 lớp kiểm soát, ủy quyền đích danh, bằng chứng tin nhắn có chuỗi băm | `modules/autoblock/`, `autoblock_test.py` |
| Toàn vẹn nhật ký | Trước 2.2.1: **chuỗi băm có thể gãy khi chạy nhiều pod**, vì khoá chỉ có tác dụng trong một tiến trình. Đã sửa ở M1 | `core/hashchain.py`, `hashchain_multiproc_test.py` |
| Kiểm thử | **Tốt**. 32 bộ E2E kèm contract test. Trước đây vòng lặp chạy toàn bộ test báo FAIL giả; đã thêm `tests/run_all.sh` | `tests/` |
| Hiệu suất | **Đủ cho quy mô hiện tại**. Có vài điểm nghẽn khi dữ liệu lớn (VPN, Audit, gzip); M1 đã xử lý | §3 |
| **Liên kết giữa các tính năng** | **Yếu**. Các module mạnh khi đứng riêng, nhưng không có trang tổng quan, không tra cứu được một IP xuyên module, và cả giao diện chỉ có một liên kết chéo giữa các trang | §2 |
| Giám sát chủ động | **Yếu**. Sức khoẻ firewall chỉ được kiểm khi bấm tay. Sửa trên WebAdmin (drift) có ghi nhận nhưng không báo ai. Không theo dõi kích thước group | §2 |

## 2. M2 — Liên kết các tính năng hiện có (đề xuất)

Thứ tự ưu tiên tính theo giá trị cho Infra Manager trên công sức bỏ ra. Không mục nào cần nới `policy.py`.

| # | Đề xuất | Giá trị | Phạm vi | Rủi ro |
|---|---|---|---|---|
| L1 ✅ 2.3.0 | **Trang Tổng quan** (`#overview`, trang mặc định cho quản trị viên; Write / Readonly giữ Chặn nhanh) | Một màn hình trả lời "hôm nay có gì cần xử lý": firewall lỗi, lệnh chờ duyệt, rule VPN hết hạn mà vẫn bật, đợt rà soát quá hạn, email gửi lỗi, drift, cache cũ | Chỉ frontend, gọi các API sẵn có: `/api/firewalls`, `/api/group-cache`, `/api/autoblock/status`, `/api/vpn/rules` (`summary`, `syncs`), `/api/review/campaigns`, `/api/notify/outbox?status=failed`, `/api/reports/summary?days=7`. Thẻ nào vai trò không có quyền đọc thì ẩn | Thấp |
| L2 | **Deep link có tham số** `#tab?ip=…&fw=…` | Mở thẳng tới đúng IP hoặc firewall từ email, báo cáo hay thẻ Tổng quan | `frontend/js/router.js` (hiện chỉ nhận `^[a-z]+$`) và phần điền sẵn bộ lọc ở các trang Lịch sử, VPN, IP Host Group. Backend đã có bộ lọc `q`, `firewall_id` | Thấp |
| L3 | **Tra cứu một IP** `GET /api/ip/{ip}` và ô tra cứu trên thanh trên | Trả lời câu hỏi của auditor và SOC: "IP này bị chặn khi nào, ai yêu cầu (tin Teams + bằng chứng), trên firewall nào, đã gỡ chưa" | API mới gộp `GroupChange`, `AutoBlockRequest`/evidence, `AuditLog` và trạng thái cache hiện tại. Cần ghi lại contract snapshot | TB |
| L4 | **VPN ↔ Rà soát** | Từ mục rà soát mở được rule/tài khoản VPN tương ứng; ở chi tiết rule thấy quyết định của đợt rà soát gần nhất | `review.js`, `vpn.js` và `/api/vpn/rules/{id}` thêm khoá `review` (đổi response, cần ghi lại snapshot) | Thấp |
| L5 | **Firewall → dữ liệu của nó** | Mỗi dòng firewall có lối tắt tới IP Host Group, VPN và lịch sử thay đổi của chính firewall đó (dùng L2) | `firewalls.js` | Thấp |
| L6 | **Huy hiệu menu** cho VPN hết hạn, rà soát đang mở, email lỗi, drift | Thấy việc cần làm mà không phải mở từng tab | Gộp chung vòng poll 60 giây hiện có (đã ngừng poll khi tab ẩn ở M1); nên thêm `GET /api/overview/counts` nhẹ thay vì gọi 5 API | Thấp |
| L7 | **Gộp logic "ai chặn gì, khi nào"** | Báo cáo và Lịch sử dùng cùng một bộ tổng hợp, không bao giờ lệch số | `ipblock/changelog.py` và `reports/data.py` cùng dùng một hàm tổng hợp theo IP. Tái cấu trúc, đổi gì phải giữ `reports_test.py` xanh | TB |

## 3. Hiệu suất

**Đã làm ở M1:** khoá chuỗi băm liên pod; tìm Audit trong SQL kèm index `action`; VPN `list_rules` nhanh hơn khoảng 100 lần
(500 rule × 2 000 tài khoản: 1,3 s → 0,01 s); gzip (mức 5); dọn bảng `jobs` mỗi 6 giờ; pool DB cấu hình được; huy hiệu ngừng poll khi tab ẩn.

**Còn lại (cần số đo thật trước khi làm):**

| # | Việc | Vì sao hoãn |
|---|---|---|
| P1 | Chạy song song các lượt quét định kỳ `group_cache.run_due` và `vpn.sync_all` (hiện chạy tuần tự từng firewall, tối đa 180 s mỗi firewall) | Có thể tranh worker với lệnh chặn khẩn của SOC và làm tăng số kết nối DB/firewall. Cần đo thời gian một vòng trên production; nếu làm thì dùng pool riêng 2 luồng |
| P2 | Bỏ chặn nhiều IP: hiện xoá từng IP Host, mỗi lệnh một round-trip | Gộp lệnh `Remove` **[P]**. Phần dựng bảng tra ngược `{ip: object}` (O(n)) làm được ngay, không cần nới allowlist |
| P3 | `/api/group-cache` và `group-members` parse `data_json` 2–3 lần mỗi request | Mỗi lần chỉ vài ms; chạm vùng `ipblock`. Làm khi tách `total`/`full_scanned_at` thành cột |
| P4 | Các endpoint `verify` duyệt lại toàn bộ chuỗi băm mỗi lần bấm | Cache theo `max(id)` kèm TTL ngắn; giữ nguyên chế độ quét đầy đủ |
| P5 | Tìm `q` trong Audit và Lịch sử dùng `%x%`, nên quét cả bảng | Cần `pg_trgm` hoặc giới hạn khoảng thời gian khi bảng vượt khoảng 1 triệu dòng |

## 4. M3 — Tính năng bổ trợ cho IT Infrastructure Manager

| # | Tính năng | Giá trị | Cần nới allowlist? | Công sức |
|---|---|---|---|---|
| F1 | **Giám sát sức khoẻ firewall định kỳ** (dùng kết quả quét cache / VPN sync ghi vào `Firewall.last_status`), cảnh báo email sau N lần lỗi liên tiếp | Biết firewall mất kết nối API trước khi SOC cần chặn | Không | Nhỏ |
| F2 | **Cảnh báo drift WebAdmin** qua email (outbox, kiểu `group_drift`) gửi danh sách Infra | Phát hiện người sửa `SCANPORT GROUP` ngoài quy trình, phục vụ kiểm soát thay đổi ISO 27001 A.8.32 | Không | Nhỏ |
| F3 | **Thời hạn chặn (TTL)**, tuỳ chọn cho mỗi lần chặn: tự gỡ khi hết hạn, có danh sách sắp hết hạn | Group không phình mãi; IP động của nhà mạng không bị chặn vĩnh viễn | Không (xoá IP Host do app tạo đã được phép) | TB, cần schema `expires_at` và job định kỳ |
| F4 | **Ngưỡng kích thước group**: cảnh báo khi `total` vượt mức cấu hình | Tránh chạm giới hạn object của SFOS (cần đối chiếu tài liệu Sophos) | Không | Nhỏ |
| F5 | **Báo cáo tháng cho quản lý** (PDF tự gửi ngày 1): số IP, tỉ lệ tự động, thời gian phản ứng, VPN hết hạn, tiến độ rà soát, sức khoẻ firewall | Tài liệu báo cáo lãnh đạo và auditor, không phải làm tay | Không | TB (tái dùng `modules/reports`) |
| F6 | **Theo dõi firmware / HA / license / chứng chỉ** của từng firewall (chỉ đọc) | Lên kế hoạch nâng cấp, gia hạn | **[P]** cần `Get` thêm entity hệ thống | TB |
| F7 | **Sao lưu cấu hình định kỳ (chỉ đọc)** và so sánh khác biệt | Khôi phục nhanh, có bằng chứng thay đổi | **[P]**, dữ liệu nhạy cảm, phải mã hoá | Lớn |
| F8 | **Quy trình xin / gia hạn quyền VPN** (đại diện team đề xuất, Infra duyệt; app chỉ ghi nhận và nhắc, không sửa firewall) | Khép vòng ISO A.5.18: cấp quyền, rà soát, thu hồi | Không (VPN vẫn chỉ đọc) | Lớn |
| F9 | **Xuất chỉ số Prometheus `/metrics`** (job lỗi, độ trễ firewall, lệnh chờ duyệt) | Đưa vào hệ giám sát sẵn có của Infra (Grafana) | Không | Nhỏ |

**Đề xuất thứ tự:** ~~L1~~ (xong 2.3.0) → L2 → F1 + F2 (dùng chung outbox) → L3 → F3 → F5. Các mục **[P]** cần chủ sản phẩm duyệt riêng.

## 5. Việc người vận hành nên kiểm trên production

1. Gọi `/api/changes/verify`, `/api/vpn/changes/verify`, `/api/review/verify`, `/api/autoblock/verify`. Nếu đã từng chạy hơn 1 pod
   thì chuỗi cũ có thể đã gãy; cần quyết định cách ghi nhận theo Quy tắc 6, không tính lại hash.
2. `SHOW default_transaction_isolation;`: phải là `read committed`, vì khoá chuỗi băm dựa vào mức này.
3. `SHOW lc_ctype;`: nếu là `C`/`POSIX` thì tìm Audit không phân biệt hoa thường với chữ có dấu.
4. Proxy phía trước (App Proxy / Ingress) phải chuyển tiếp `Accept-Encoding` và không nén lần hai:
   `curl -sI -H 'Accept-Encoding: gzip' https://<app>/js/main.js`.
