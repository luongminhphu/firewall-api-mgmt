# Mục tiêu
Đánh giá tổng thể SOC Rapid Block (v2.2) từ góc nhìn IT Infrastructure Manager. Làm ngay milestone M1 (sửa lỗi đúng/sai và
hiệu suất, rủi ro thấp, **không đổi API**). Viết đề xuất M2 (liên kết tính năng) và M3 (tính năng bổ trợ) vào `docs/roadmap-infra.md`
để người dùng chọn trước khi code.

# Ngoài phạm vi (lần này)
- Mọi thứ cần **nới allowlist `policy.py`** (gộp lệnh Remove, đọc firmware/HA/license/backup cấu hình): chỉ đề xuất, chờ chủ sản phẩm duyệt (Quy tắc 1).
- API mới / đổi hình dạng response (M2, M3): chờ người dùng chọn.
- Alembic, đổi cơ chế đăng nhập, token CSV qua query string (backlog cũ §7).

# Đánh giá (bằng chứng)
Điểm mạnh: kiểm soát an toàn chặt (policy.py điểm chặn duy nhất, 4 lớp autoblock, chuỗi băm, AES-GCM), 28 bộ E2E + contract test, tài liệu đầy đủ.
Điểm yếu chính:
- E1 [đúng/sai] `core/hashchain.py:32` khoá chỉ trong tiến trình; nhiều pod ghi cùng bảng → hai dòng cùng prev_hash, gãy chuỗi (README quảng bá chạy nhiều pod).
- E2 [đúng/sai] `modules/audit/router.py:27-38` tìm `q` sau `LIMIT` → không tìm thấy bản ghi cũ; `audit_logs` không có index ngoài PK.
- E3 [hiệu suất] `modules/vpn/rules.py:246-262` rules × accounts × `json.loads`; gọi từ `/api/vpn/rules`, notify mỗi 5 phút, rà soát.
- E4 [hiệu suất] `group_cache.run_due` và `vpn/sync.sync_all` quét tuần tự từng firewall (mỗi cái tới 180 s).
- E5 [hiệu suất] Không gzip (`group-members` trả toàn bộ thành viên); `/api/group-cache` parse `data_json` 2 lần/firewall, giao diện poll 1 s.
- E6 [vận hành] `jobs.purge_old` chỉ chạy lúc khởi động; pool DB mặc định 5+10 trong khi job chặn giữ 2 kết nối/luồng.
- E7 [vận hành] Badge menu poll mỗi 60 s cả khi tab ẩn.
- E8 [kiểm chứng] Vòng lặp chạy toàn bộ test trong `.claude/cowork.md` báo FAIL giả: app cũ chưa nhả cổng 8090; `logging_test` / `slow_fw_test` cần biến môi trường riêng.
- Liên kết (M2): không có trang tổng quan, router không nhận tham số, không tra cứu một IP xuyên module, VPN ↔ Rà soát không link,
  sức khoẻ firewall chỉ kiểm tra tay, drift WebAdmin không báo ai, không có hạn chặn (TTL), không theo dõi kích thước group.

# Ràng buộc & quyết định
- D1: M1 không thêm/đổi endpoint, không đổi khoá JSON → `contract_test.py` không ghi lại snapshot.
- D2: Index mới tạo bằng `CREATE INDEX IF NOT EXISTS` khi khởi động (Quy tắc 7), chạy được SQLite + PostgreSQL.
- D3: Khoá chuỗi băm: giữ threading.Lock + `pg_advisory_xact_lock` trên chính session khi PostgreSQL (không thêm kết nối, nhả khi commit); không tính lại hash dữ liệu cũ (C-01).
- D4: Không song song hoá quét định kỳ trong M1 (C-03, Deferred). Pool DB cấu hình qua env, mặc định giữ 5/10.
- D5: Tìm audit dùng `icontains(autoescape=True)` (C-04).

# Tiêu chí hoàn thành (kiểm chứng được)
- [x] Toàn bộ `tests/*_test.py` pass bằng `bash tests/run_all.sh` (mới), không FAIL giả.
- [x] Test mới: tìm audit trúng bản ghi nằm ngoài N dòng mới nhất; chuỗi băm còn liền khi 2 tiến trình ghi song song trên PostgreSQL (FAIL trên code cũ).
- [x] `vpn_rules_test.py` cho cùng kết quả sau tối ưu; đo `list_rules` 500 rule × 2000 tài khoản < 2 s và kết quả từng rule giống bản cũ.
- [x] `contract_test.py`, `policy_guard_test.py`, `db_migrate_test.py` pass, snapshot không đổi.
- [x] `docs/roadmap-infra.md` có M2/M3, mỗi mục: giá trị, phạm vi, rủi ro, có chạm Quy tắc 1 không.

# Task
| ID | Mô tả | Phụ thuộc | Rủi ro | Trạng thái |
|----|-------|-----------|--------|------------|
| T-01 | `tests/run_all.sh`: chờ cổng rảnh giữa các bộ, env riêng cho logging/slow_fw; sửa lệnh trong cowork.md | — | Thấp | done |
| T-02 | Khoá chuỗi băm liên pod (E1) + test ghi song song | T-01 | Cao | done |
| T-03 | Audit: lọc `q` trong SQL trước LIMIT, index `audit_logs(action)` (E2) + test | T-01 | Cao | done |
| T-04 | VPN `list_rules`: dựng chỉ mục tài khoản một lần (E3) + test đo | T-01 | TB | done |
| T-05 | Purge jobs định kỳ + pool DB cấu hình được (E6); song song quét (E4) Deferred | T-01 | TB | done |
| T-06 | GZip, badge bỏ poll khi tab ẩn (E5, E7); parse cache một lần Deferred (C-13) | T-01 | Thấp | done |
| T-07 | `docs/roadmap-infra.md` (M2, M3) + nhật ký architecture.md + README | T-02..T-06 | Thấp | done |
| T-08 | Test gzip + dọn jobs (C-12) | T-05, T-06 | Thấp | done |
