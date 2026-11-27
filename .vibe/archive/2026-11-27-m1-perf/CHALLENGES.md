# CHALLENGES

## C-01 [Major] Khoá chuỗi băm bằng jobs.lock tốn thêm kết nối, có thể cạn pool sau khi đã ghi firewall
- Nguồn: Gate 1 (F1)
- Vấn đề: jobs.lock mở kết nối riêng; trong fw_lock mỗi luồng giữ 3 kết nối → pool 15 cạn → GroupChange mất → lượt quét sau ghi nhầm "sửa trên WebAdmin".
- Quyết định của Opus: Accepted → D3 đổi: giữ threading.Lock + `pg_advisory_xact_lock` trên chính session (PostgreSQL), nhả khi commit. T-02.

## C-02 [Major] Test song song trong một tiến trình không chứng minh E1
- Nguồn: Gate 1 (F2)
- Quyết định của Opus: Accepted → T-02 test bằng 2 tiến trình trên PostgreSQL (máy có PG 16), phải FAIL trên code cũ.

## C-03 [Major] Song song hoá quét định kỳ: tranh worker với lệnh chặn khẩn, nhân kết nối
- Nguồn: Gate 1 (F3)
- Quyết định của Opus: Deferred → đưa vào roadmap (cần số đo thật về thời gian quét). Bỏ khỏi M1. T-05 chỉ còn purge jobs định kỳ + pool cấu hình được (mặc định giữ 5/10).

## C-04 [Major] ilike đổi hành vi (% _ là ký tự đại diện, SQLite không lower Unicode)
- Nguồn: Gate 1 (F4)
- Quyết định của Opus: Accepted → dùng `icontains(q, autoescape=True)`; test có `_`; ghi nhận giới hạn chữ hoa có dấu trên SQLite (production PostgreSQL không bị).

## C-05 [Minor] Index (ts) không truy vấn nào dùng
- Quyết định của Opus: Accepted → chỉ tạo `ix_audit_logs_action` (CREATE INDEX IF NOT EXISTS).

## C-06 [Minor] Ngưỡng thời gian cứng dễ flaky; phải giữ thứ tự linked + nhánh user_code
- Quyết định của Opus: Accepted → ngưỡng rộng (< 2 s) + so kết quả từng rule giữa bản cũ và mới.

## C-07 [Câu hỏi] Production có >1 replica? Chuỗi cũ đã gãy chưa?
- Quyết định của Opus: base `replicas: 1`; T-02 rẻ nên vẫn làm (README quảng bá nhiều pod). Đề nghị người dùng gọi các endpoint verify trên production — ghi vào báo cáo cuối.

## C-08 [Minor] T-02: exception không phải lỗi DB giữ khoá xact tới khi session đóng
- Nguồn: Gate 2 (T-02 F1)
- Quyết định của Opus: Accepted → Opus sửa: try/except BaseException → rollback → raise trong append.

## C-09 [Minor] T-02: thứ tự khoá / chờ vô hạn; test có thể treo
- Nguồn: Gate 2 (T-02 F2, F3, Q1)
- Quyết định của Opus: Accepted một phần → docstring ghi quy ước "flush trước, append sau, không gọi firewall giữa"; chờ khoá không giới hạn (ưu tiên không mất bản ghi, không đặt lock_timeout); test thêm timeout 120 s. Giả định READ COMMITTED + lc_ctype ghi vào báo cáo để người dùng kiểm production.

## C-10 [Major] T-03: nhánh tạo index cho DB cũ không có test
- Nguồn: Gate 2 (T-03 F1)
- Quyết định của Opus: Accepted → Opus thêm vào db_migrate_test (DROP INDEX → init_db → có index); đã chứng minh FAIL khi bỏ code ở db.py.

## C-11 [Minor] T-03: hai pod cùng tạo index lần đầu; ILIKE chữ có dấu tuỳ lc_ctype
- Quyết định của Opus: Rejected (race giống create_all đang có, pod tự khởi động lại thì qua; base replicas 1). lc_ctype: ghi vào báo cáo cho người dùng kiểm.

## C-12 [Major] T-05/T-06 không có test cho hành vi mới
- Nguồn: Gate 2 (milestone, F1)
- Quyết định của Opus: Accepted → T-08 (tests/ops_test.py).

## C-13 [Minor] Gate 2 milestone F2–F7
- F2 bài đo không bắt hồi quy: Accepted → ngưỡng tương đối (mới × 5 < cũ).
- F3 parse cache một lần: Deferred (vài ms/lần, chạm vùng ipblock; xem roadmap).
- F4 gzip mức 9 chặn event loop: Accepted → compresslevel=5.
- F5 comment BREACH sai lý do: Accepted → sửa comment.
- F6 groups_json hỏng: Rejected (accounts.py luôn ghi list hợp lệ; bản cũ cũng lỗi khi gặp).
- F7 DB_POOL_SIZE rỗng: Accepted → `or "5"`.
