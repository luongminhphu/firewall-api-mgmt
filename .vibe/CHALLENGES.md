# CHALLENGES — Trang Tổng quan

## C-01 [Major] Drift 7 ngày không có trong API ở D2
- Nguồn: Gate 1 (F1)
- Quyết định của Opus: Accepted → thêm `/api/changes?type=drift&from=<ngày VN − 6>&limit=500`, đọc `totals.drift` (viewer gọi được). T-01.

## C-02 [Major] Thẻ email lỗi đỏ vĩnh viễn (outbox failed không lọc ngày)
- Quyết định của Opus: Accepted → lọc phía client `created_at` trong 7 ngày, ghi "7 ngày"; chỉ hiện số lượng + loại thư, không hiện `to`/`subject`.

## C-03 [Major] "Firewall lỗi" từ last_status là dữ liệu cũ
- Kiểm thêm: mark_status chỉ chạy khi bấm Kiểm tra hoặc khi chặn/bỏ chặn — không định kỳ.
- Quyết định của Opus: Accepted → tín hiệu chính: `/api/group-cache` (status/error/stale/exists) + `syncs[]` của VPN; `last_status` chỉ phụ, kèm `last_checked`. Dùng `state.firewalls` đã nạp, không gọi lại `/api/firewalls`.

## C-04 [Major] Back về trang không hash không đổi màn hình
- Quyết định của Opus: Accepted → router: hashchange với hash rỗng → show(tab mặc định). Test Back trong T-02.

## C-05 [Minor] Chi phí 7–8 API mỗi lần mở tab
- Quyết định của Opus: Accepted một phần → chặn gọi chồng (đang tải thì bỏ qua). Rejected mẹo `status=<không khớp>` cho /api/vpn/rules (dựa vào chi tiết cài đặt; list_rules đã nhanh sau M1).

## C-06 [Minor] Hash không hợp lệ với admin; roadmap ghi "admin và Write"
- Quyết định của Opus: Accepted → mặc định theo vai trò áp dụng cho cả hash không hợp lệ; T-03 sửa roadmap cho khớp D4.

## C-07 [Q/A] 401 song song gọi logout nhiều lần; chuỗi lỗi từ hệ thống ngoài
- Quyết định của Opus: Q1 Rejected (api.js:52 chỉ gọi khi state.token còn; logout xoá token đồng bộ). A1 Accepted → mọi chuỗi qua esc().

## C-08 [Major] Thẻ Tự động chặn gắn "công tắc khẩn cấp" cho trường enabled (bộ đọc Teams)
- Nguồn: Gate 2 (F1). Opus xác nhận ở autoblock/settings.py:30-31.
- Quyết định của Opus: Accepted → nhãn đúng; công tắc khẩn cấp TẮT = mục Cảnh báo (Q1: trạng thái cố ý nhưng dễ quên bật lại → warn, không err).

## C-09 [Major] Response null làm cả trang kẹt "Đang tải…"
- Quyết định của Opus: Accepted → try/catch từng phần, value null → thẻ lỗi. Test trong T-02.

## C-10 [Minor] Gate 2 F3–F5
- F3 mất focus: Accepted → focus mục menu đang active sau khi bấm thẻ.
- F4 hashchange sau khi thoát: Accepted → bỏ qua khi #app đang ẩn.
- F5: outbox limit=1000 Accepted; bộ đọc Teams đứng (last_poll_at > 3 chu kỳ) Accepted → warn; last_checked trên thẻ Firewall Deferred (tín hiệu phụ).
