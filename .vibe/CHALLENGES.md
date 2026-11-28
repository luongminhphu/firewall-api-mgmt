# CHALLENGES — F1 + F2 cảnh báo email

## C-01 [Major] Drift giả do quét cache đua với lệnh chặn → email báo động sai
- Quyết định của Opus: Accepted → D1b (quét do probe kích hoạt chạy dưới fw_lock không chờ) + D1c (scan bỏ detect_drift nếu app ghi sau lúc bắt đầu quét). T-02.
## C-02 [Major] Trạng thái F1 phải theo kết quả probe, không theo last_status
- Accepted → D2/D3, state lưu status probe.
## C-03 [Major] Một firewall lỗi (MasterKeyMissing, bị xoá) làm chết cả vòng
- Accepted → try/except + commit từng firewall; dọn state firewall tắt/xoá.
## C-04 [Major] deliver không khoá → thư trùng
- Accepted → fw-health chỉ enqueue; deliver bọc jobs.lock("outbox-deliver", blocking=False).
## C-05 [Major] Con trỏ drift khi tắt; bước drift phụ thuộc kế hoạch VPN
- Accepted → con trỏ luôn tiến; bước drift try riêng; test bật lại.
## C-06 [Minor] Dedupe drift theo max_id tách lô
- Accepted → dedupe theo batch_id.
## C-07 [Q1] Probe sai mật khẩu 288 lần/ngày → khoá tài khoản API
- Accepted → auth_error giãn chu kỳ firewall đó 60 phút.
## C-08 [Q] Cảnh báo phụ thuộc công tắc nhắc hạn VPN
- Accepted → không phụ thuộc `enabled`; chỉ cần loại cảnh báo bật + infra_emails.
## C-09 [A1] Get toàn bộ IPHostGroup mỗi 5 phút nặng
- Accepted → probe dùng get_group(BLOCK_GROUP) (lọc theo tên).
## C-10 [Q2] Mạng pod chết → N email
- Deferred (≤ 10 firewall; gộp email làm sau nếu thực tế phiền).
## C-11 [Người dùng] Drift chỉ email ngoài giờ hành chính / cuối tuần
- Yêu cầu người dùng 27/11 → D0 (dùng lịch Tự động chặn) + D1b để thời điểm drift ≈ thời điểm sửa (≤ 1 chu kỳ probe).

## C-12 [Major] Gate 2 T-01: giãn 60 phút khi auth_error chặn cả xét ngưỡng email và việc nhận ra admin đã sửa mật khẩu
- Quyết định của Opus: Accepted → Opus sửa: trong giãn chu kỳ chỉ bỏ lệnh gọi mạng, vẫn xét ngưỡng; fingerprint host/port/username/password_enc trong state — đổi cấu hình thì probe ngay. Test: email đúng hạn khi đang giãn; sửa mật khẩu → probe ngay → fw_up.
## C-13 [Minor] Gate 2 T-01 F2–F4, Q1, Q2
- F2 urgent deliver bị bỏ lượt: Accepted → deliver(wait=True) cho cảnh báo autoblock; log cảnh báo khi FW_HEALTH bật mà NOTIFY_INTERVAL=0.
- F3 state hỏng làm kẹt firewall: Accepted → _parse chịu lỗi, naive → UTC, down_since hỏng tính lại từ lượt này.
- F4 tắt firewall đang báo lỗi không có email đóng: Deferred → ghi tài liệu.
- Q1 firewall chập chờn không bao giờ có email: Deferred (audit fw_health có dữ liệu; làm khi cần).
- Q2 N pod → N probe/chu kỳ: Deferred (email không trùng nhờ state; backoff auth lưu DB nên pod khác cũng giãn).

## C-14 [Blocker] Gate 2 T-02: drift giả khi scan bắt đầu sau changelog.record nhưng trước khi snapshot commit
- Bằng chứng: hashchain.append commit GroupChange ngay (T2); save_snapshot commit cuối hàm (T3); bỏ chặn + delete_object có hàng chục giây giữa T2–T3. Raced-check `ts >= t_start` không phủ → drift_remove giả vĩnh viễn trong chuỗi băm + email ban đêm.
- Quyết định của Opus: Accepted → T-02b: `jobs.lock(f"fw-write:{fw.id}", blocking=False)` BÊN TRONG scan, bọc raced-check + detect_drift + commit; bận → raced. Bỏ khoá fw-write ở health._sync_drift (không cần tham số). Test cửa sổ T2–T3.
## C-15 [Major] raced làm probe mù ("lượt sau so lại" không tồn tại)
- Accepted → _sync_drift quét cả khi row.dirty.
## C-16 [Minor] scan của probe không giữ gc-scan
- Accepted → _sync_drift lấy jobs.lock(f"gc-scan:{fw.id}", blocking=False); bận → bỏ lượt.
## C-17 [Q1/Q2] D0 phân loại theo thời điểm PHÁT HIỆN
- Accepted có giới hạn: probe 5 phút → lệch ≤ ~5 phút (sửa 17:58 phát hiện 18:03 có thể báo; chấp nhận). Probe tắt / firewall down → sửa đêm có thể bị phát hiện trong giờ → không email. Ghi rõ trong README/architecture. A1 lệch đồng hồ pod: chấp nhận (NTP).

## C-18 [Major] Gate 2 vòng 2: nút Đồng bộ (/api/changes/sync) so drift không khoá
- Quyết định của Opus: Accepted → khoá fw-write không chờ; bận → trả lỗi "thử lại sau". Test trên PostgreSQL (khoá liên tiến trình).
## C-19 [Major, xác suất thấp] Crash giữa changelog.record và commit snapshot → drift_remove giả
- Opus thử đảo thứ tự (save_snapshot trước record) → e2e_changelog_test trên PostgreSQL drift giả 1/2 lần (thứ tự cũ: 6/6 sạch). Chưa rõ cơ chế.
- Quyết định: Rejected bản sửa (gây lỗi thường xuyên hơn rủi ro nó chữa) → Deferred, cần điều tra riêng (snapshot / phiên trong block_on_firewall). Ghi giới hạn trong architecture §25.
## C-20 [Minor] Gate 2 vòng 2 F3, F4
- F3 lỗi khi lấy khoá coi là không raced: Accepted → raced=True trong except.
- F4 raced-check loại drift_*: Accepted → mọi GroupChange sau t_start. (Test alerts dùng ngày tương lai cố định → đổi sang ngày quá khứ.)
