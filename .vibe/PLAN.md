# Mục tiêu
Roadmap F1 + F2: Infra nhận email khi (F1) một firewall mất kết nối XML API kéo dài, kèm email khi hồi phục, và (F2) có người sửa
`SCANPORT GROUP` trực tiếp trên WebAdmin (drift). Trạng thái firewall trên giao diện thành dữ liệu sống.

# Ngoài phạm vi
- Kênh khác email (Teams, SMS, Prometheus — roadmap F9).
- Kiểm tra song song nhiều firewall (tuần tự đủ cho ≤ 10 firewall với chu kỳ 5 phút).
- Đổi cách phát hiện drift (giữ `changelog.detect_drift` chạy trong lượt quét cache).

# Ràng buộc & quyết định
- D0 (yêu cầu người dùng 27/11): email drift **chỉ khi thời điểm drift ngoài giờ hành chính / cuối tuần / ngày lễ**. Trong giờ hành chính team network
  quản trị trực tiếp trên WebAdmin là bình thường → vẫn ghi Lịch sử thay đổi, không email. "Giờ hành chính" dùng chung lịch của Tự động chặn
  (`autoblock.settings.window_reason`: khung 18:00–08:00, thứ 7/CN, ngày lễ) — tính với `window_enabled` coi như bật (lịch tắt 24/7 không có nghĩa
  "luôn ngoài giờ"). Thời điểm = `GroupChange.ts` của dòng drift.
- D1: **Job fw-health** `jobs.every("fw-health", FW_HEALTH_MINUTES*60)` (env, mặc định 5; 0 = tắt): mỗi firewall đang bật gọi `cli.get_group(BLOCK_GROUP)`
  (Get lọc theo tên, nhẹ, đã có trong allowlist policy.py — không lệnh ghi). Thành công = sống; cập nhật `mark_status`. Mỗi firewall try/except +
  commit riêng (C-03). `auth_error` → giãn chu kỳ firewall đó 60 phút để không khoá tài khoản API (C-07).
- D1b: **Drift gần thời gian thực**: nếu tập tên thành viên probe đọc được khác cache → chạy `group_cache.scan(mode="lite")` NGAY trong probe, dưới
  `fw_lock` (khoá ghi theo firewall) lấy kiểu không chờ; đang có lệnh chặn thì bỏ lượt này (C-01).
- D1c: `group_cache.scan` (mọi chế độ): nếu có `GroupChange` add/remove do app của firewall đó ghi SAU lúc scan bắt đầu đọc → bỏ `detect_drift`
  lượt này, đánh dấu dirty để lượt sau so lại (sửa race drift giả có sẵn — C-01).
- D2: Audit chỉ khi trạng thái **probe** đổi (so với trạng thái probe trước lưu trong state, không so `last_status` mà luồng chặn cũng ghi — C-02),
  action `fw_health`, actor `system`.
- D3: F1 email khi lỗi liên tục ≥ `fw_down_minutes` (mặc định 15) từ `down_since`; email hồi phục chỉ khi đã gửi email lỗi. State
  `{fw_id: {status, down_since, alerted, next_probe_at}}` trong AppSetting khoá riêng `alerts.state`; firewall tắt / bị xoá → xoá state (C-03).
- D4: F2 trong `notify.run_cycle`, bước riêng có try riêng (C-05): đọc drift `id > con trỏ` (AppSetting `alerts.state`), **con trỏ luôn tiến kể cả
  khi cảnh báo tắt** (bật lại không xả lịch sử); lọc theo D0; gom theo `batch_id` (mỗi lô một email, dedupe `drift:<batch_id>`, C-06), ≤ 50 dòng.
  Lần đầu: con trỏ = max id, không gửi lịch sử.
- D5: fw-health chỉ `enqueue` (không deliver); `deliver` bọc `jobs.lock("outbox-deliver", blocking=False)` để không pod/luồng nào gửi trùng (C-04).
  Dedupe: `fw_down:<fw>:<down_since>`, `fw_up:<fw>:<down_since>`, `drift:<batch_id>`.
- D6: Cấu hình **tách khỏi công tắc nhắc hạn VPN** (C-08): thêm vào notify cfg `DEFAULTS` (để update_cfg không xoá): `alert_fw_down` (true),
  `fw_down_minutes` (15, 5–1440), `alert_drift` (true). Gửi khi loại đó bật và có `infra_emails` — KHÔNG phụ thuộc `enabled` (nhắc hạn VPN).
  `GET/PUT /api/notify/settings` thêm khoá: cố ý đổi API, ghi lại contract snapshot — lý do: cấu hình cảnh báo F1/F2.
- D7: Nội dung tiếng Việt: tên firewall, site, thời điểm giờ VN, thông điệp lỗi (cắt 500 ký tự), IP drift thêm/bớt + giờ + lý do ngoài giờ
  ("Cuối tuần", "Ngoài giờ 18:00–08:00", "Ngày lễ: …"). Link L2 nếu có APP_BASE_URL.
- D8: Không lệnh ghi mới, không nới policy.py (Quy tắc 1). Không thêm bảng/cột.
- Deferred: gộp nhiều firewall down trong một email (Q2); song song probe.

# Tiêu chí hoàn thành (kiểm chứng được)
- [x] `tests/alerts_test.py` (SQLite + PostgreSQL): firewall trỏ cổng đóng → sau ngưỡng có đúng 1 email `fw_down` (chạy job nhiều lần vẫn 1);
      trỏ lại mock → 1 email `fw_up`; chưa quá ngưỡng → không email; Thông báo tắt / alert_fw_down tắt → không email; audit `fw_health` chỉ ở lần đổi trạng thái.
- [x] Drift: sửa group trên mock ngoài app → probe phát hiện trong cùng lượt → GroupChange drift; drift lúc ngoài giờ → 1 email liệt kê IP; drift trong giờ hành chính → không email nhưng có trong Lịch sử; chạy lại → không trùng; lần đầu / bật lại sau khi tắt không gửi lịch sử; lệnh chặn chen giữa lượt quét → không drift giả.
- [x] `policy_guard_test.py` pass (không lệnh ghi mới); `contract_test.py` pass sau khi ghi lại snapshot có chủ đích; `run_all.sh` pass.
- [x] Cài đặt › Email có 3 ô cấu hình mới (UI smoke). README (biến `FW_HEALTH_MINUTES`, mục cảnh báo), architecture.md, roadmap F1/F2 xong.

# Task
| ID | Mô tả | Phụ thuộc | Rủi ro | Trạng thái |
|----|-------|-----------|--------|------------|
| T-01 | Cấu hình notify (3 khoá) + job fw-health (probe, state, F1 email, audit chuyển trạng thái) + khoá deliver + test | — | Cao | done |
| T-02 | Drift gần thời gian thực (D1b, D1c) + email drift ngoài giờ (D0, D4) + test | T-01 | Cao | done |
| T-03 | Giao diện Cài đặt › Email + ui_smoke + contract snapshot | T-02 | TB | done |
| T-04 | Tài liệu (Opus) | T-03 | Thấp | done |
