# Mục tiêu
Trang **Tổng quan** (`#overview`) cho IT Infrastructure Manager: một màn hình trả lời "hôm nay có gì cần xử lý" xuyên các module
(firewall, tự động chặn, IP Host Group, VPN, rà soát, email, số liệu 7 ngày), mỗi thẻ bấm được để mở đúng tab xử lý.
Roadmap: `docs/roadmap-infra.md` mục L1.

# Ngoài phạm vi
- API mới / đổi response (để dành L3 tra cứu IP, L6 `/api/overview/counts`).
- Deep link có tham số `#tab?ip=` (L2, làm sau) — thẻ chỉ mở tab.
- Tự làm mới theo chu kỳ (chỉ tải khi mở tab + nút "Làm mới").

# Ràng buộc & quyết định
- D1: **Chỉ frontend**, gọi API sẵn có, `contract_test.py` không đổi snapshot. Gọi song song bằng `Promise.allSettled`; thẻ nào lỗi / 403 thì hiện "Không đọc được" riêng thẻ đó, không làm hỏng trang.
- D2: API dùng: `/api/firewalls`, `/api/group-cache`, `/api/autoblock/status`, `/api/vpn/rules` (`summary`, `syncs`), `/api/review/campaigns`, `/api/reports/summary?days=7`, `/api/notify/outbox?status=failed` (**chỉ admin** gọi — vai trò khác không gọi, không hiện thẻ). Tất cả còn lại cần quyền Readonly (viewer) trở lên — đã kiểm ở router.
- D3: Vai trò Rà soát không thấy tab Tổng quan (main.js đã ẩn mọi tab trừ review; REVIEWER_PATHS chặn ở API).
- D4: Trang mặc định khi không có hash: **Quản trị viên → `overview`**; Write / Readonly giữ **Chặn nhanh** (ca trực SOC ban đêm cần vào thẳng màn chặn). Giả định — người dùng có thể đổi.
- D5: Nhóm menu mới đầu tiên "Tổng quan" (trên "Vận hành"). Giao diện tiếng Việt có dấu, dùng lại class sẵn có (`.stat`, `.status-card`, chip trạng thái) + token theme (sáng/tối), theo skill `ui-ux-pro-max` / `impeccable`; điện thoại 390px không cuộn ngang.
- D7: Drift 7 ngày: `/api/changes?type=drift&from=…&limit=500` → `totals.drift` (C-01). Email lỗi: chỉ thư `created_at` trong 7 ngày, chỉ số lượng + loại (C-02). Sức khoẻ firewall: group-cache + VPN syncs là tín hiệu chính, `last_status` phụ kèm `last_checked` (C-03). Ngày "hôm nay" theo giờ VN: lấy `today` từ `/api/vpn/rules`.
- D8: Router: hash rỗng / không hợp lệ → tab mặc định theo vai trò, kể cả khi bấm Back (C-04, C-06). Đang tải thì không gọi chồng (C-05). Mọi chuỗi từ API qua `esc()`.
- D6: Thứ tự: khối "Cần xử lý" (chỉ các mục có vấn đề, sắp theo mức nghiêm trọng) ở trên, rồi các thẻ module; khi không có gì cần xử lý hiện câu chốt "Không có việc cần xử lý".

# Tiêu chí hoàn thành (kiểm chứng được)
- [x] `tests/ui_smoke_test.py`: admin không hash → vào Tổng quan; có đủ thẻ; bấm thẻ VPN → `#vpn` active; Readonly không hash → Chặn nhanh, thấy tab Tổng quan nhưng không có thẻ email và không gọi `/api/notify/outbox`; không lỗi JS; điện thoại 390px không cuộn ngang; từ Tổng quan bấm thẻ VPN rồi Back → về lại Tổng quan.
- [x] Thẻ lỗi riêng lẻ: một API trả lỗi → thẻ đó báo "Không đọc được", thẻ khác vẫn hiện (kiểm bằng route chặn trong Playwright).
- [x] `frontend_lint_test.py`, `contract_test.py` (không ghi snapshot), `bash tests/run_all.sh` pass.
- [x] README (tính năng, mục 6 hướng dẫn tab), architecture.md nhật ký, roadmap đánh dấu L1 xong.

# Task
| ID | Mô tả | Phụ thuộc | Rủi ro | Trạng thái |
|----|-------|-----------|--------|------------|
| T-01 | `pages/overview.js` + tab/panel trong `index.html` + CSS + nối `main.js` + trang mặc định theo vai trò trong `router.js` | — | TB | done |
| T-02 | Bổ sung `tests/ui_smoke.cjs` theo tiêu chí trên | T-01 | Thấp | done |
| T-03 | Tài liệu (README, architecture.md, roadmap) | T-02 | Thấp | done |
