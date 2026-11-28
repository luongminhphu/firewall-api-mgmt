# Mục tiêu
Deep link có tham số `#<tab>?<khoá>=<giá trị>` (roadmap L2): mở thẳng một trang với bộ lọc điền sẵn — từ Tổng quan, từ kết quả chặn,
hoặc dán link vào email / ticket. Ví dụ `#changes?q=1.2.3.4`, `#changes?fw=2&type=drift`, `#vpn?status=expired_enabled`, `#groups?fw=2&q=1.2.3.4`, `#audit?q=1.2.3.4`.

# Ngoài phạm vi
- Ghi ngược bộ lọc người dùng tự chỉnh vào URL (URL "chia sẻ được" của trạng thái hiện tại) — làm sau nếu cần.
- API mới (L3 tra cứu IP), lối tắt trên trang Firewall (L5), VPN ↔ Rà soát (L4).

# Ràng buộc & quyết định
- D1: Chỉ frontend, không đổi API (contract không đổi).
- D2: Cú pháp `#tab?k=v&k2=v2` (URLSearchParams). Router nhận `^[a-z]+(\?.*)?$`; tab vẫn chỉ chữ thường. Hash `#sso=…`/`#sso_error=…` giữ nguyên xử lý cũ (main.js đọc trước router).
- D3: Khoá được hỗ trợ (danh sách trắng, khoá khác bỏ qua):
  - `changes`: `fw` (id firewall) → `#c-fw`, `type` → `#c-type`, `q` → `#c-q`, `actor` → `#c-actor`, `from`/`to` (YYYY-MM-DD) → `#c-from`/`#c-to`
  - `audit`: `q` → `#a-search`, `action` → `#a-action`
  - `groups`: `fw` → `#g-fw`, `q` → `#g-search`
  - `vpn`: `fw` → `#vr-fw`, `q` → `#vr-q`, `status` → bộ lọc chip `vs.status` (chỉ giá trị có trong danh sách chip), view rule
- D4: Chỉ gán `.value` (không bao giờ innerHTML); `select` chỉ nhận giá trị có trong option (sau khi option đã được điền); ngày phải đúng `YYYY-MM-DD`; chuỗi cắt ≤ 120 ký tự. Giá trị không hợp lệ → bỏ qua khoá đó, không lỗi.
- D5: Khi có tham số: các ô lọc KHÔNG có trong link được đặt lại rỗng (link cho kết quả xác định, không lẫn bộ lọc cũ). Khi không có tham số (bấm menu): giữ bộ lọc người dùng như hiện tại.
- D6: Cùng tab, đổi tham số → tải lại với bộ lọc mới (hashchange). Tab không được phép → tab mặc định như cũ (bỏ tham số).
- D7: Dùng ngay: Tổng quan (mục "Cần xử lý" theo firewall → `#groups?fw=<id>`, drift → `#changes?type=drift&from=<VN−6>`, VPN hết hạn còn bật → `#vpn?status=expired_enabled`, sắp hết hạn → `#vpn?status=expiring`); kết quả Chặn nhanh "Xem lịch sử thay đổi" → `#changes?q=<IP đầu tiên>` nếu chặn 1 IP, hoặc theo khoảng thời gian hôm nay.
- D9: Không bao giờ nhận tham số cho tab có thao tác ghi tự do (#block: ô IP, lý do). Chỉ tab trong D3. (C-07)
- D10: Link sống sót qua SSO (C-01); go() cùng tab xoá `?` cũ (C-06); D5 sửa theo C-02; áp tham số trong hàm load của trang, 1 request (C-03).
- D8: Một hàm dựng link dùng chung (vd `link(tab, params)` trong router.js) để không ai tự ghép chuỗi hash.

# Tiêu chí hoàn thành (kiểm chứng được)
- [x] ui_smoke: mở `#changes?q=1.2.3.4` → `#c-q` = "1.2.3.4" và request `/api/changes` có `q=1.2.3.4`; `#changes?fw=<id>&type=drift` → select đúng; `#vpn?status=expired_enabled` → chip đó active; `#groups?fw=<id>` → `#g-fw` đúng; `#audit?q=x` → `#a-search` = x.
- [x] Giá trị xấu (`fw=999999`, `from=abc`, `q=<script>`, khoá lạ) → không lỗi JS, không chèn HTML, khoá bị bỏ qua.
- [x] Bấm menu sau đó → bộ lọc không bị xoá (D5). Back giữa hai link khác tham số → bộ lọc theo link.
- [x] SSO `#sso=` vẫn chạy (oidc/sso test hiện có pass); vai trò Rà soát mở `#vpn?…` → vẫn chỉ tab Rà soát.
- [x] Tổng quan: bấm mục VPN hết hạn → `#vpn?status=expired_enabled`, chip active.
- [x] `bash tests/run_all.sh` pass; contract không đổi. README 6.x ghi cú pháp link; architecture.md; roadmap L2 xong.

# Task
| ID | Mô tả | Phụ thuộc | Rủi ro | Trạng thái |
|----|-------|-----------|--------|------------|
| T-01 | Router (parse, `link()`, params cho onShow, go() cùng tab), main.js truyền params, giữ link qua SSO, siết SSO hash | — | TB | done |
| T-02 | 4 trang nhận params trong hàm load (changes, audit, groups, vpn) + C-02, C-04, C-05 | T-01 | TB | done |
| T-03 | Dùng link: overview.js, block.js (D7) | T-02 | Thấp | done |
| T-04 | ui_smoke khẳng định theo tiêu chí + C-03 (1 request), D9 | T-03 | Thấp | done |
| T-05 | Tài liệu (Opus) | T-04 | Thấp | done |
