# CHALLENGES — L2 deep link

## C-01 [Major] Deep link mất khi phải đăng nhập lại qua OIDC
- Quyết định của Opus: Accepted → lưu hash vào sessionStorage trước khi chuyển hướng SSO (autoSso + nút SSO), khôi phục sau `#sso=`, qua cùng bộ kiểm tra. T-01.

## C-02 [Major] D5 mơ hồ: ô lọc không có khoá (vr-team/from/to/asof) và #g-fw không có option rỗng
- Quyết định của Opus: Accepted → có tham số thì đặt lại MỌI ô lọc của trang + vs.status + vs.page=1; riêng #g-fw giữ nguyên khi link thiếu/sai fw. T-02.

## C-03 [Major] Áp tham số từ main.js gây tải hai lần (VPN showView tự load)
- Quyết định của Opus: Accepted → mỗi trang nhận params trong hàm load của nó, áp xong tải đúng một lần; cấm dispatchEvent. Test đếm 1 request / lần điều hướng. T-02, T-04.

## C-04 [Minor] #c-fw điền option sau API
- Quyết định của Opus: Accepted → fillChangeFilters() lên đầu loadChanges; fw kiểm theo state.firewalls.

## C-05 [Minor] Bộ lọc áp bằng link không hiện (hộp lọc thu gọn, đếm không cập nhật)
- Quyết định của Opus: Accepted → sau khi áp: mở hộp lọc + cập nhật đếm.

## C-06 [Minor] URL cũ sau khi người dùng sửa lọc / bấm menu cùng tab
- Quyết định của Opus: Accepted → go() cùng tab có `?` → replaceState về `#tab`; show() chỉ truyền params khi tab hiển thị đúng tab yêu cầu.

## C-07 [Q] Tham số cho tab có thao tác ghi; `#x?sso=` bị coi là SSO
- Quyết định của Opus: Accepted → quyết định D9: không bao giờ có khoá cho #block (ô IP, lý do) — test `#block?ip=1.2.3.4` → ô trống. Siết SSO: chỉ khi hash BẮT ĐẦU bằng `sso=` / `sso_error=`.

## C-08 [Major] Link toàn giá trị xấu không đặt lại bộ lọc cũ (lệch C-02, Sonnet tự chọn ở T-02)
- Nguồn: Gate 2 (F1). Opus trước đó tạm chấp nhận lệch; Fable đưa kịch bản mới (link ticket cũ trỏ firewall đã xoá hiện dữ liệu theo bộ lọc cũ).
- Quyết định của Opus: Accepted → đặt lại khi params có BẤT KỲ khoá nào của trang (params.has), kể cả giá trị sai; VPN tính khoá status. #g-fw vẫn giữ.

## C-09 [Minor] Gate 2 F2–F4, Q1
- F2 #groups?fw sai im lặng hiện firewall khác: Accepted → toast cảnh báo.
- F3 sb_return_hash còn lại khi SSO lỗi: Accepted → xoá trong boot().
- F4 test Back rỗng → T-04 sửa; vnDay lặp → Accepted, chuyển vào util.js.
- Q1 thoát thủ công để lại #tab?q=… trên máy dùng chung: Accepted → logout(true) xoá hash.
