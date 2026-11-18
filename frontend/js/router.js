/* Điều hướng tab qua location.hash (#block, #groups, …): deep link, nút Back/Forward của trình duyệt.
   Hash có dấu "=" (vd #sso=… từ Entra) không phải tab — main.js xử lý và xóa trước khi router chạy. */
import { $, $$ } from "./util.js";

const DEFAULT_TAB = "block";
let onShow = () => {};

const tabFromHash = () => {
  const h = location.hash.replace(/^#/, "");
  return /^[a-z]+$/.test(h) ? h : null;
};

const available = (name) => {
  const btn = $(`.tab[data-tab="${name}"]`);
  return btn && !btn.classList.contains("hidden") ? btn : null;
};

/** Hiện tab `name` (tab ẩn theo quyền / không tồn tại → tab mặc định) rồi gọi onShow để trang tải dữ liệu. */
export function show(name) {
  const btn = available(name) || available(DEFAULT_TAB);
  const tab = btn.dataset.tab;
  $$(".tab").forEach((t) => {
    t.classList.toggle("is-active", t === btn);
    t.setAttribute("aria-selected", String(t === btn));
  });
  $$(".panel").forEach((p) => p.classList.toggle("is-active", p.dataset.panel === tab));
  onShow(tab);
  return tab;
}

/** Chuyển tab do người dùng chọn: ghi vào lịch sử trình duyệt (Back quay lại tab trước). */
export function go(name) {
  if (tabFromHash() === name) show(name);
  else location.hash = name; // → hashchange → show()
}

/** Gắn sự kiện; `showFn(tab)` được gọi mỗi lần một tab hiện ra. */
export function initRouter(showFn) {
  onShow = showFn;
  $("#tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (btn) go(btn.dataset.tab);
  });
  window.addEventListener("hashchange", () => {
    const t = tabFromHash();
    if (t) show(t);
  });
}

/** Sau khi đăng nhập (đã biết quyền): mở đúng tab theo deep link; không có hash thì giữ tab mặc định. */
export function showInitial() {
  const t = tabFromHash();
  return t ? show(t) : null;
}
