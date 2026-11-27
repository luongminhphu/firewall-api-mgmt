/* Điều hướng tab qua location.hash (#block, #groups, …): deep link, nút Back/Forward của trình duyệt.
   Hash có dấu "=" (vd #sso=… từ Entra) không phải tab — main.js xử lý và xóa trước khi router chạy. */
import { $, $$ } from "./util.js";

let DEFAULT_TAB = "block";
/** Tab mặc định theo vai trò (hash rỗng / không hợp lệ); main.js đặt sau khi biết quyền. */
export const setDefaultTab = (name) => { DEFAULT_TAB = name; };
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
  // tab ẩn theo quyền → tab mặc định → tab đầu tiên còn hiện (vd vai trò Rà soát chỉ có một tab)
  const btn = available(name) || available(DEFAULT_TAB) || $$(".tab").find((t) => !t.classList.contains("hidden"));
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
    if ($("#app").classList.contains("hidden")) return; // chưa đăng nhập / đã thoát: không tải trang nào
    show(tabFromHash() || DEFAULT_TAB); // hash rỗng (vd Back về URL không hash) → tab mặc định
  });
}

/** Sau khi đăng nhập (đã biết quyền): mở đúng tab theo deep link; không có hash → tab mặc định được phép. */
export function showInitial() {
  return show(tabFromHash() || DEFAULT_TAB);
}
