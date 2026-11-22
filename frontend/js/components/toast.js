/* Thông báo nổi ngắn (#toast). Trình đọc màn hình đọc được (aria-live); lỗi đọc ngay (assertive) và
   KHÔNG tự tắt — người trực có thể đang nhìn chỗ khác — đóng bằng nút ✕ hoặc khi có thông báo mới. */
import { $ } from "../util.js";

export function toast(msg, kind = "") {
  const el = $("#toast");
  const err = kind === "err";
  el.setAttribute("aria-live", err ? "assertive" : "polite");
  el.className = `toast ${kind ? "toast--" + kind : ""}`;
  el.innerHTML = `<span></span><button type="button" class="toast__x" aria-label="Đóng thông báo">✕</button>`;
  el.firstChild.textContent = msg;
  clearTimeout(toast._t);
  if (!err) toast._t = setTimeout(() => el.classList.add("hidden"), 5000);
}

$("#toast").addEventListener("click", (e) => {
  if (e.target.closest(".toast__x")) e.currentTarget.classList.add("hidden");
});
