/* Hộp thoại dùng chung (<dialog id="modal">): Esc đóng, focus nằm trong hộp thoại, đóng xong trả focus về chỗ cũ. */
import { $ } from "../util.js";

let returnFocus = null;

export function openModal(title, html) {
  const dlg = $("#modal");
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = html;
  returnFocus = document.activeElement;
  if (!dlg.open) dlg.showModal();
  dlg.querySelector("[data-close]")?.focus();
}

export function closeModal() {
  const dlg = $("#modal");
  if (dlg.open) dlg.close();
}

$("#modal").addEventListener("click", (e) => {
  if (e.target.closest("[data-close]") || e.target === e.currentTarget) closeModal(); // nút Đóng / bấm nền
});
$("#modal").addEventListener("close", () => {
  returnFocus?.focus?.();
  returnFocus = null;
});
