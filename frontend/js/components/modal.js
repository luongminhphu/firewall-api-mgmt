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
// Đổi tab (hash) hoặc bấm Back: hộp thoại thuộc trang cũ → đóng, không đè lên trang mới
window.addEventListener("hashchange", closeModal);
$("#modal").addEventListener("close", () => {
  returnFocus?.focus?.();
  returnFocus = null;
});

/** Xác nhận trong app thay cho confirm() của trình duyệt: nêu rõ sẽ làm gì, nút chính ghi đúng hành động.
    danger=true → nút đỏ, focus mặc định ở Hủy (Enter vô tình không thực thi). Esc / bấm nền = Hủy. */
export function confirmAction({ title, html, ok, danger = true }) {
  const dlg = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-body").innerHTML = html;
  const okBtn = $("#confirm-ok");
  okBtn.textContent = ok;
  okBtn.className = `btn ${danger ? "btn--danger" : "btn--primary"}`;
  const back = document.activeElement;
  return new Promise((resolve) => {
    // Kết quả chốt ĐỒNG BỘ ngay lúc bấm / Esc — không dựa vào sự kiện "close" (phát bất đồng bộ: Esc rồi mở lại
    // ngay thì "close" của lần trước tới trễ và hủy nhầm lần mới)
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      dlg.removeEventListener("click", onClick);
      dlg.removeEventListener("cancel", onCancel);
      window.removeEventListener("hashchange", onNav);
      if (dlg.open) dlg.close();
      back?.focus?.();
      resolve(v);
    };
    const onClick = (e) => {
      if (e.target === okBtn) finish(true);
      else if (e.target.closest("#confirm-cancel") || e.target === dlg) finish(false);
    };
    const onCancel = (e) => {
      e.preventDefault();
      finish(false);
    };
    const onNav = () => finish(false); // đổi tab giữa chừng = Hủy
    dlg.addEventListener("click", onClick);
    dlg.addEventListener("cancel", onCancel);
    window.addEventListener("hashchange", onNav, { once: true });
    dlg.showModal();
    (danger ? $("#confirm-cancel") : okBtn).focus();
  });
}
