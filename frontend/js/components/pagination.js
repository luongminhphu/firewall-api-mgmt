/* Phân trang phía trình duyệt cho bảng dài (vd ~400 rule VPN). */
import { esc } from "../util.js";

export const PAGE_SIZE = 50;

export function pageSlice(rows, page, size = PAGE_SIZE) {
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const p = Math.min(Math.max(1, page), pages);
  return { rows: rows.slice((p - 1) * size, p * size), page: p, pages };
}

/** Vẽ thanh phân trang; onChange(page) khi người dùng chọn trang. Ẩn khi chỉ có một trang. */
export function renderPager(el, { page, pages, total }, onChange) {
  if (pages <= 1) {
    el.innerHTML = total ? `<span class="muted tiny">${total} dòng</span>` : "";
    return;
  }
  el.innerHTML = `
    <button class="btn btn--sm btn--ghost" type="button" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}
      aria-label="Trang trước">‹ Trước</button>
    <span class="tiny" aria-live="polite">Trang <strong>${page}</strong>/${pages} · ${esc(total)} dòng</span>
    <button class="btn btn--sm btn--ghost" type="button" data-page="${page + 1}" ${page >= pages ? "disabled" : ""}
      aria-label="Trang sau">Sau ›</button>`;
  el.onclick = (e) => {
    const b = e.target.closest("[data-page]");
    if (b && !b.disabled) onChange(Number(b.dataset.page));
  };
}
