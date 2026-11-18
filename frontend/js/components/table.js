/* Trạng thái bảng dùng chung: đang tải / trống / lỗi (một dòng trải hết số cột). */
import { esc } from "../util.js";

export function tableMessage(tbody, colspan, kind, text = "") {
  const inner = {
    loading: `<div class="skeleton"></div>`,
    empty: `<p class="empty">${esc(text)}</p>`,
    error: `<p class="alert alert--error">${esc(text)}</p>`,
  }[kind];
  tbody.innerHTML = `<tr><td colspan="${colspan}">${inner}</td></tr>`;
}
