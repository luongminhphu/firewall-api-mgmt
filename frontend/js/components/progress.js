/* Phản hồi khi chờ: nút bận (spinner + aria-busy) và khung tiến độ theo firewall của công việc nền. */
import { esc } from "../util.js";

export const reduceMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

export function setBusy(btn, busy, label) {
  // nhớ nhãn gốc khi bắt đầu chạy → kết thúc không truyền nhãn thì trả lại nhãn gốc (không để nút trống chữ)
  if (busy && btn.dataset.idleLabel === undefined) btn.dataset.idleLabel = btn.textContent.trim();
  btn.disabled = busy;
  btn.setAttribute("aria-busy", String(busy));
  if (busy) {
    btn.innerHTML = `<span class="spinner spinner--btn" aria-hidden="true"></span>${esc(label ?? "")}`;
  } else {
    btn.textContent = label ?? btn.dataset.idleLabel ?? "";
    delete btn.dataset.idleLabel;
  }
}

/** Tiến độ khi đang chạy: thanh tiến độ + trạng thái từng firewall (đang chờ / xong / lỗi). */
export function progressBox(job, dry, title = "") {
  const total = job.total || job.firewalls?.length || 0;
  const done = job.results?.length || 0;
  const byId = Object.fromEntries((job.results || []).map((r) => [r.firewall_id, r]));
  const items = (job.firewalls || [])
    .map((f) => {
      const r = byId[f.id];
      const st = !r
        ? '<span class="chip"><span class="spinner spinner--xs" aria-hidden="true"></span>đang xử lý</span>'
        : r.ok
        ? '<span class="chip chip--ok">xong</span>'
        : '<span class="chip chip--err">có lỗi</span>';
      return `<li><span>${esc(f.name)}</span>${st}</li>`;
    })
    .join("");
  return `<div class="progress-box" role="status">
    <div class="progress-box__head">
      <strong>${title || (dry ? "Đang chạy thử" : "Đang đẩy cấu hình")}</strong>
      <span class="muted tiny">${done}/${total} firewall xong</span>
    </div>
    <progress max="${total}" value="${done}" aria-label="Tiến độ theo firewall"></progress>
    ${items ? `<ul class="progress-box__list">${items}</ul>` : ""}
    ${
      job.job_id
        ? `<p class="muted tiny">Firewall phản hồi chậm — công việc chạy nền trên máy chủ. Có thể để trang mở, kết quả sẽ tự hiện.</p>`
        : ""
    }
  </div>`;
}
