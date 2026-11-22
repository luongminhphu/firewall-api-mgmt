/* Tiện ích DOM / định dạng dùng chung. */
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const fmtTime = (iso) => {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", { hour12: false, timeZone: "Asia/Ho_Chi_Minh" });
};

export const ICON = {
  alert:
    '<svg class="ic" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  x: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
};

/** Mã nội bộ (người thực hiện / nguồn) → nhãn tiếng Việt; mã lạ giữ nguyên. */
const ACTOR_LABEL = {
  autoblock: "Tự động chặn (Teams)", "ngoai-app": "Ngoài app (sửa trực tiếp trên firewall)", "he-thong": "Hệ thống",
  "teams-auto": "Tự động từ Teams", "teams-paste": "Dán từ Teams", paste: "Dán từ Teams", manual: "Nhập tay",
  csv: "File CSV/TXT", unblock: "Bỏ chặn",
};
export const actorLabel = (v) => ACTOR_LABEL[v] || v;

/** Thông báo thường gặp của Sophos API (tiếng Anh) → tiếng Việt; không khớp thì giữ nguyên. */
export function fwMessage(msg) {
  const m = String(msg || "");
  const rules = [
    [/^Host group "?(.+?)"? has been updated successfully\.?$/i, (g) => `Đã cập nhật group ${g}`],
    [/^Configuration applied successfully\.?$/i, () => "Đã áp dụng cấu hình"],
    [/^Authentication Successful\.?$/i, () => "Đăng nhập API thành công"],
    [/^Operation Successful\.?$/i, () => "Thao tác thành công"],
    [/^Entity having same name already exists\.?$/i, () => "Đã có object cùng tên"],
  ];
  for (const [re, fn] of rules) {
    const x = m.match(re);
    if (x) return fn(x[1]);
  }
  return m;
}
