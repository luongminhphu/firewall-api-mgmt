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
    [/^Host "?(.+?)"? has been added successfully\.?$/i, (h) => `Đã thêm object ${h}`],
    [/^Host "?(.+?)"? has been (deleted|removed) successfully\.?$/i, (h) => `Đã xóa object ${h}`],
    [/^Host has been deleted successfully\.?$/i, () => "Đã xóa object"],
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

/** Ngày hôm nay (hoặc `d`) theo giờ Việt Nam, dạng YYYY-MM-DD. */
export const vnDay = (d = new Date()) => d.toLocaleDateString("en-CA", { timeZone: "Asia/Ho_Chi_Minh" });

/** Đếm ô lọc đang có giá trị trong một hộp "Lọc" và ghi vào dòng "· n đang áp dụng". */
export const filterCount = (box) => {
  const n = [...box.querySelectorAll("input, select")].filter((el) => el.value && el.type !== "checkbox").length;
  box.querySelector(".filter-count").textContent = n ? `· ${n} đang áp dụng` : "";
};

/** Deep link: gán `params` (URLSearchParams) vào ô lọc theo `spec` {khoá: "#id"}; chỉ gán .value, bỏ khoá không hợp lệ.
    Có ít nhất một khoá hợp lệ (hoặc `extra` = true, vd khoá không phải ô nhập) → đặt rỗng `reset` trước, mở hộp lọc, cập nhật đếm. Trả về true nếu đã áp. */
export function applyFilterParams(params, spec, reset, extra = false) {
  if (!(params instanceof URLSearchParams)) return false; // gọi từ sự kiện / nơi khác: không có link
  const ok = [];
  for (const [key, id] of Object.entries(spec)) {
    const el = $(id);
    const v = (params.get(key) ?? "").slice(0, 120);
    if (!v) continue;
    if (el.tagName === "SELECT" ? ![...el.options].some((o) => o.value === v) : el.type === "date" && !/^\d{4}-\d{2}-\d{2}$/.test(v)) continue;
    ok.push([el, v]);
  }
  // link có khoá của trang (kể cả giá trị sai, vd firewall đã xoá) → vẫn đặt lại: kết quả theo link, không lẫn bộ lọc cũ
  if (!Object.keys(spec).some((k) => params.has(k)) && !extra) return false;
  reset.forEach((id) => { $(id).value = ""; });
  ok.forEach(([el, v]) => { el.value = v; });
  new Set([...reset, ...Object.values(spec)].map((id) => $(id).closest("[data-filter-box]")).filter(Boolean)).forEach((box) => {
    box.open = true;
    filterCount(box);
  });
  return true;
}
