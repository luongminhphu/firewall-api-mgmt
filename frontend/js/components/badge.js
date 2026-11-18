/* Nhãn (chip) dùng chung: kết quả chặn / bỏ chặn / audit; trạng thái kết nối firewall. */
import { esc } from "../util.js";

const RESULT = {
  added: ["chip--ok", "đã thêm"],
  existed: ["chip--info", "đã có"],
  removed: ["chip--ok", "đã bỏ"],
  not_found: ["chip--warn", "không thấy"],
  error: ["chip--err", "lỗi"],
  "dry-run": ["chip--warn", "chạy thử"],
};

export const resultChip = (res) => {
  const [cls, label] = RESULT[res] || ["", res];
  return `<span class="chip ${cls}">${label}</span>`;
};

/** Trạng thái kết nối lần kiểm tra gần nhất của firewall. */
export function statusChip(fw) {
  const map = {
    ok: ["chip--ok", "Kết nối OK"],
    error: ["chip--err", "Lỗi kết nối"],
    auth_error: ["chip--err", "Sai tài khoản"],
    unknown: ["", "Chưa kiểm tra"],
  };
  const [cls, label] = map[fw.last_status] || map.unknown;
  return `<span class="chip ${cls}" title="${esc(fw.last_message || "")}">${label}</span>`;
}
