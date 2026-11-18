/* Nhãn kết quả (chip) dùng chung cho chặn / bỏ chặn / audit. */
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
