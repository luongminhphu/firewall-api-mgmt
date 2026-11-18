/* Gọi API: token phiên, lỗi có hướng xử lý (gateway 502/503/504, mất mạng), công việc nền (runJob). */
import { state } from "./store.js";
import { ICON, esc, sleep } from "./util.js";

export const API = (window.__API_BASE__ || "").replace(/\/$/, "");

// Gateway (Entra App Proxy / ingress) trả trang HTML, không phải JSON → dịch sang thông báo có hướng xử lý
export const GATEWAY_MSG = {
  502: "Máy chủ trung gian không nhận được phản hồi hợp lệ từ app (502).",
  503: "App đang khởi động lại hoặc quá tải (503). Thử lại sau ít phút.",
  504: "Máy chủ trung gian hết thời gian chờ (504).",
};

export class ApiError extends Error {
  constructor(message, { status = 0, hint = "" } = {}) {
    super(message);
    this.status = status;
    this.hint = hint;
  }
}

let onUnauthorized = () => {};
/** Đăng ký xử lý khi phiên hết hạn (401) — tránh import vòng giữa api.js và trang đăng nhập. */
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

export async function api(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(`${API}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(state.token ? { "X-Auth-Token": state.token } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Mất kết nối tới máy chủ app.", {
      hint: "Kiểm tra mạng/VPN rồi thử lại. Nếu vừa bấm Chặn/Bỏ chặn, xem tab Lịch sử thay đổi trước khi làm lại.",
    });
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    if (res.status === 401 && state.token) onUnauthorized();
    const writes = method !== "GET";
    throw new ApiError(data?.detail || GATEWAY_MSG[res.status] || `Lỗi máy chủ (${res.status}).`, {
      status: res.status,
      hint:
        !data?.detail && writes && res.status >= 502
          ? "Thao tác có thể vẫn đang chạy trên firewall. Xem tab Lịch sử thay đổi trước khi chạy lại."
          : "",
    });
  }
  return data;
}

/** Gửi lệnh ghi; server chưa xong trong ~20s thì trả status "running" + job_id → hỏi tiến độ tới khi xong. */
export async function runJob(path, body, onProgress) {
  let job = await api(path, { method: "POST", body });
  onProgress?.(job);
  let misses = 0;
  while (job.status === "running") {
    await sleep(1500);
    try {
      job = await api(`/api/jobs/${encodeURIComponent(job.job_id)}`);
      misses = 0;
      onProgress?.(job);
    } catch (ex) {
      // Mất mạng chốc lát khi đang theo dõi: thử lại, công việc vẫn chạy trên server
      if (++misses >= 8 || ex.status === 404) throw ex;
    }
  }
  if (job.status === "error") {
    throw new ApiError(job.error || "Công việc lỗi", {
      hint: "Kết quả của các firewall đã xong vẫn được ghi trong tab Lịch sử thay đổi.",
    });
  }
  return job;
}

/** Khối lỗi dùng chung: tiêu đề + chi tiết + gợi ý xử lý. */
export function errorBox(ex, title = "Không thực hiện được") {
  return `<div class="alert alert--error alert--rich" role="alert">
    ${ICON.alert}
    <div><strong>${esc(title)}</strong><p>${esc(ex.message)}</p>${
      ex.hint ? `<p class="alert__hint">${esc(ex.hint)}</p>` : ""
    }</div></div>`;
}
