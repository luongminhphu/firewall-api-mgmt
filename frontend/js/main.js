/* SOC Rapid Block — điểm ghép nối frontend (ES module, không build step):
   khởi động sau đăng nhập (boot), điều hướng tab, phân quyền giao diện, sáng/tối, trình tự đăng nhập lúc mở trang.
   Nghiệp vụ từng màn hình nằm ở pages/*, dùng chung ở api.js / store.js / components/*. */
import { API, api } from "./api.js";
import { openModal } from "./components/modal.js";
import { initTips } from "./components/tips.js";
import { toast } from "./components/toast.js";
import { loadAudit } from "./pages/audit.js";
import { loadAutoblock } from "./pages/autoblock.js";
import { loadBranding } from "./pages/branding.js";
import { loadChanges } from "./pages/changes.js";
import { loadFirewalls } from "./pages/firewalls.js";
import { loadGroupsForSelectedFw } from "./pages/groups.js";
import { loadUsers } from "./pages/users.js";
import { loadReports } from "./pages/reports.js";
import { loadReview } from "./pages/review.js";
import { loadSettings } from "./pages/settings.js";
import { loadVpn } from "./pages/vpn.js";
import { initRouter, showInitial } from "./router.js";
import { autoSso, initLogin, logout, sess, setAfterLogin, showLoginError, tryHeaderSso } from "./session.js";
import { can, ROLE_LABEL, state, tokenStore as store } from "./store.js";
import { $, $$, esc } from "./util.js";
// Các trang tự gắn sự kiện khi được nạp (kể cả trang không export gì cho main, vd Chặn nhanh)
import "./pages/block.js";

async function boot() {
  state.config = await api("/api/config");
  state.user = state.config.user;
  state.role = state.config.role || "viewer";
  state.blockGroup = state.config.block_group || state.blockGroup;
  if (state.config.auth_method === "entra-oidc" || state.config.auth_method === "entra-header") {
    try { localStorage.setItem("sb_last_upn", state.config.user); } catch {}
  }
  sess?.removeItem("sb_no_auto");
  sess?.removeItem("sb_auto_ts");
  $$(".js-block-group").forEach((el) => (el.textContent = state.blockGroup));
  $("#login-screen").classList.add("hidden");
  $("#app").classList.remove("hidden");
  const display = state.config.name || state.config.user;
  const initials = display.split(/[\s.@_-]+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase();
  $("#who").innerHTML = `<span class="avatar" aria-hidden="true">${esc(initials || "?")}</span>
    <span class="who__text"><span class="who__name">${esc(display)}</span>
    <span class="role-chip">${esc(ROLE_LABEL[state.role] || state.role)}</span></span>`;
  $("#app-version").textContent = `v${state.config.version}`;
  $("#who").title = `${state.config.user} · ${state.config.auth_method} · v${state.config.version}`;
  // Vai trò Rà soát (đại diện team, không là người dùng app): chỉ tab Rà soát, không gọi API nào khác
  const reviewerOnly = state.role === "reviewer";
  $$(".tab").forEach((t) => t.classList.toggle("hidden", reviewerOnly && t.dataset.tab !== "review"));
  if (reviewerOnly) {
    loadBranding();
    showInitial();
    return;
  }
  $("#a-export").href = `${API}/api/audit.csv?token=${encodeURIComponent(state.token)}`;
  applyRole();
  $("#tab-users").classList.toggle("hidden", !can("admin"));
  $("#tab-settings").classList.toggle("hidden", !can("admin"));
  $("#my-pass-btn").classList.toggle("hidden", !state.config.can_change_password);
  if (!state.config.master_key_set) {
    toast("Chưa cấu hình MASTER_KEY — không thể lưu credential firewall", "err");
  }
  await loadFirewalls();
  loadBranding();
  showInitial(); // deep link #tab (tab không được phép → Chặn nhanh)
  refreshPendingBadge();
  window.clearInterval(boot._badge);
  boot._badge = window.setInterval(refreshPendingBadge, 60000);
}

async function refreshPendingBadge() {
  if (!state.token || document.hidden) return; // tab ẩn: không poll; quay lại tab thì cập nhật ngay
  try {
    const s = await api("/api/autoblock/status");
    const b = $("#ab-badge");
    b.hidden = !s.pending;
    b.textContent = s.pending > 99 ? "99+" : String(s.pending || "");
    b.setAttribute("aria-label", `${s.pending} lệnh chờ duyệt`);
  } catch {
    /* không đọc được trạng thái (mất mạng / hết phiên): giữ huy hiệu cũ */
  }
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshPendingBadge(); });
setAfterLogin(boot);
initTips(); // nút ⓘ hướng dẫn cạnh các mục cấu hình

// ------------------------------------------------------------------- tabs
// Menu trái: trên màn hình hẹp là ngăn kéo (nút ☰), chọn mục xong tự đóng.
function setNav(open) {
  $("#app").classList.toggle("nav-open", open);
  $("#nav-scrim").hidden = !open;
  $("#nav-toggle").setAttribute("aria-expanded", String(open));
  if (open) $(".tab.is-active")?.focus();
}
$("#nav-toggle").addEventListener("click", () => setNav(!$("#app").classList.contains("nav-open")));
$("#nav-scrim").addEventListener("click", () => setNav(false));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("#app").classList.contains("nav-open")) {
    setNav(false);
    $("#nav-toggle").focus();
  }
});

// Bộ lọc gom trong "Lọc": desktop mở sẵn; điện thoại thu gọn để bảng không bị đẩy xuống. Đếm bộ lọc đang áp dụng.
const filterCount = (box) => {
  const n = [...box.querySelectorAll("input, select")].filter((el) => el.value && el.type !== "checkbox").length;
  box.querySelector(".filter-count").textContent = n ? `· ${n} đang áp dụng` : "";
};
$$("[data-filter-box]").forEach((box) => {
  box.open = !box.hasAttribute("data-collapsed") && window.matchMedia("(min-width: 721px)").matches;
  ["input", "change"].forEach((ev) => box.addEventListener(ev, () => filterCount(box)));
  filterCount(box);
});

// Phím tắt cho người dùng thường xuyên (ca trực): Ctrl/⌘+Enter chặn, "/" tìm/lọc, "?" bảng phím tắt
const SHORTCUTS = [
  ["Ctrl / ⌘ + Enter", "Chặn nhanh: mở màn xác nhận chặn (khi nút Chặn ngay đang bật)"],
  ["/", "Đưa con trỏ vào ô tìm kiếm / lọc đầu tiên của trang"],
  ["Esc", "Đóng hộp thoại, tooltip, menu (trên màn xác nhận = Hủy)"],
  ["?", "Mở bảng phím tắt này"],
];
document.addEventListener("keydown", (e) => {
  if (!state.token || document.querySelector("dialog[open]")) return;
  const typing = e.target.closest?.("input, textarea, select, [contenteditable]");
  const panel = $(".panel.is-active");
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && panel?.id === "panel-block") {
    e.preventDefault();
    if (!$("#do-block").disabled) $("#do-block").click();
    else $("#block-hint").focus?.();
    return;
  }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "/") {
    const f = panel?.querySelector('input[type="search"], .filters input:not([type="date"]):not([type="checkbox"]), textarea');
    if (f && f.offsetParent) {
      e.preventDefault();
      f.focus();
      f.select?.();
    }
  } else if (e.key === "?") {
    e.preventDefault();
    openModal("Phím tắt", `<dl class="confirm-facts kbd-list">${SHORTCUTS.map(([k, d]) =>
      `<dt><kbd>${esc(k)}</kbd></dt><dd>${esc(d)}</dd>`).join("")}</dl>`);
  }
});

initRouter((tab) => {
  const btn = $(`.tab[data-tab="${tab}"]`);
  $("#page-title").textContent = btn?.querySelector("span")?.textContent.trim() || btn?.textContent.trim() || ""; // bỏ huy hiệu số
  document.title = `${$("#page-title").textContent} · SOC Rapid Block`;
  setNav(false);
  if (tab === "audit") loadAudit();
  if (tab === "changes") loadChanges();
  if (tab === "groups") loadGroupsForSelectedFw();
  if (tab === "users") loadUsers();
  if (tab === "vpn") loadVpn();
  if (tab === "settings") loadSettings();
  if (tab === "review") loadReview();
  if (tab === "autoblock") loadAutoblock();
  if (tab === "reports") loadReports();
});

// Giao diện sáng/tối: chế độ ban đầu đã được áp dụng trong <head> (index.html); bấm đổi → ghi nhớ cho lần sau
$("#theme-toggle").addEventListener("click", () => {
  const el = document.documentElement;
  el.dataset.theme = el.dataset.theme === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("sb_theme", el.dataset.theme);
  } catch {
    /* trình duyệt chặn lưu trữ (chế độ riêng tư) — vẫn đổi được, chỉ không nhớ */
  }
});

// ------------------------------------------------------------ phân quyền
function applyRole() {
  const viewer = !can("operator");
  // Chỉ xem: nói rõ ngay đầu trang Chặn nhanh và khóa form, thay vì để điền xong mới biết
  $("#block-ro").hidden = !viewer;
  $$("#panel-block textarea, #panel-block input, #panel-block .seg-btn, #manual-add, #dropzone").forEach((el) => {
    el.disabled = viewer;
  });
  const fwFormCard = $("#fw-form")?.closest(".card");
  if (fwFormCard) fwFormCard.hidden = !can("admin");
  $("#test-all").hidden = viewer;
  $("#c-sync").hidden = viewer;
  $("#v-sync").hidden = viewer;
  $("#do-block").title = viewer ? "Vai trò Chỉ xem không được chặn IP" : "";
  $("#do-unblock").title = viewer ? "Vai trò Chỉ xem không được bỏ chặn" : "";
  if (viewer) toast("Bạn đang có quyền Chỉ xem — liên hệ quản trị viên nếu cần quyền Thao tác", "");
}

// --------------------------------------------------------- khởi động
(async () => {
  // 1) Kết quả trả về từ Entra ID (OIDC callback chuyển hướng về /#sso=...)
  const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
  if (hash.has("sso") || hash.has("sso_error")) {
    history.replaceState(null, "", location.pathname + location.search);
  }
  loadBranding(); // logo cũng hiện ở màn hình đăng nhập (endpoint công khai)
  const modes = await initLogin();
  if (hash.has("sso_error")) {
    showLoginError("Đăng nhập Microsoft thất bại: " + hash.get("sso_error"));
    return;
  }
  if (hash.has("sso")) {
    state.token = hash.get("sso");
    store?.setItem("sb_token", state.token);
    try {
      await boot();
      return;
    } catch (ex) {
      logout();
      showLoginError(ex.message);
      return;
    }
  }
  // 2) Phiên đã lưu
  let saved = "";
  try {
    saved = store?.getItem("sb_token") || "";
  } catch {}
  if (saved) {
    state.token = saved;
    try {
      await boot();
      return;
    } catch {
      logout();
    }
  }
  // 3) Header SSO qua Entra Application Proxy
  if (modes?.header && (await tryHeaderSso())) return;
  // 4) SSO Microsoft tự động: đã xác thực ở App Proxy → Entra trả về ngay, không hỏi mật khẩu/MFA lần 2
  autoSso(modes);
})();

// Đoạn giới thiệu dài ở đầu thẻ: thu gọn thành nút ⓘ cạnh tiêu đề (bấm để đọc) — trạng thái trước, giải thích khi cần
$$(".card-head > div:first-child > p.muted.tiny:not([id])").forEach((p, i) => {
  if (p.textContent.trim().length < 90) return;
  const h = p.parentElement.querySelector("h2, h3");
  if (!h) return;
  p.id = p.id || `card-intro-${i}`;
  p.hidden = true;
  const b = document.createElement("button");
  b.type = "button";
  b.className = "intro-toggle";
  b.setAttribute("aria-expanded", "false");
  b.setAttribute("aria-controls", p.id);
  b.setAttribute("aria-label", `Giải thích: ${h.textContent.trim().slice(0, 60)}`);
  b.textContent = "i";
  b.addEventListener("click", () => {
    p.hidden = !p.hidden;
    b.setAttribute("aria-expanded", String(!p.hidden));
  });
  h.append(b);
});
