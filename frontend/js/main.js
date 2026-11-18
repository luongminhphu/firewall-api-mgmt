/* SOC Rapid Block — điểm khởi động frontend (ES module, không build step) */
import { API, api, setUnauthorizedHandler } from "./api.js";
import { toast } from "./components/toast.js";
import { loadAudit } from "./pages/audit.js";
import { loadChanges } from "./pages/changes.js";
import { loadFirewalls } from "./pages/firewalls.js";
import { loadGroupsForSelectedFw } from "./pages/groups.js";
import { loadUsers } from "./pages/users.js";
import { initRouter, showInitial } from "./router.js";
// Các trang tự gắn sự kiện khi được nạp (kể cả trang không export gì cho main, vd Chặn nhanh)
import "./pages/block.js";
import { can, ROLE_LABEL, state, tokenStore as store } from "./store.js";
import { $, $$, esc } from "./util.js";

// ------------------------------------------------------------------ login
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-error");
  err.classList.add("hidden");
  try {
    const r = await api("/api/login", {
      method: "POST",
      body: { user: $("#login-user").value, password: $("#login-pass").value },
    });
    state.token = r.token;
    state.user = r.user;
    store?.setItem("sb_token", r.token);
    await boot();
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove("hidden");
  }
});

function showLoginError(msg) {
  const err = $("#login-error");
  err.textContent = msg;
  err.classList.remove("hidden");
}

async function initLogin() {
  try {
    const m = await api("/api/auth/modes");
    state.authModes = m;
    // Có SSO Microsoft → form mật khẩu thu gọn thành đường khẩn cấp
    $("#local-box").classList.toggle("hidden", !m.local || m.oidc);
    $("#local-toggle").classList.toggle("hidden", !(m.local && m.oidc));
    $("#sso-box").classList.toggle("hidden", !m.oidc);
    if (m.oidc && !m.oidc_ready) {
      $("#sso-hint").textContent = "Đăng nhập Microsoft chưa cấu hình đủ: " + m.oidc_message;
      $("#sso-hint").classList.remove("hidden");
    }
    $("#sso-btn").href = ssoUrl();
    return m;
  } catch {
    return null;
  }
}

// UPN lần đăng nhập Microsoft trước → login_hint để Entra chọn đúng tài khoản, không hiện bảng chọn
function ssoUrl() {
  let hint = "";
  try { hint = localStorage.getItem("sb_last_upn") || ""; } catch {}
  return `${API}/api/auth/oidc/login` + (hint ? `?hint=${encodeURIComponent(hint)}` : "");
}
const sess = (() => { try { return window.sessionStorage; } catch { return null; } })();

$("#local-toggle").addEventListener("click", () => {
  $("#local-box").classList.remove("hidden");
  $("#local-toggle").classList.add("hidden");
  $("#login-user").focus();
});

function autoSso(modes) {
  if (!modes?.oidc_auto) return false;
  if (sess?.getItem("sb_no_auto") === "1") return false; // vừa bấm Thoát → không tự đăng nhập lại
  const last = Number(sess?.getItem("sb_auto_ts") || 0);
  if (Date.now() - last < 60_000) return false; // chống vòng lặp chuyển hướng
  sess?.setItem("sb_auto_ts", String(Date.now()));
  $("#sso-auto").classList.remove("hidden");
  $("#sso-box").classList.add("hidden");
  location.replace(ssoUrl());
  return true;
}

async function tryHeaderSso() {
  try {
    const r = await api("/api/auth/header", { method: "POST" });
    state.token = r.token;
    store?.setItem("sb_token", r.token);
    await boot();
    return true;
  } catch {
    return false;
  }
}

function logout(manual) {
  state.token = "";
  store?.removeItem("sb_token");
  if (manual === true) {
    sess?.setItem("sb_no_auto", "1");
    if (state.authModes?.oidc) {
      $("#sso-hint").textContent = "Đã thoát khỏi app. Bấm nút trên để vào lại bằng tài khoản Microsoft.";
      $("#sso-hint").className = "alert alert--info";
    }
  }
  $("#app").classList.add("hidden");
  $("#login-screen").classList.remove("hidden");
}
$("#logout").addEventListener("click", () => logout(true));
setUnauthorizedHandler(() => logout());

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
  $("#who").innerHTML = `${esc(state.config.name || state.config.user)} <span class="role-chip">· ${esc(
    ROLE_LABEL[state.role] || state.role
  )}</span>`;
  $("#who").title = `${state.config.user} · ${state.config.auth_method} · v${state.config.version}`;
  $("#a-export").href = `${API}/api/audit.csv?token=${encodeURIComponent(state.token)}`;
  applyRole();
  $("#tab-users").classList.toggle("hidden", !can("admin"));
  $("#my-pass-btn").classList.toggle("hidden", !state.config.can_change_password);
  if (!state.config.master_key_set) {
    toast("Chưa cấu hình MASTER_KEY — không thể lưu credential firewall", "err");
  }
  await loadFirewalls();
  loadBranding();
  showInitial(); // deep link #tab (tab không được phép → Chặn nhanh)
}

// ---------------------------------------------------------------- branding
const brandState = { hasLogo: false, url: "", maxKb: 300, pending: null };
async function loadBranding() {
  try {
    const r = await api("/api/branding");
    brandState.hasLogo = !!r.has_logo;
    brandState.url = r.logo_url ? `${API}${r.logo_url}` : "";
    brandState.maxKb = r.logo_max_kb || 300;
  } catch {
    brandState.hasLogo = false;
  }
  $$(".js-brand-logo").forEach((img) => {
    if (brandState.hasLogo) {
      img.src = brandState.url;
      img.hidden = false;
    } else {
      img.removeAttribute("src");
      img.hidden = true;
    }
  });
  $$(".js-brand-divider").forEach((el) => (el.hidden = !brandState.hasLogo));
  $$(".js-default-logo").forEach((el) => el.classList.toggle("hidden", brandState.hasLogo));
  renderLogoCard();
}

function renderLogoCard() {
  const box = $("#logo-preview");
  if (!box) return;
  $("#logo-max").textContent = brandState.maxKb;
  const src = brandState.pending?.dataUrl || (brandState.hasLogo ? brandState.url : "");
  box.innerHTML = src
    ? `<img src="${esc(src)}" alt="Xem trước logo" />`
    : `<span class="muted tiny">Chưa có logo — đang dùng biểu tượng mặc định</span>`;
  $("#logo-save").disabled = !brandState.pending;
  $("#logo-save").classList.toggle("btn--primary", !!brandState.pending);
  $("#logo-remove").disabled = !brandState.hasLogo || !!brandState.pending;
}

function logoMsg(text, kind) {
  const el = $("#logo-msg");
  el.textContent = text;
  el.className = `alert alert--${kind}`;
  if (!text) el.className = "alert hidden";
}

$("#logo-pick").addEventListener("click", () => $("#logo-file").click());
$("#logo-file").addEventListener("change", (e) => {
  const f = e.target.files[0];
  e.target.value = "";
  if (!f) return;
  const okType = ["image/png", "image/jpeg", "image/webp", "image/svg+xml"].includes(f.type);
  if (!okType) return logoMsg("Chỉ nhận PNG, JPG, WebP hoặc SVG.", "error");
  if (f.size > brandState.maxKb * 1024)
    return logoMsg(`Tệp ${Math.ceil(f.size / 1024)} KB vượt giới hạn ${brandState.maxKb} KB.`, "error");
  const reader = new FileReader();
  reader.onload = () => {
    brandState.pending = { dataUrl: reader.result, name: f.name };
    logoMsg(`Xem trước ${f.name} — bấm Lưu logo để áp dụng cho mọi người dùng.`, "info");
    renderLogoCard();
  };
  reader.readAsDataURL(f);
});
$("#logo-save").addEventListener("click", async () => {
  if (!brandState.pending) return;
  const btn = $("#logo-save");
  btn.disabled = true;
  try {
    await api("/api/branding/logo", { method: "PUT", body: { data_url: brandState.pending.dataUrl } });
    brandState.pending = null;
    logoMsg("Đã lưu logo.", "ok");
    toast("Đã cập nhật logo", "ok");
    await loadBranding();
  } catch (ex) {
    logoMsg(ex.message, "error");
    renderLogoCard();
  }
});
$("#logo-remove").addEventListener("click", async () => {
  if (!confirm("Gỡ logo và dùng lại biểu tượng mặc định?")) return;
  try {
    await api("/api/branding/logo", { method: "DELETE" });
    logoMsg("Đã gỡ logo.", "ok");
    await loadBranding();
  } catch (ex) {
    logoMsg(ex.message, "error");
  }
});

// ------------------------------------------------------------------- tabs
initRouter((tab) => {
  if (tab === "audit") loadAudit();
  if (tab === "changes") loadChanges();
  if (tab === "groups") loadGroupsForSelectedFw();
  if (tab === "users") loadUsers();
});

$("#theme-toggle").addEventListener("click", () => {
  const el = document.documentElement;
  el.dataset.theme = el.dataset.theme === "dark" ? "light" : "dark";
});
if (window.matchMedia && !window.matchMedia("(prefers-color-scheme: dark)").matches) {
  document.documentElement.dataset.theme = "light";
}

// ------------------------------------------------------------ phân quyền
function applyRole() {
  const viewer = !can("operator");
  const fwFormCard = $("#fw-form")?.closest(".card");
  if (fwFormCard) fwFormCard.hidden = !can("admin");
  $("#test-all").hidden = viewer;
  $("#c-sync").hidden = viewer;
  $("#do-block").title = viewer ? "Vai trò Chỉ xem không được chặn IP" : "";
  $("#do-unblock").title = viewer ? "Vai trò Chỉ xem không được bỏ chặn" : "";
  if (viewer) toast("Bạn đang có quyền Readonly — liên hệ quản trị viên nếu cần quyền Write", "");
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
