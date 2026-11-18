/* Phiên đăng nhập: form mật khẩu, SSO Microsoft (tự động / nút), header SSO qua App Proxy, Thoát. */
import { api, API, setUnauthorizedHandler } from "./api.js";
import { state, tokenStore as store } from "./store.js";
import { $ } from "./util.js";
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
    await afterLogin();
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove("hidden");
  }
});

export function showLoginError(msg) {
  const err = $("#login-error");
  err.textContent = msg;
  err.classList.remove("hidden");
}

export async function initLogin() {
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
export const sess = (() => { try { return window.sessionStorage; } catch { return null; } })();

$("#local-toggle").addEventListener("click", () => {
  $("#local-box").classList.remove("hidden");
  $("#local-toggle").classList.add("hidden");
  $("#login-user").focus();
});

export function autoSso(modes) {
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

export async function tryHeaderSso() {
  try {
    const r = await api("/api/auth/header", { method: "POST" });
    state.token = r.token;
    store?.setItem("sb_token", r.token);
    await afterLogin();
    return true;
  } catch {
    return false;
  }
}

export function logout(manual) {
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

let afterLogin = async () => {};
/** main.js đăng ký hàm khởi động app sau khi có token (tránh import vòng session ↔ main). */
export function setAfterLogin(fn) {
  afterLogin = fn;
}
