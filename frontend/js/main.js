/* SOC Rapid Block — điểm khởi động frontend (ES module, không build step) */
import { API, api, errorBox, runJob, setUnauthorizedHandler } from "./api.js";
import { resultChip, statusChip } from "./components/badge.js";
import { progressBox, reduceMotion, setBusy } from "./components/progress.js";
import { toast } from "./components/toast.js";
import { loadAudit } from "./pages/audit.js";
import { loadChanges } from "./pages/changes.js";
import { loadFirewalls } from "./pages/firewalls.js";
import { loadGroupsForSelectedFw, watchCache } from "./pages/groups.js";
import { loadUsers } from "./pages/users.js";
import { initRouter, showInitial } from "./router.js";
import { can, on, ROLE_LABEL, state, tokenStore as store } from "./store.js";
import { $, $$, ICON, esc } from "./util.js";

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

on("firewalls", () => renderFwPicker());

function renderFwPicker() {
  const box = $("#fw-picker");
  const list = state.firewalls.filter((f) => f.enabled);
  const keep = new Set(
    $$("#fw-picker input[type=checkbox]:checked").map((b) => b.value)
  );
  if (!list.length) {
    box.innerHTML = `<p class="empty">Chưa có firewall nào đang bật. Sang tab <strong>Firewall</strong> để thêm.</p>`;
    return;
  }
  box.innerHTML = list
    .map(
      (f) => `<label class="fw-opt">
        <input type="checkbox" value="${f.id}" ${
          keep.has(String(f.id)) || (!keep.size && list.length === 1) ? "checked" : ""
        } />
        <span class="fw-opt__body">
          <span class="fw-opt__name">${esc(f.name)}${f.site ? ` · ${esc(f.site)}` : ""}</span>
          <span class="fw-opt__meta">${esc(f.host)}:${f.port} → ${esc(state.blockGroup)}</span>
        </span>
        ${statusChip(f)}
      </label>`
    )
    .join("");
  refreshBlockButton();
}

$("#pick-all-fw").addEventListener("click", () => {
  const boxes = $$("#fw-picker input[type=checkbox]");
  const allOn = boxes.every((b) => b.checked);
  boxes.forEach((b) => (b.checked = !allOn));
  refreshBlockButton();
});
$("#fw-picker").addEventListener("change", refreshBlockButton);

const selectedFwIds = () =>
  $$("#fw-picker input[type=checkbox]:checked").map((b) => Number(b.value));

// ------------------------------------------------------- nguồn IP & danh sách
$("#source-seg").addEventListener("click", (e) => {
  const btn = e.target.closest(".seg-btn");
  if (!btn) return;
  state.source = btn.dataset.src;
  $$(".seg-btn", $("#source-seg")).forEach((b) => b.classList.toggle("is-active", b === btn));
  $$("[data-src-body]").forEach((b) =>
    b.classList.toggle("hidden", b.dataset.srcBody !== state.source)
  );
});

let parseTimer;
$("#paste-text").addEventListener("input", () => {
  clearTimeout(parseTimer);
  parseTimer = setTimeout(() => parseText($("#paste-text").value), 350);
});

async function parseText(text, { replace = true } = {}) {
  if (!text.trim()) {
    if (replace) {
      state.candidates = [];
      renderCandidates([]);
    }
    return;
  }
  try {
    const r = await api("/api/parse", { method: "POST", body: { text } });
    const incoming = r.accepted.map((a) => ({ value: a.value, kind: a.kind, object: a.object }));
    state.candidates = replace
      ? incoming
      : [...state.candidates, ...incoming.filter((i) => !state.candidates.some((c) => c.value === i.value))];
    renderCandidates(r.rejected);
  } catch (ex) {
    toast(ex.message, "err");
  }
}

function renderCandidates(rejected = []) {
  const box = $("#candidate-list");
  $("#count-chip").textContent = `${state.candidates.length} IP`;
  if (!state.candidates.length) {
    box.innerHTML = `<p class="empty">Chưa có IP nào. Dán nội dung chat hoặc nhập tay ở cột bên trái.</p>`;
  } else {
    box.innerHTML = state.candidates
      .map(
        (c, i) => `<div class="cand">
          <span class="chip ${c.kind === "Network" ? "chip--info" : ""}">${c.kind === "Network" ? "CIDR" : "IP"}</span>
          <span class="cand__ip">${esc(c.value)}</span>
          ${
            c.object && c.object !== c.value // từ v1.4 tên object = chính IP → chỉ hiện khi khác
              ? `<span class="cand__obj" title="Tên object trên firewall">${esc(c.object)}</span>`
              : ""
          }
          <button class="cand__x" type="button" data-i="${i}" aria-label="Bỏ ${esc(c.value)} khỏi danh sách" title="Bỏ khỏi danh sách">${ICON.x}</button>
        </div>`
      )
      .join("");
  }
  const rbox = $("#rejected-box");
  if (rejected.length) {
    rbox.innerHTML =
      `<strong>Đã loại ${rejected.length} mục:</strong><br />` +
      rejected
        .slice(0, 12)
        .map((r) => `<code>${esc(r.value)}</code> — ${esc(r.reason)}`)
        .join("<br />") +
      (rejected.length > 12 ? `<br />… và ${rejected.length - 12} mục khác` : "");
    rbox.classList.remove("hidden");
  } else {
    rbox.classList.add("hidden");
  }
  refreshBlockButton();
}

$("#candidate-list").addEventListener("click", (e) => {
  const btn = e.target.closest(".cand__x");
  if (!btn) return;
  state.candidates.splice(Number(btn.dataset.i), 1);
  renderCandidates();
});

$("#clear-list").addEventListener("click", () => {
  state.candidates = [];
  $("#paste-text").value = "";
  $("#csv-info").textContent = "";
  renderCandidates([]);
  $("#block-result").innerHTML = "";
});

function refreshBlockButton() {
  $("#do-block").disabled = !can("operator") || !(state.candidates.length && selectedFwIds().length);
}

const addManual = () => {
  const v = $("#manual-ip").value.trim();
  if (!v) return;
  parseText(v, { replace: false });
  $("#manual-ip").value = "";
};
$("#manual-add").addEventListener("click", addManual);
$("#manual-ip").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    addManual();
  }
});

// CSV / TXT
const dz = $("#dropzone");
dz.addEventListener("click", () => $("#csv-file").click());
["dragenter", "dragover"].forEach((ev) =>
  dz.addEventListener(ev, (e) => {
    e.preventDefault();
    dz.classList.add("is-over");
  })
);
["dragleave", "drop"].forEach((ev) =>
  dz.addEventListener(ev, () => dz.classList.remove("is-over"))
);
dz.addEventListener("drop", (e) => {
  e.preventDefault();
  if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]);
});
$("#csv-file").addEventListener("change", (e) => {
  if (e.target.files[0]) readFile(e.target.files[0]);
});

function readFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    $("#csv-info").textContent = `Đã đọc ${file.name} (${Math.round(file.size / 1024)} KB)`;
    parseText(String(reader.result), { replace: false });
  };
  reader.readAsText(file);
}

// ------------------------------------------------------------------ block
$("#do-block").addEventListener("click", async () => {
  const ids = selectedFwIds();
  const dry = $("#dry-run").checked;
  const fwNames = state.firewalls.filter((f) => ids.includes(f.id)).map((f) => f.name);
  if (
    !dry &&
    !confirm(
      `Chặn ${state.candidates.length} IP trên ${ids.length} firewall (${fwNames.join(", ")})?\n` +
        `IP Host Group: ${state.blockGroup}`
    )
  )
    return;

  const btn = $("#do-block");
  const box = $("#block-result");
  setBusy(btn, true, dry ? "Đang chạy thử…" : "Đang đẩy cấu hình…");
  $("#clear-list").disabled = true;
  box.innerHTML = progressBox({ total: ids.length, done: 0, firewalls: ids.map((id, i) => ({ id, name: fwNames[i] })), results: [] }, dry);
  box.scrollIntoView({ block: "nearest", behavior: reduceMotion() ? "auto" : "smooth" }); // điện thoại: kết quả nằm dưới nút
  try {
    const r = await runJob(
      "/api/block",
      {
        firewall_ids: ids,
        values: state.candidates.map((c) => c.value),
        reason: $("#block-reason").value.trim(),
        source: state.source === "paste" ? "teams-paste" : state.source,
        dry_run: dry,
      },
      (job) => {
        if (job.status === "running") box.innerHTML = progressBox(job, dry) + renderBlockResult(job);
      }
    );
    box.innerHTML = blockSummary(r, dry) + renderBlockResult(r);
    if (r.cache_refresh?.length) watchCache(r.cache_refresh);
    const okCount = r.results.filter((x) => x.ok).length;
    toast(
      dry
        ? "Chạy thử xong — chưa ghi gì lên firewall"
        : `Hoàn tất trên ${okCount}/${r.results.length} firewall`,
      okCount === r.results.length ? "ok" : "err"
    );
  } catch (ex) {
    box.innerHTML = errorBox(ex, dry ? "Chạy thử không thành công" : "Chặn IP không thành công");
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Chặn ngay");
  $("#clear-list").disabled = false;
  refreshBlockButton();
  loadFirewalls();
});

/** Tóm tắt cuối cùng ở đầu kết quả: tổng thêm / đã có / lỗi trên mọi firewall. */
function blockSummary(r, dry) {
  const t = { added: 0, existed: 0, error: 0, dry_run: 0 };
  r.results.forEach((x) => Object.keys(t).forEach((k) => (t[k] += x.summary?.[k] || 0)));
  const fwErr = r.results.filter((x) => !x.ok).length;
  const cls = fwErr ? "alert--warn" : "alert--ok";
  const parts = dry
    ? [`${t.dry_run} sẽ tạo`, `${t.existed} đã có`]
    : [`${t.added} đã thêm`, `${t.existed} đã có`, `${t.error} lỗi`];
  return `<div class="alert ${cls} result-summary" role="status">
    <strong>${dry ? "Chạy thử xong" : fwErr ? `Xong, ${fwErr}/${r.results.length} firewall có lỗi` : "Đã chặn xong"}</strong>
    <span>${r.results.length} firewall · ${parts.join(" · ")}</span>
  </div>`;
}

const ROWS_OPEN_MAX = 5; // nhiều dòng hơn thì thu gọn (tổng kết đã nằm ở đầu), luôn mở sẵn khi có lỗi

function renderBlockResult(r) {
  return (r.results || [])
    .map((fw) => {
      const s = fw.summary || {};
      const head = `<div class="result-fw__head">
          <span>${esc(fw.firewall)}</span>
          ${fw.ok ? '<span class="chip chip--ok">OK</span>' : '<span class="chip chip--err">Có lỗi</span>'}
          <span class="muted tiny">thêm ${s.added || 0} · đã có ${s.existed || 0} · lỗi ${s.error || 0}${
            s.dry_run ? ` · chạy thử ${s.dry_run}` : ""
          }</span>
        </div>`;
      if (fw.error) {
        return `<div class="result-fw">${head}<div class="result-row result-row--err">${esc(fw.error)}</div></div>`;
      }
      const rows = (fw.rows || [])
        .map(
          (row) => `<div class="result-row">
            ${resultChip(row.result)}
            <span class="mono">${esc(row.value)}</span>
            ${row.object && row.object !== row.value ? `<span class="muted tiny mono">${esc(row.object)}</span>` : ""}
            <span class="result-row__msg">${esc(row.code ? row.code + " · " : "")}${esc(row.message)}</span>
          </div>`
        )
        .join("");
      const open = (fw.rows || []).length <= ROWS_OPEN_MAX || (s.error || 0) > 0;
      const list = `<details class="result-rows"${open ? " open" : ""}>
          <summary>Chi tiết ${(fw.rows || []).length} IP</summary>${rows}</details>`;
      const xml = fw.group_xml
        ? `<details class="xml-preview"${s.dry_run ? " open" : ""}>
            <summary>Payload IPHostGroup ${s.dry_run ? "dự kiến" : "đã gửi"} ·
              <span class="mono">Set operation="${esc(fw.group_operation)}"</span> · ${esc(fw.ip_family || "IPv4")}</summary>
            <pre class="mono">${esc(fw.group_xml)}</pre>
          </details>`
        : "";
      return `<div class="result-fw">${head}${list}${xml}</div>`;
    })
    .join("");
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
