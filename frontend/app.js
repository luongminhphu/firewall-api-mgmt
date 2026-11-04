/* SOC Rapid Block — frontend logic (vanilla JS, không build step) */
(() => {
  "use strict";

  const API = (window.__API_BASE__ || "").replace(/\/$/, "");
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    token: "",
    user: "",
    config: null,
    firewalls: [],
    candidates: [], // [{value, kind, object}]
    source: "paste",
    groupMembers: [],
    role: "viewer",
    blockGroup: "SCANPORT GROUP", // cố định phía server; giá trị lấy lại từ /api/config
    authModes: null,
  };

  const RANK = { viewer: 0, operator: 1, admin: 2 };
  const can = (role) => (RANK[state.role] ?? -1) >= RANK[role];
  const ROLE_LABEL = { admin: "Quản trị", operator: "Write", viewer: "Readonly" };

  // ------------------------------------------------------------------ utils
  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  function toast(msg, kind = "") {
    const el = $("#toast");
    el.textContent = msg;
    el.className = `toast ${kind ? "toast--" + kind : ""}`;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), 4200);
  }

  // Lưu token: dùng bộ nhớ trình duyệt nếu được phép, nếu không thì chỉ giữ trong RAM
  const store = (() => {
    try {
      const s = window["local" + "Storage"];
      s.setItem("_sb_probe", "1");
      s.removeItem("_sb_probe");
      return s;
    } catch {
      return null;
    }
  })();

  async function api(path, { method = "GET", body } = {}) {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(state.token ? { "X-Auth-Token": state.token } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      if (res.status === 401 && state.token) logout();
      throw new Error(data?.detail || `Lỗi ${res.status}`);
    }
    return data;
  }

  const fmtTime = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleString("vi-VN", { hour12: false, timeZone: "Asia/Ho_Chi_Minh" });
  };

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
      $("#local-box").classList.toggle("hidden", !m.local);
      $("#sso-box").classList.toggle("hidden", !m.oidc);
      $("#sso-divider").classList.toggle("hidden", !(m.oidc && m.local));
      if (m.oidc && !m.oidc_ready) {
        $("#sso-hint").textContent = "Đăng nhập Microsoft chưa cấu hình đủ: " + m.oidc_message;
        $("#sso-hint").classList.remove("hidden");
      }
      $("#sso-btn").href = `${API}/api/auth/oidc/login`;
      return m;
    } catch {
      return null;
    }
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

  function logout() {
    state.token = "";
    store?.removeItem("sb_token");
    $("#app").classList.add("hidden");
    $("#login-screen").classList.remove("hidden");
  }
  $("#logout").addEventListener("click", logout);

  async function boot() {
    state.config = await api("/api/config");
    state.user = state.config.user;
    state.role = state.config.role || "viewer";
    state.blockGroup = state.config.block_group || state.blockGroup;
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
  }

  // ------------------------------------------------------------------- tabs
  $("#tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (!btn) return;
    $$(".tab").forEach((t) => t.classList.toggle("is-active", t === btn));
    $$(".panel").forEach((p) => p.classList.toggle("is-active", p.dataset.panel === btn.dataset.tab));
    if (btn.dataset.tab === "audit") loadAudit();
    if (btn.dataset.tab === "changes") loadChanges();
    if (btn.dataset.tab === "groups") loadGroupsForSelectedFw();
    if (btn.dataset.tab === "users") loadUsers();
  });

  $("#theme-toggle").addEventListener("click", () => {
    const el = document.documentElement;
    el.dataset.theme = el.dataset.theme === "dark" ? "light" : "dark";
  });
  if (window.matchMedia && !window.matchMedia("(prefers-color-scheme: dark)").matches) {
    document.documentElement.dataset.theme = "light";
  }

  // ------------------------------------------------------------- firewalls
  async function loadFirewalls() {
    state.firewalls = await api("/api/firewalls");
    renderFwPicker();
    renderFwList();
    renderFwSelect();
  }

  function statusChip(fw) {
    const map = {
      ok: ["chip--ok", "Kết nối OK"],
      error: ["chip--err", "Lỗi kết nối"],
      auth_error: ["chip--err", "Sai tài khoản"],
      unknown: ["", "Chưa kiểm tra"],
    };
    const [cls, label] = map[fw.last_status] || map.unknown;
    return `<span class="chip ${cls}" title="${esc(fw.last_message || "")}">${label}</span>`;
  }

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

  function renderFwList() {
    const box = $("#fw-list");
    if (!state.firewalls.length) {
      box.innerHTML = `<p class="empty">Chưa khai báo firewall nào.</p>`;
      return;
    }
    box.innerHTML = state.firewalls
      .map(
        (f) => `<article class="fw-card">
        <div class="fw-card__top">
          <span class="fw-card__title">${esc(f.name)}</span>
          ${statusChip(f)}
          ${f.enabled ? "" : '<span class="chip chip--warn">Đang tắt</span>'}
          <span class="fw-card__acts">
            ${can("operator") ? `<button class="btn btn--sm" data-act="test" data-id="${f.id}">Kiểm tra</button>` : ""}
            ${can("admin") ? `<button class="btn btn--sm" data-act="edit" data-id="${f.id}">Sửa</button>
            <button class="btn btn--sm btn--ghost" data-act="del" data-id="${f.id}">Xóa</button>` : ""}
          </span>
        </div>
        <dl class="fw-card__grid">
          <div><dt>Địa chỉ</dt><dd>${esc(f.host)}:${f.port}</dd></div>
          <div><dt>Tài khoản</dt><dd>${esc(f.username)}</dd></div>
          <div><dt>IP Host Group</dt><dd>${esc(state.blockGroup)}</dd></div>
          <div><dt>Site</dt><dd>${esc(f.site || "—")}</dd></div>
          <div><dt>TLS verify</dt><dd>${f.verify_ssl ? "Bật" : "Tắt"}</dd></div>
          <div><dt>Kiểm tra lần cuối</dt><dd>${esc(fmtTime(f.last_checked) || "—")}</dd></div>
        </dl>
        ${f.last_message ? `<p class="tiny muted">${esc(f.last_message)}</p>` : ""}
        ${f.note ? `<p class="tiny muted">Ghi chú: ${esc(f.note)}</p>` : ""}
      </article>`
      )
      .join("");
  }

  $("#fw-list").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const fw = state.firewalls.find((f) => f.id === id);
    if (btn.dataset.act === "test") {
      btn.disabled = true;
      btn.textContent = "Đang kiểm tra…";
      try {
        const r = await api(`/api/firewalls/${id}/test`, { method: "POST" });
        toast(`${r.firewall}: ${r.message}`, r.ok ? "ok" : "err");
      } catch (ex) {
        toast(ex.message, "err");
      }
      await loadFirewalls();
    } else if (btn.dataset.act === "edit") {
      fillFwForm(fw);
    } else if (btn.dataset.act === "del") {
      if (!confirm(`Xóa firewall "${fw.name}" khỏi mini app? (Không ảnh hưởng cấu hình trên firewall)`)) return;
      try {
        await api(`/api/firewalls/${id}`, { method: "DELETE" });
        toast("Đã xóa", "ok");
        await loadFirewalls();
      } catch (ex) {
        toast(ex.message, "err");
      }
    }
  });

  $("#test-all").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const r = await api("/api/firewalls/test-all", { method: "POST", body: {} });
      const ok = r.results.filter((x) => x.ok).length;
      toast(`${ok}/${r.results.length} firewall phản hồi tốt`, ok === r.results.length ? "ok" : "err");
      await loadFirewalls();
    } catch (ex) {
      toast(ex.message, "err");
    }
    e.target.disabled = false;
  });

  function fillFwForm(fw) {
    $("#fw-id").value = fw ? fw.id : "";
    $("#fw-name").value = fw?.name || "";
    $("#fw-site").value = fw?.site || "";
    $("#fw-host").value = fw?.host || "";
    $("#fw-port").value = fw?.port || 4444;
    $("#fw-user").value = fw?.username || "";
    $("#fw-pass").value = "";
    $("#fw-pass").placeholder = fw ? "Bỏ trống = giữ mật khẩu cũ" : "••••••";
    $("#fw-note").value = fw?.note || "";
    $("#fw-verify").checked = !!fw?.verify_ssl;
    $("#fw-enabled").checked = fw ? fw.enabled : true;
    $("#fw-form-title").textContent = fw ? `Sửa: ${fw.name}` : "Thêm firewall";
    $("#fw-form-reset").classList.toggle("hidden", !fw);
    $("#fw-form-msg").classList.add("hidden");
    if (fw) $("#fw-form").scrollIntoView({ behavior: "smooth", block: "center" });
  }
  $("#fw-form-reset").addEventListener("click", () => fillFwForm(null));

  $("#fw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#fw-form-msg");
    const id = $("#fw-id").value;
    const payload = {
      name: $("#fw-name").value,
      site: $("#fw-site").value,
      host: $("#fw-host").value,
      port: Number($("#fw-port").value),
      username: $("#fw-user").value,
      note: $("#fw-note").value,
      verify_ssl: $("#fw-verify").checked,
      enabled: $("#fw-enabled").checked,
    };
    if ($("#fw-pass").value) payload.password = $("#fw-pass").value;
    if (!id && !payload.password) {
      msg.textContent = "Cần nhập mật khẩu khi thêm firewall mới";
      msg.className = "alert alert--error";
      return;
    }
    try {
      await api(id ? `/api/firewalls/${id}` : "/api/firewalls", {
        method: id ? "PUT" : "POST",
        body: payload,
      });
      msg.textContent = id ? "Đã cập nhật firewall" : "Đã thêm firewall";
      msg.className = "alert alert--ok";
      fillFwForm(null);
      await loadFirewalls();
    } catch (ex) {
      msg.textContent = ex.message;
      msg.className = "alert alert--error";
    }
  });

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
            <span class="chip ${c.kind === "Network" ? "chip--info" : ""}">${c.kind}</span>
            <span class="cand__ip">${esc(c.value)}</span>
            <span class="cand__obj">${esc(c.object)}</span>
            <button class="cand__x" data-i="${i}" title="Bỏ khỏi danh sách">✕</button>
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
    btn.disabled = true;
    btn.textContent = dry ? "Đang chạy thử…" : "Đang đẩy cấu hình…";
    $("#block-result").innerHTML = `<div class="skeleton"></div>`;
    try {
      const r = await api("/api/block", {
        method: "POST",
        body: {
          firewall_ids: ids,
          values: state.candidates.map((c) => c.value),
          reason: $("#block-reason").value.trim(),
          source: state.source === "paste" ? "teams-paste" : state.source,
          dry_run: dry,
        },
      });
      renderBlockResult(r);
      const okCount = r.results.filter((x) => x.ok).length;
      toast(
        dry
          ? "Chạy thử xong — chưa ghi gì lên firewall"
          : `Hoàn tất trên ${okCount}/${r.results.length} firewall`,
        okCount === r.results.length ? "ok" : "err"
      );
    } catch (ex) {
      $("#block-result").innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
      toast(ex.message, "err");
    }
    btn.textContent = "Chặn ngay";
    refreshBlockButton();
    loadFirewalls();
  });

  const resultChip = (res) => {
    const map = {
      added: ["chip--ok", "đã thêm"],
      existed: ["chip--info", "đã có"],
      removed: ["chip--ok", "đã bỏ"],
      not_found: ["chip--warn", "không thấy"],
      error: ["chip--err", "lỗi"],
      "dry-run": ["chip--warn", "chạy thử"],
    };
    const [cls, label] = map[res] || ["", res];
    return `<span class="chip ${cls}">${label}</span>`;
  };

  function renderBlockResult(r) {
    const box = $("#block-result");
    box.innerHTML = r.results
      .map((fw) => {
        const s = fw.summary || {};
        const head = `<div class="result-fw__head">
            <span>${esc(fw.firewall)}</span>
            <span class="chip">${esc(fw.group)}</span>
            ${fw.ip_family ? `<span class="chip">IPHostGroup · ${esc(fw.ip_family)}</span>` : ""}
            ${fw.ok ? '<span class="chip chip--ok">OK</span>' : '<span class="chip chip--err">Có lỗi</span>'}
            <span class="muted tiny">thêm ${s.added || 0} · đã có ${s.existed || 0} · lỗi ${s.error || 0}</span>
          </div>`;
        if (fw.error) {
          return `<div class="result-fw">${head}<div class="result-row"><span class="muted">${esc(fw.error)}</span></div></div>`;
        }
        const rows = fw.rows
          .map(
            (row) => `<div class="result-row">
              ${resultChip(row.result)}
              <span class="mono">${esc(row.value)}</span>
              <span class="muted tiny mono">${esc(row.object)}</span>
              <span class="result-row__msg">${esc(row.code ? row.code + " · " : "")}${esc(row.message)}</span>
            </div>`
          )
          .join("");
        const xml = fw.group_xml
          ? `<details class="xml-preview"${fw.summary?.dry_run ? " open" : ""}>
              <summary>Payload IPHostGroup ${fw.summary?.dry_run ? "dự kiến" : "đã gửi"} ·
                <span class="mono">Set operation="${esc(fw.group_operation)}"</span> · ${esc(fw.ip_family || "IPv4")}</summary>
              <pre class="mono">${esc(fw.group_xml)}</pre>
            </details>`
          : "";
        return `<div class="result-fw">${head}${rows}${xml}</div>`;
      })
      .join("");
  }

  // ----------------------------------------------------------- object group
  function renderFwSelect() {
    const sel = $("#g-fw");
    const prev = sel.value;
    sel.innerHTML = state.firewalls
      .map((f) => `<option value="${f.id}">${esc(f.name)}</option>`)
      .join("");
    if (prev) sel.value = prev;
  }

  $("#g-fw").addEventListener("change", loadGroupsForSelectedFw);
  $("#g-reload").addEventListener("click", loadMembers);
  $("#g-search").addEventListener("input", () => renderMembers(filterMembers()));

  async function loadGroupsForSelectedFw() {
    const id = $("#g-fw").value;
    if (!id) return;
    $("#g-meta").innerHTML = `<span class="skeleton" style="width:220px"></span>`;
    try {
      const r = await api(`/api/firewalls/${id}/groups`);
      if (!r.groups.length) {
        $("#g-meta").innerHTML = `<span class="chip chip--err">Chưa có IP Host Group '${esc(
          state.blockGroup
        )}' trên firewall này — admin firewall cần tạo group (IPv4) và gắn vào rule chặn.</span>`;
        renderMembers([]);
        return;
      }
      await loadMembers();
    } catch (ex) {
      $("#g-meta").innerHTML = `<span class="chip chip--err">${esc(ex.message)}</span>`;
      renderMembers([]);
    }
  }

  async function loadMembers() {
    const id = $("#g-fw").value;
    const group = state.blockGroup;
    if (!id) return;
    $("#g-table").querySelector("tbody").innerHTML =
      `<tr><td colspan="5"><div class="skeleton"></div></td></tr>`;
    try {
      const r = await api(
        `/api/firewalls/${id}/group-members?group=${encodeURIComponent(group)}`
      );
      state.groupMembers = r.members;
      $("#g-meta").innerHTML = `
        <span>Firewall: <strong>${esc(r.firewall)}</strong></span>
        <span>Group: <strong>${esc(r.group)}</strong></span>
        <span>Thành viên: <strong>${r.total}</strong></span>
        <span>IP family: ${esc(r.ip_family)}</span>
        ${r.description ? `<span>${esc(r.description)}</span>` : ""}`;
      renderMembers(filterMembers());
    } catch (ex) {
      $("#g-meta").innerHTML = `<span class="chip chip--err">${esc(ex.message)}</span>`;
      renderMembers([]);
    }
  }

  const filterMembers = () => {
    const q = $("#g-search").value.trim().toLowerCase();
    if (!q) return state.groupMembers;
    return state.groupMembers.filter(
      (m) => m.object.toLowerCase().includes(q) || (m.value || "").toLowerCase().includes(q)
    );
  };

  function renderMembers(members) {
    const tb = $("#g-table").querySelector("tbody");
    if (!members.length) {
      tb.innerHTML = `<tr><td colspan="5"><p class="empty">Không có object nào khớp.</p></td></tr>`;
    } else {
      tb.innerHTML = members
        .map(
          (m) => `<tr>
            <td><input type="checkbox" value="${esc(m.object)}" /></td>
            <td class="mono">${esc(m.object)}</td>
            <td>${esc(m.host_type || "—")}</td>
            <td class="mono">${esc(m.value || "—")}</td>
            <td class="muted">${esc(m.description || "")}</td>
          </tr>`
        )
        .join("");
    }
    $("#g-check-all").checked = false;
    refreshUnblockButton();
  }

  $("#g-check-all").addEventListener("change", (e) => {
    $$("#g-table tbody input[type=checkbox]").forEach((c) => (c.checked = e.target.checked));
    refreshUnblockButton();
  });
  $("#g-table").addEventListener("change", refreshUnblockButton);

  const selectedObjects = () =>
    $$("#g-table tbody input[type=checkbox]:checked").map((c) => c.value);

  function refreshUnblockButton() {
    $("#do-unblock").disabled = !can("operator") || selectedObjects().length === 0;
  }

  $("#do-unblock").addEventListener("click", async () => {
    const targets = selectedObjects();
    const fwId = Number($("#g-fw").value);
    const group = state.blockGroup;
    const fw = state.firewalls.find((f) => f.id === fwId);
    if (!confirm(`Bỏ chặn ${targets.length} object khỏi group ${group} trên ${fw.name}?`)) return;
    const btn = $("#do-unblock");
    btn.disabled = true;
    btn.textContent = "Đang xử lý…";
    try {
      const r = await api("/api/unblock", {
        method: "POST",
        body: {
          firewall_ids: [fwId],
          targets,
          delete_object: $("#delete-object").checked,
          reason: "Bỏ chặn từ mini app",
        },
      });
      $("#unblock-result").innerHTML = r.results
        .map((res) => {
          const head = `<div class="result-fw__head"><span>${esc(res.firewall)}</span>
            <span class="chip">${esc(res.group)}</span>
            ${res.ok ? '<span class="chip chip--ok">OK</span>' : '<span class="chip chip--err">Có lỗi</span>'}</div>`;
          if (res.error)
            return `<div class="result-fw">${head}<div class="result-row"><span class="muted">${esc(res.error)}</span></div></div>`;
          const rows = res.rows
            .map(
              (row) => `<div class="result-row">${resultChip(row.result)}
                <span class="mono">${esc(row.object || row.value)}</span>
                <span class="result-row__msg">${esc(row.message)}</span></div>`
            )
            .join("");
          return `<div class="result-fw">${head}${rows}</div>`;
        })
        .join("");
      toast("Đã cập nhật group", "ok");
      await loadMembers();
    } catch (ex) {
      toast(ex.message, "err");
    }
    btn.textContent = "Bỏ chặn mục đã chọn";
    refreshUnblockButton();
  });

  // ------------------------------------------------------------------ audit
  $("#a-reload").addEventListener("click", loadAudit);
  $("#a-action").addEventListener("change", loadAudit);
  let auditTimer;
  $("#a-search").addEventListener("input", () => {
    clearTimeout(auditTimer);
    auditTimer = setTimeout(loadAudit, 300);
  });

  async function loadAudit() {
    const tb = $("#a-table").querySelector("tbody");
    tb.innerHTML = `<tr><td colspan="8"><div class="skeleton"></div></td></tr>`;
    try {
      const params = new URLSearchParams({
        limit: "300",
        action: $("#a-action").value,
        q: $("#a-search").value.trim(),
      });
      const r = await api(`/api/audit?${params}`);
      if (!r.rows.length) {
        tb.innerHTML = `<tr><td colspan="8"><p class="empty">Chưa có bản ghi nào.</p></td></tr>`;
        return;
      }
      const actionLabel = {
        block: "Chặn",
        unblock: "Bỏ chặn",
        test: "Kiểm tra",
        firewall_cud: "Sửa firewall",
      };
      tb.innerHTML = r.rows
        .map(
          (row) => `<tr>
            <td class="mono nowrap">${esc(fmtTime(row.ts))}</td>
            <td class="nowrap">${esc(row.actor)}</td>
            <td class="nowrap">${esc(actionLabel[row.action] || row.action)}</td>
            <td class="nowrap">${esc(row.firewall_name || "—")}</td>
            <td class="mono">${esc(row.group_name || "—")}</td>
            <td class="mono">${esc(row.target)}</td>
            <td>${resultChip(row.result === "ok" ? "added" : row.result)}</td>
            <td class="muted">${esc(row.status_code ? row.status_code + " · " : "")}${esc(row.message)}${
              row.reason ? `<br /><em>${esc(row.reason)}</em>` : ""
            }</td>
          </tr>`
        )
        .join("");
    } catch (ex) {
      tb.innerHTML = `<tr><td colspan="8"><p class="alert alert--error">${esc(ex.message)}</p></td></tr>`;
    }
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

  // ======================================================= NGƯỜI DÙNG
  const userState = { list: [], auth: "local", perm: "readonly", minLen: 10 };

  function segSet(id, v) {
    $$(`#${id} .seg-btn`).forEach((b) => b.classList.toggle("is-active", b.dataset.v === v));
  }
  function permChip(u) {
    if (u.is_admin) return `<span class="chip chip--warn">Quản trị · Write</span>`;
    return u.permission === "write"
      ? `<span class="chip chip--info">Write</span>`
      : `<span class="chip">Readonly</span>`;
  }

  async function loadUsers() {
    const tb = $("#u-table tbody");
    tb.innerHTML = `<tr><td colspan="6"><span class="skeleton"></span></td></tr>`;
    try {
      const r = await api("/api/users");
      userState.list = r.users;
      userState.minLen = r.password_min_length || 10;
      const pol = [];
      pol.push(r.shared_password_login
        ? "Mật khẩu chung APP_PASSWORD đang BẬT (dự phòng khẩn cấp)."
        : "Mật khẩu chung APP_PASSWORD đã tắt.");
      pol.push(r.users_strict
        ? "Đăng nhập Microsoft chỉ chấp nhận người có trong danh sách."
        : "Người dùng Microsoft chưa có trong danh sách sẽ dùng App Role của Entra ID.");
      $("#u-policy").textContent = pol.join(" ");
      renderUsers();
      updateAuthHint();
    } catch (ex) {
      tb.innerHTML = `<tr><td colspan="6"><p class="alert alert--error">${esc(ex.message)}</p></td></tr>`;
    }
  }

  function renderUsers() {
    const q = ($("#u-search").value || "").trim().toLowerCase();
    const rows = userState.list.filter((u) =>
      !q || [u.username, u.display_name, u.permission, u.note, u.is_admin ? "quản trị admin" : ""]
        .join(" ").toLowerCase().includes(q));
    const tb = $("#u-table tbody");
    if (!rows.length) {
      tb.innerHTML = `<tr><td colspan="6" class="muted">${userState.list.length ? "Không có kết quả" : "Chưa có người dùng nào — thêm người đầu tiên ở khung bên phải."}</td></tr>`;
      return;
    }
    tb.innerHTML = rows.map((u) => {
      const self = u.username === state.user;
      return `<tr>
        <td><div class="mono">${esc(u.username)}${self ? ' <span class="muted">(bạn)</span>' : ""}</div>
            <div class="muted">${esc(u.display_name || "")}</div>
            ${u.enabled ? "" : '<span class="chip chip--err only-mobile">Đã khóa</span>'}</td>
        <td class="nowrap">${u.auth_type === "microsoft" ? "Microsoft" : "Mật khẩu"}</td>
        <td>${permChip(u)}</td>
        <td>${u.enabled ? '<span class="chip chip--ok">Hoạt động</span>' : '<span class="chip chip--err">Đã khóa</span>'}</td>
        <td class="nowrap">${esc(fmtTime(u.last_login) || "—")}</td>
        <td class="nowrap">
          <button class="btn btn--sm" data-uact="edit" data-id="${u.id}" type="button">Sửa</button>
          ${self ? "" : `<button class="btn btn--sm btn--danger-ghost" data-uact="del" data-id="${u.id}" type="button">Xóa</button>`}
        </td>
      </tr>`;
    }).join("");
  }

  function updateAuthHint() {
    const local = userState.auth === "local";
    const editing = !!$("#u-id").value;
    $("#u-pass-row").classList.toggle("hidden", !local);
    $("#u-pass-label").textContent = editing ? "Đặt lại mật khẩu (bỏ trống = giữ nguyên)" : "Mật khẩu *";
    $("#u-auth-hint").textContent = local
      ? `Đăng nhập bằng tên + mật khẩu riêng. Tối thiểu ${userState.minLen} ký tự, có chữ và số.`
      : "Đăng nhập bằng tài khoản công ty qua Microsoft (MFA). Tên đăng nhập phải là UPN, vd phu.luong@hsc.com.vn.";
  }

  function resetUserForm() {
    $("#u-form").reset();
    $("#u-id").value = "";
    $("#u-username").disabled = false;
    userState.auth = "local"; userState.perm = "readonly";
    segSet("u-auth", "local"); segSet("u-perm", "readonly");
    $("#u-enabled").checked = true;
    $("#u-form-title").textContent = "Thêm người dùng";
    $("#u-form-reset").classList.add("hidden");
    $("#u-form-msg").classList.add("hidden");
    $("#u-perm").classList.remove("is-disabled");
    updateAuthHint();
  }

  function editUser(u) {
    resetUserForm();
    $("#u-id").value = u.id;
    $("#u-username").value = u.username;
    $("#u-username").disabled = true;
    $("#u-display").value = u.display_name || "";
    $("#u-note").value = u.note || "";
    $("#u-admin").checked = u.is_admin;
    $("#u-enabled").checked = u.enabled;
    userState.auth = u.auth_type; userState.perm = u.permission;
    segSet("u-auth", u.auth_type); segSet("u-perm", u.permission);
    $("#u-perm").classList.toggle("is-disabled", u.is_admin);
    $("#u-form-title").textContent = `Sửa người dùng ${u.username}`;
    $("#u-form-reset").classList.remove("hidden");
    updateAuthHint();
    $("#u-form").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  $("#u-auth").addEventListener("click", (e) => {
    const b = e.target.closest(".seg-btn"); if (!b) return;
    userState.auth = b.dataset.v; segSet("u-auth", b.dataset.v); updateAuthHint();
  });
  $("#u-perm").addEventListener("click", (e) => {
    const b = e.target.closest(".seg-btn"); if (!b || $("#u-admin").checked) return;
    userState.perm = b.dataset.v; segSet("u-perm", b.dataset.v);
  });
  $("#u-admin").addEventListener("change", (e) => {
    if (e.target.checked) { userState.perm = "write"; segSet("u-perm", "write"); }
    $("#u-perm").classList.toggle("is-disabled", e.target.checked);
  });
  $("#u-search").addEventListener("input", renderUsers);
  $("#u-new").addEventListener("click", () => { resetUserForm(); $("#u-username").focus(); });
  $("#u-form-reset").addEventListener("click", resetUserForm);

  $("#u-table").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-uact]"); if (!b) return;
    const u = userState.list.find((x) => String(x.id) === b.dataset.id); if (!u) return;
    if (b.dataset.uact === "edit") return editUser(u);
    if (!confirm(`Xóa người dùng ${u.username}? Phiên đăng nhập hiện tại của người này bị vô hiệu ngay.`)) return;
    try {
      await api(`/api/users/${u.id}`, { method: "DELETE" });
      toast(`Đã xóa ${u.username}`, "ok");
      if ($("#u-id").value === String(u.id)) resetUserForm();
      loadUsers();
    } catch (ex) { toast(ex.message, "err"); }
  });

  $("#u-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#u-form-msg");
    msg.classList.add("hidden");
    const id = $("#u-id").value;
    const pw = $("#u-pass").value, pw2 = $("#u-pass2").value;
    const show = (t, kind = "error") => { msg.textContent = t; msg.className = `alert alert--${kind}`; };
    if (userState.auth === "local" && (pw || !id) && pw !== pw2) return show("Hai lần nhập mật khẩu không khớp");
    const body = {
      display_name: $("#u-display").value,
      auth_type: userState.auth,
      permission: $("#u-admin").checked ? "write" : userState.perm,
      is_admin: $("#u-admin").checked,
      enabled: $("#u-enabled").checked,
      note: $("#u-note").value,
    };
    if (pw) body.password = pw;
    try {
      if (id) {
        await api(`/api/users/${id}`, { method: "PUT", body });
        toast("Đã cập nhật người dùng", "ok");
      } else {
        body.username = $("#u-username").value;
        await api("/api/users", { method: "POST", body });
        toast(`Đã tạo người dùng ${body.username.trim().toLowerCase()}`, "ok");
      }
      resetUserForm();
      loadUsers();
    } catch (ex) { show(ex.message); }
  });

  // Đổi mật khẩu của chính mình
  const pd = $("#pass-dialog");
  $("#my-pass-btn").addEventListener("click", () => {
    $("#pass-form").reset(); $("#pd-msg").classList.add("hidden"); pd.showModal();
  });
  $("#pd-cancel").addEventListener("click", () => pd.close());
  $("#pass-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = $("#pd-msg");
    const show = (t) => { m.textContent = t; m.className = "alert alert--error"; };
    if ($("#pd-new").value !== $("#pd-new2").value) return show("Hai lần nhập mật khẩu mới không khớp");
    try {
      await api("/api/me/password", { method: "POST",
        body: { current_password: $("#pd-cur").value, new_password: $("#pd-new").value } });
      pd.close();
      toast("Đã đổi mật khẩu", "ok");
    } catch (ex) { show(ex.message); }
  });

  // ===================================================== LỊCH SỬ THAY ĐỔI
  const KIND = {
    change: ["", "Thao tác trong app"],
    drift: ["chip--warn", "Thay đổi ngoài app"],
    baseline: ["", "Bắt đầu theo dõi"],
    create_group: ["chip--info", "Tạo group"],
  };
  const SOURCE = { "teams-paste": "Dán từ Teams", paste: "Dán từ Teams", manual: "Nhập tay", csv: "File CSV/TXT", unblock: "Bỏ chặn" };
  const METHOD = { "entra-oidc": "Entra ID + MFA", "entra-header": "Entra App Proxy", local: "Mật khẩu app", drift: "Phát hiện tự động", system: "Hệ thống" };
  const DIFF_PREVIEW = 12;

  function changeParams() {
    const p = new URLSearchParams();
    const add = (k, v) => v && p.set(k, v);
    add("firewall_id", $("#c-fw").value);
    add("type", $("#c-type").value);
    add("q", $("#c-q").value.trim());
    add("actor", $("#c-actor").value.trim());
    add("from", $("#c-from").value);
    add("to", $("#c-to").value);
    return p;
  }

  function fillChangeFilters() {
    const fwSel = $("#c-fw");
    const keepFw = fwSel.value;
    fwSel.innerHTML = `<option value="">Tất cả</option>` +
      state.firewalls.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
    fwSel.value = keepFw;
  }

  function diffList(b) {
    const lines = [
      ...b.added.map((i) => ({ ...i, s: "+", c: "add" })),
      ...b.removed.map((i) => ({ ...i, s: "−", c: "rm" })),
    ];
    if (!lines.length) return "";
    const row = (l, extra) => `<li class="${l.c}${extra ? " extra hidden" : ""}"><span class="sg">${l.s}</span><span>${esc(l.value || "(không rõ IP)")}</span><span class="ob">${esc(l.object)}</span></li>`;
    const head = lines.slice(0, DIFF_PREVIEW).map((l) => row(l, false)).join("");
    const rest = lines.slice(DIFF_PREVIEW);
    return `<ul class="diff">${head}${
      rest.map((l) => row(l, true)).join("")
    }</ul>${rest.length ? `<div class="diff-more"><button type="button" data-more>Xem thêm ${rest.length} dòng</button></div>` : ""}`;
  }

  function renderChanges(r) {
    const t = r.totals;
    $("#c-stats").innerHTML = `
      <div class="stat"><b>${t.batches}</b><span>lần thay đổi</span></div>
      <div class="stat stat--add"><b>+${t.added}</b><span>IP đưa vào group chặn</span></div>
      <div class="stat stat--rm"><b>−${t.removed}</b><span>IP gỡ khỏi group</span></div>
      <div class="stat stat--drift"><b>${t.drift}</b><span>lần sửa ngoài app</span></div>`;
    const box = $("#c-list");
    if (!r.batches.length) {
      box.innerHTML = `<p class="empty">Không có thay đổi nào khớp bộ lọc. Lịch sử bắt đầu ghi từ phiên bản 1.2 — thao tác chặn/bỏ chặn đầu tiên sẽ xuất hiện tại đây.</p>`;
      return;
    }
    box.innerHTML = r.batches.map((b) => {
      const [cls, label] = KIND[b.kind] || KIND.change;
      const delta = b.kind === "baseline"
        ? `<span class="cb__count">${b.count_after} object</span>`
        : `${b.added.length ? `<span class="d-add">+${b.added.length}</span>` : ""}${
            b.removed.length ? `<span class="d-rm">−${b.removed.length}</span>` : ""
          }<span class="cb__count">${b.count_before} → ${b.count_after} object</span>`;
      return `<article class="cb cb--${b.kind}">
        <div class="cb__head">
          <span class="cb__time">${esc(fmtTime(b.ts))}</span>
          <span class="cb__who">${esc(b.actor_name || b.actor)}${
            b.actor && b.actor !== b.actor_name ? `<small>${esc(b.actor)}</small>` : ""
          }</span>
          <span class="chip ${cls}">${label}</span>
          <span class="cb__target">${esc(b.firewall_name)} › ${esc(b.group_name)}</span>
          <span class="cb__delta">${delta}</span>
        </div>
        <div class="cb__meta">
          ${b.reason ? `<span>Lý do: <strong>${esc(b.reason)}</strong></span>` : ""}
          ${b.source ? `<span>Nguồn: ${esc(SOURCE[b.source] || b.source)}</span>` : ""}
          ${b.auth_method ? `<span>Xác thực: ${esc(METHOD[b.auth_method] || b.auth_method)}</span>` : ""}
          ${b.client_ip ? `<span>IP client: <span class="mono">${esc(b.client_ip)}</span></span>` : ""}
          <span class="mono" title="Mã lô thao tác">#${esc(b.batch_id)}</span>
        </div>
        ${diffList(b)}
      </article>`;
    }).join("");
  }

  async function loadChanges() {
    const box = $("#c-list");
    box.innerHTML = `<div class="skeleton"></div><div class="skeleton"></div>`;
    const p = changeParams();
    $("#c-export").href = `${API}/api/changes.csv?token=${encodeURIComponent(state.token)}&${p}`;
    try {
      const r = await api(`/api/changes?${p}`);
      fillChangeFilters();
      renderChanges(r);
    } catch (ex) {
      box.innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
    }
  }

  let changeTimer;
  ["#c-fw", "#c-type", "#c-from", "#c-to"].forEach((id) =>
    $(id).addEventListener("change", loadChanges)
  );
  ["#c-q", "#c-actor"].forEach((id) =>
    $(id).addEventListener("input", () => {
      clearTimeout(changeTimer);
      changeTimer = setTimeout(loadChanges, 350);
    })
  );
  $("#c-list").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-more]");
    if (!btn) return;
    btn.closest(".cb").querySelectorAll(".extra").forEach((li) => li.classList.remove("hidden"));
    btn.parentElement.remove();
  });

  $("#c-sync").addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Đang đọc firewall…";
    try {
      const body = $("#c-fw").value ? { firewall_ids: [Number($("#c-fw").value)] } : {};
      const r = await api("/api/changes/sync", { method: "POST", body });
      const drift = r.results.filter((x) => x.ok && (x.added?.length || x.removed?.length));
      const errs = r.results.filter((x) => !x.ok);
      if (errs.length) toast(`Không đọc được: ${errs.map((x) => x.firewall).join(", ")}`, "err");
      else if (drift.length)
        toast(`Phát hiện thay đổi ngoài app trên ${drift.map((x) => `${x.firewall}/${x.group}`).join(", ")}`, "err");
      else toast(`Đã đối chiếu ${r.results.length} group — không có thay đổi ngoài app`, "ok");
      await loadChanges();
    } catch (ex) {
      toast(ex.message, "err");
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  });

  $("#c-verify").addEventListener("click", async () => {
    const el = $("#c-verify-msg");
    try {
      const r = await api("/api/changes/verify");
      el.textContent = r.message;
      el.className = `alert ${r.ok ? "alert--ok" : "alert--error"}`;
    } catch (ex) {
      el.textContent = ex.message;
      el.className = "alert alert--error";
    }
  });

  // --------------------------------------------------------- khởi động
  (async () => {
    // 1) Kết quả trả về từ Entra ID (OIDC callback chuyển hướng về /#sso=...)
    const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
    if (hash.has("sso") || hash.has("sso_error")) {
      history.replaceState(null, "", location.pathname + location.search);
    }
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
    if (modes?.header) await tryHeaderSso();
  })();
})();
