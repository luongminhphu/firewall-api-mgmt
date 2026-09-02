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
  };

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
    return d.toLocaleString("vi-VN", { hour12: false });
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
    $("#login-screen").classList.add("hidden");
    $("#app").classList.remove("hidden");
    $("#who").textContent = `${state.config.user} · v${state.config.version}`;
    $("#a-export").href = `${API}/api/audit.csv?token=${encodeURIComponent(state.token)}`;
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
    if (btn.dataset.tab === "groups") loadGroupsForSelectedFw();
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
            <span class="fw-opt__meta">${esc(f.host)}:${f.port} → ${esc(f.default_group)}</span>
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
            <button class="btn btn--sm" data-act="test" data-id="${f.id}">Kiểm tra</button>
            <button class="btn btn--sm" data-act="edit" data-id="${f.id}">Sửa</button>
            <button class="btn btn--sm btn--ghost" data-act="del" data-id="${f.id}">Xóa</button>
          </span>
        </div>
        <dl class="fw-card__grid">
          <div><dt>Địa chỉ</dt><dd>${esc(f.host)}:${f.port}</dd></div>
          <div><dt>Tài khoản</dt><dd>${esc(f.username)}</dd></div>
          <div><dt>Group mặc định</dt><dd>${esc(f.default_group)}</dd></div>
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
    $("#fw-group").value = fw?.default_group || "SOC_BLOCKED_IPS";
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
      default_group: $("#fw-group").value,
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
    $("#do-block").disabled = !(state.candidates.length && selectedFwIds().length);
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
          `Group: ${$("#block-group").value.trim() || "mặc định của từng firewall"}`
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
          group: $("#block-group").value.trim(),
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
        return `<div class="result-fw">${head}${rows}</div>`;
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
  $("#g-group").addEventListener("change", loadMembers);
  $("#g-reload").addEventListener("click", loadMembers);
  $("#g-search").addEventListener("input", () => renderMembers(filterMembers()));

  async function loadGroupsForSelectedFw() {
    const id = $("#g-fw").value;
    if (!id) return;
    $("#g-meta").innerHTML = `<span class="skeleton" style="width:220px"></span>`;
    try {
      const r = await api(`/api/firewalls/${id}/groups`);
      $("#g-group").innerHTML = r.groups
        .map(
          (g) =>
            `<option value="${esc(g.name)}" ${g.name === r.default_group ? "selected" : ""}>${esc(g.name)} (${g.count})</option>`
        )
        .join("");
      if (!r.groups.length) {
        $("#g-group").innerHTML = `<option value="">— chưa có group —</option>`;
        $("#g-meta").innerHTML = `<span class="muted">Firewall này chưa có IP Host Group nào.</span>`;
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
    const group = $("#g-group").value;
    if (!id || !group) return;
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
    $("#do-unblock").disabled = selectedObjects().length === 0;
  }

  $("#do-unblock").addEventListener("click", async () => {
    const targets = selectedObjects();
    const fwId = Number($("#g-fw").value);
    const group = $("#g-group").value;
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
          group,
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

  // --------------------------------------------------------- auto-login lại
  (async () => {
    let saved = "";
    try {
      saved = store?.getItem("sb_token") || "";
    } catch {}
    if (!saved) return;
    state.token = saved;
    try {
      await boot();
    } catch {
      logout();
    }
  })();
})();
