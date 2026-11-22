/* Trang VPN (chỉ đọc trên firewall) — 3 view:
   - Thời hạn truy cập (B2): thẻ đếm theo trạng thái (bấm để lọc), lọc firewall/team/khoảng ngày/từ khóa/xem tại ngày,
     bảng phân trang, chi tiết rule + lịch sử, xuất CSV danh sách cần xử lý.
   - Tài khoản (B1): lọc firewall / phạm vi / trạng thái, thống kê.
   - Lịch sử thay đổi: rule mới / bị xóa / đổi hạn / đổi đích… giữa các lần đồng bộ, kiểm tra chuỗi băm.
   Đồng bộ (operator) đọc lại cả tài khoản lẫn rule. */
import { API, api, errorBox, runJob } from "../api.js";
import { openModal } from "../components/modal.js";
import { pageSlice, renderPager } from "../components/pagination.js";
import { progressBox, setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { on, state } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

const vs = { view: "rules", status: "", page: 1, rules: [], loaded: false };
let searchTimer;
const debounce = (fn) => () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(fn, 300);
};

// Thứ tự + màu thẻ trạng thái: việc cần xử lý trước, màu luôn đi kèm chữ (không chỉ dựa vào màu)
// Việc cần xử lý (theo mức nghiêm trọng) hiện dạng thẻ; trạng thái chỉ để tham khảo gom thành hàng chip.
const TODO = [
  ["expired_enabled", "Hết hạn nhưng vẫn bật", "err"],
  ["user_gone", "User không còn / bị khóa", "err"],
  ["expiring", "Sắp hết hạn", "warn"],
  ["mismatch", "Lệch thời hạn", "warn"],
  ["unreadable", "Không đọc được tên", "warn"],
];
const INFO = [
  ["active", "Còn hạn"],
  ["no_expiry", "Không có hạn"],
  ["expired_disabled", "Hết hạn (đã tắt)"],
];
const STATUS_CHIP = {
  active: "chip--ok", expiring: "chip--warn", expired_enabled: "chip--err", user_gone: "chip--err",
  unreadable: "chip--warn", expired_disabled: "", no_expiry: "",
};
const SOURCE = { schedule: "Schedule", name: "tên rule", none: "—" };
const CHANGE = {
  baseline: "Bắt đầu theo dõi", rule_added: "Rule mới", rule_removed: "Rule bị xóa", expiry_changed: "Đổi hạn",
  destination_changed: "Đổi đích", identity_changed: "Đổi người dùng", service_changed: "Đổi dịch vụ",
  status_changed: "Bật/tắt rule", rule_changed: "Thay đổi khác",
};

const fmtDate = (iso) => (iso ? iso.split("-").reverse().join("/") : "—");
const list = (xs, cls = "") => (xs || []).map((x) => `<span class="chip ${cls}">${esc(x)}</span>`).join(" ");

// ------------------------------------------------------------------ chung
on("firewalls", () => {
  for (const id of ["#v-fw", "#vr-fw"]) {
    const sel = $(id);
    const keep = sel.value;
    sel.innerHTML = `<option value="">Tất cả</option>` +
      state.firewalls.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
    sel.value = keep;
  }
});

$("#v-view").addEventListener("click", (e) => {
  const b = e.target.closest("[data-view]");
  if (b) showView(b.dataset.view);
});

function showView(view) {
  vs.view = view;
  $$("#v-view [data-view]").forEach((b) => {
    b.classList.toggle("is-active", b.dataset.view === view);
    b.setAttribute("aria-selected", String(b.dataset.view === view));
  });
  $$("[data-vview]").forEach((el) => el.classList.toggle("hidden", el.dataset.vview !== view));
  $("#vr-export").classList.toggle("hidden", view !== "rules");
  loadVpn();
}

export function loadVpn() {
  if (vs.view === "accounts") return loadAccounts();
  if (vs.view === "history") return loadHistory();
  return loadRules();
}

function renderSync(syncs, what) {
  const box = $("#v-sync-status");
  if (!syncs.length) {
    box.innerHTML = `<p class="muted tiny">Chưa đồng bộ lần nào — bấm <strong>Đồng bộ ngay</strong> (cần quyền Write).</p>`;
    return;
  }
  box.innerHTML = syncs.map((s) => {
    const sum = s.summary || {};
    const chip = s.status === "ok"
      ? `<span class="chip chip--ok">OK</span>`
      : `<span class="chip chip--err" title="${esc(s.error)}">Lỗi</span>`;
    const detail = s.status === "ok"
      ? `${sum.total ?? 0} ${what}${sum.removed ? ` · mất ${sum.removed}` : ""}${sum.new ? ` · mới ${sum.new}` : ""}`
      : esc(s.error);
    return `<span class="sync-item">${chip}<strong>${esc(s.firewall)}</strong>
      <span class="muted tiny">${esc(fmtTime(s.synced_at))} · ${detail}</span></span>`;
  }).join("");
}

// ------------------------------------------------------- thời hạn truy cập
["#vr-fw", "#vr-team", "#vr-from", "#vr-to", "#vr-asof"].forEach((id) =>
  $(id).addEventListener("change", () => { vs.page = 1; loadRules(); }));
$("#vr-q").addEventListener("input", debounce(() => { vs.page = 1; loadRules(); }));
$("#vr-cards").addEventListener("click", (e) => {
  const b = e.target.closest("[data-status]");
  if (!b) return;
  vs.status = vs.status === b.dataset.status ? "" : b.dataset.status; // bấm lại → bỏ lọc
  vs.page = 1;
  loadRules();
});

function ruleParams() {
  const p = new URLSearchParams();
  const add = (k, v) => v && p.set(k, v);
  add("firewall_id", $("#vr-fw").value);
  add("team", $("#vr-team").value);
  add("date_from", $("#vr-from").value);
  add("date_to", $("#vr-to").value);
  add("q", $("#vr-q").value.trim());
  add("as_of", $("#vr-asof").value);
  return p;
}

function renderCards(summary) {
  const n = (k) => summary[k] ?? 0;
  const todo = summary.todo ?? TODO.reduce((t, [k]) => t + n(k), 0); // số rule cần xử lý (không đếm trùng)
  const pressed = (k) => `data-status="${k}" aria-pressed="${vs.status === k}"`;
  // Một dải lọc duy nhất: việc cần làm (màu theo mức) rồi trạng thái tham khảo; bấm lại để bỏ lọc
  $("#vr-cards").innerHTML = `
    <p class="vr-todo"><strong>${todo ? `Cần xử lý: ${todo} rule` : "Không có rule nào cần xử lý"}</strong>
      <span class="muted tiny">Bấm một mục để lọc bảng; bấm lại để bỏ lọc.</span></p>
    <div class="vr-strip" role="group" aria-label="Lọc theo trạng thái">${TODO.map(([k, label, tone]) => `
      <button type="button" class="chip-btn${n(k) ? ` chip-btn--${tone}` : " is-zero"}${vs.status === k ? " is-active" : ""}" ${pressed(k)}>${label} <b>${n(k)}</b></button>`).join("")}
      <span class="vr-strip__sep" aria-hidden="true"></span>${INFO.map(([k, label]) => `
      <button type="button" class="chip-btn${vs.status === k ? " is-active" : ""}" ${pressed(k)}>${label} <b>${n(k)}</b></button>`).join("")}</div>`;
}

function statusCell(x) {
  const days = x.days_left;
  const when = days == null ? "" : days < 0 ? `quá hạn ${-days} ngày` : days === 0 ? "hết hạn hôm nay" : `còn ${days} ngày`;
  const extra = x.flags.filter((f) => f !== x.status && ["expired_enabled", "user_gone"].includes(f))
    .map((f) => `<span class="chip chip--err">${f === "user_gone" ? "User không còn" : "Hết hạn, vẫn bật"}</span>`).join(" ");
  return `<span class="chip ${STATUS_CHIP[x.status] || ""}">${esc(x.status_label)}</span>
    ${when ? `<div class="muted tiny">${when}</div>` : ""}${extra ? `<div>${extra}</div>` : ""}`;
}

function expiryCell(x) {
  return `<div class="mono">${fmtDate(x.expiry_date)}</div>
    ${x.expiry_source === "none" ? "" : `<div class="muted tiny">theo ${SOURCE[x.expiry_source]}</div>`}
    ${x.expiry_mismatch ? `<span class="chip chip--warn" title="Schedule ${fmtDate(x.schedule_end)} ≠ tên rule ${fmtDate(x.name_date)}">Lệch thời hạn</span>` : ""}`;
}

function usersCell(x) {
  if (x.accounts.length)
    return x.accounts.map((a) => `<div class="mono tiny${a.removed_at || a.status.toLowerCase() !== "active" ? " is-gone" : ""}">${esc(a.username)}</div>`).join("");
  return x.identities.length ? `<div class="muted tiny">${x.identities.map(esc).join("<br>")}</div>` : `<span class="muted">—</span>`;
}

function renderRules() {
  const tb = $("#vr-table tbody");
  const rows = vs.status ? vs.rules.filter((x) => (vs.status === "mismatch" ? x.expiry_mismatch : x.status === vs.status)) : vs.rules;
  const pg = pageSlice(rows, vs.page);
  vs.page = pg.page;
  if (!rows.length) tableMessage(tb, 6, "empty", "Không có rule nào khớp bộ lọc.");
  else
    tb.innerHTML = pg.rows.map((x) => `<tr class="row-link" tabindex="0" data-rule="${x.id}">
        <td><div class="rule-name">${esc(x.rule_name)}${x.enabled ? "" : ' <span class="chip">Rule tắt</span>'}</div>
          <div>${x.team ? `<span class="chip">${esc(x.team)}</span>` : ""}${x.user_code ? ` <span class="chip chip--info mono">${esc(x.user_code)}</span>` : ""}</div></td>
        <td>${statusCell(x)}</td>
        <td class="nowrap">${expiryCell(x)}</td>
        <td>${usersCell(x)}</td>
        <td><div class="tiny">${esc([...x.dst_zones, ...x.dst_networks].join(", ") || "—")}</div>
          <div class="muted tiny">${esc(x.services.join(", "))}</div></td>
        <td class="nowrap tiny">${esc(x.firewall)}</td>
      </tr>`).join("");
  renderPager($("#vr-pager"), { page: pg.page, pages: pg.pages, total: rows.length }, (p) => { vs.page = p; renderRules(); });
  // CSV: thẻ đang chọn, hoặc mặc định mọi trạng thái cần xử lý
  const exp = ruleParams();
  exp.set("status", vs.status || "expiring,expired_enabled,user_gone,unreadable,mismatch");
  exp.set("token", state.token);
  $("#vr-export").href = `${API}/api/vpn/rules.csv?${exp}`;
}

async function loadRules() {
  const tb = $("#vr-table tbody");
  if (!vs.loaded) tableMessage(tb, 6, "loading");
  try {
    const r = await api(`/api/vpn/rules?${ruleParams()}`);
    vs.rules = r.rules;
    vs.loaded = true;
    renderSync(r.syncs, "rule");
    renderCards(r.summary);
    const team = $("#vr-team");
    const keep = team.value;
    team.innerHTML = `<option value="">Tất cả</option>` + r.teams.map((t) => `<option>${esc(t)}</option>`).join("");
    team.value = keep;
    $("#vr-note").textContent =
      `Trạng thái tính tại ngày ${fmtDate(r.today)} (giờ Việt Nam) · "Sắp hết hạn" khi còn ≤ ${r.expiring_days} ngày · ` +
      `hạn lấy từ Schedule nếu có, nếu không thì từ tên rule.`;
    renderRules();
  } catch (ex) {
    tableMessage(tb, 6, "error", ex.message);
  }
}

$("#vr-table").addEventListener("click", (e) => {
  const tr = e.target.closest("[data-rule]");
  if (tr) showRule(Number(tr.dataset.rule));
});
$("#vr-table").addEventListener("keydown", (e) => {
  const tr = e.target.closest("[data-rule]");
  if (tr && (e.key === "Enter" || e.key === " ")) {
    e.preventDefault();
    showRule(Number(tr.dataset.rule));
  }
});

const dl = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;

async function showRule(id) {
  openModal("Chi tiết rule", `<div class="skeleton"></div>`);
  try {
    const { rule: x, history } = await api(`/api/vpn/rules/${id}`);
    openModal(x.rule_name, `
      <p>${statusCell(x)}</p>
      ${dl([
        ["Firewall · Rule Group", `${esc(x.firewall)} · ${esc(x.group_name)} (vị trí ${x.position})`],
        ["Hạn truy cập", `${fmtDate(x.expiry_date)} <span class="muted">theo ${SOURCE[x.expiry_source]}</span>`],
        ["Schedule", `${esc(x.schedule_name || "—")}${x.schedule_end ? ` · kết thúc ${fmtDate(x.schedule_end)}` : ""}`],
        ["Ngày trong tên", x.name_status === "invalid" ? `<span class="chip chip--warn">Không đọc được</span>` : fmtDate(x.name_date)],
        ["Team · mã user", `${esc(x.team || "—")} · <span class="mono">${esc(x.user_code || "—")}</span>`],
        ["Trạng thái rule", `${x.enabled ? "Bật" : "Tắt"} · ${esc(x.action)} · log ${x.log_traffic ? "bật" : "tắt"}`],
        ["Nguồn", `${list(x.src_zones)} ${list(x.src_networks)}`],
        ["Người dùng (identity)", list(x.identities, "mono") || "—"],
        ["Tài khoản liên kết", x.accounts.map((a) => `<span class="mono">${esc(a.username)}</span> <span class="muted">${esc(a.display_name)}${a.removed_at ? " · đã xóa khỏi firewall" : a.status.toLowerCase() !== "active" ? " · đã khóa" : ""}</span>`).join("<br>") || "—"],
        ["Đích", `${list(x.dst_zones)} ${list(x.dst_networks)}`],
        ["Dịch vụ", list(x.services) || "—"],
        ["Mô tả", esc(x.description || "—")],
        ["Theo dõi từ", esc(fmtTime(x.first_seen_at))],
      ])}
      <h3 class="dialog__sub">Lịch sử</h3>
      ${history.length ? `<ul class="hist">${history.map(histItem).join("")}</ul>` : `<p class="muted tiny">Chưa có thay đổi nào từ khi theo dõi.</p>`}
      <p class="muted tiny">App không sửa rule trên firewall — gia hạn / tắt rule thực hiện trên Sophos rồi bấm Đồng bộ.</p>`);
  } catch (ex) {
    openModal("Chi tiết rule", errorBox(ex));
  }
}

function changeText(c) {
  const b = c.before || {};
  const a = c.after || {};
  if (c.change_type === "expiry_changed") return `${fmtDate(b.expiry_date)} → ${fmtDate(a.expiry_date)}`;
  if (c.change_type === "status_changed") return a.enabled ? "Tắt → Bật" : "Bật → Tắt";
  if (c.change_type === "baseline") return `${a.rules} rule (${(a.groups || []).join(", ")})`;
  const keys = Object.keys({ ...b, ...a }).filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k]));
  return keys.map((k) => `${k}: ${esc(JSON.stringify(b[k] ?? "—"))} → ${esc(JSON.stringify(a[k] ?? "—"))}`).join("; ");
}

const histItem = (c) => `<li><span class="mono tiny">${esc(fmtTime(c.ts))}</span>
  <span class="chip">${CHANGE[c.change_type] || esc(c.change_type)}</span> <span class="tiny">${changeText(c)}</span></li>`;

// ------------------------------------------------------------------ tài khoản
["#v-fw", "#v-scope", "#v-state"].forEach((id) => $(id).addEventListener("change", loadAccounts));
$("#v-q").addEventListener("input", debounce(loadAccounts));

const vpnChips = (a) =>
  [a.has_sslvpn ? `<span class="chip chip--info">SSL VPN</span>` : "",
   a.has_ipsec ? `<span class="chip chip--info">IPsec</span>` : ""].join(" ") || `<span class="muted">—</span>`;

function accStatus(a) {
  if (a.removed_at) return `<span class="chip chip--err">Đã xóa khỏi firewall</span><div class="muted tiny">${esc(fmtTime(a.removed_at))}</div>`;
  if (!a.enabled) return `<span class="chip chip--warn">Đã khóa</span>`;
  return `<span class="chip chip--ok">Hoạt động</span>`;
}

async function loadAccounts() {
  const tb = $("#v-table tbody");
  tableMessage(tb, 6, "loading");
  const p = new URLSearchParams({ scope: $("#v-scope").value, state: $("#v-state").value });
  if ($("#v-fw").value) p.set("firewall_id", $("#v-fw").value);
  if ($("#v-q").value.trim()) p.set("q", $("#v-q").value.trim());
  try {
    const r = await api(`/api/vpn/accounts?${p}`);
    renderSync(r.syncs, "tài khoản");
    const rows = r.accounts;
    const n = (f) => rows.filter(f).length;
    $("#v-stats").innerHTML = `
      <div class="stat"><b>${rows.length}</b><span>tài khoản</span></div>
      <div class="stat"><b>${n((a) => a.has_sslvpn)}</b><span>có SSL VPN</span></div>
      <div class="stat"><b>${n((a) => a.has_ipsec)}</b><span>có IPsec</span></div>
      <div class="stat stat--drift"><b>${n((a) => !a.removed_at && !a.enabled)}</b><span>đã khóa trên firewall</span></div>
      <div class="stat stat--add"><b>${n((a) => a.removed_at)}</b><span>đã xóa khỏi firewall</span></div>`;
    if (!rows.length) return tableMessage(tb, 6, "empty", "Không có tài khoản nào khớp bộ lọc.");
    tb.innerHTML = rows.map((a) => `<tr>
        <td><div class="mono">${esc(a.username)}</div><div class="muted tiny">${esc(a.display_name)}</div></td>
        <td>${list(a.groups) || `<span class="muted">—</span>`}</td>
        <td class="nowrap">${vpnChips(a)}</td>
        <td>${accStatus(a)}</td>
        <td class="nowrap">${esc(a.firewall)}</td>
        <td class="nowrap mono tiny">${esc(fmtTime(a.last_seen_at))}</td>
      </tr>`).join("");
  } catch (ex) {
    tableMessage(tb, 6, "error", ex.message);
  }
}

// ------------------------------------------------------------------ lịch sử
async function loadHistory() {
  const box = $("#vh-list");
  box.innerHTML = `<div class="skeleton"></div>`;
  try {
    const r = await api("/api/vpn/changes?limit=500");
    box.innerHTML = r.changes.length
      ? `<ul class="hist hist--full">${r.changes.map((c) => `<li><span class="mono tiny">${esc(fmtTime(c.ts))}</span>
          <span class="chip">${CHANGE[c.change_type] || esc(c.change_type)}</span>
          <strong>${esc(c.rule_name || c.firewall)}</strong> <span class="muted tiny">${esc(c.firewall)}</span>
          <div class="tiny">${changeText(c)}</div></li>`).join("")}</ul>`
      : `<p class="empty">Chưa có lịch sử — đồng bộ lần đầu sẽ ghi mốc bắt đầu theo dõi.</p>`;
  } catch (ex) {
    box.innerHTML = errorBox(ex);
  }
}

$("#vh-verify").addEventListener("click", async () => {
  const el = $("#vh-verify-msg");
  try {
    const r = await api("/api/vpn/changes/verify");
    el.textContent = r.message;
    el.className = `tiny ${r.ok ? "text-ok" : "text-err"}`;
  } catch (ex) {
    el.textContent = ex.message;
    el.className = "tiny text-err";
  }
});

// ------------------------------------------------------------------ đồng bộ
$("#v-sync").addEventListener("click", async () => {
  const btn = $("#v-sync");
  const out = $("#v-result");
  setBusy(btn, true, "Đang đọc firewall…");
  // chỉ firewall có VPN (Cài đặt › VPN); chưa chọn = mọi firewall đang bật
  let scope = [];
  try {
    scope = (await api("/api/vpn/settings")).firewall_ids || [];
  } catch {
    /* không đọc được cấu hình → hiển thị theo mọi firewall đang bật, server vẫn lọc đúng */
  }
  const fws = state.firewalls.filter((f) => f.enabled && (!scope.length || scope.includes(f.id)));
  const title = "Đang đồng bộ VPN (tài khoản + rule)";
  out.innerHTML = progressBox({ total: fws.length, firewalls: fws.map((f) => ({ id: f.id, name: f.name })), results: [] },
    false, title);
  try {
    const r = await runJob("/api/vpn/sync", {}, (job) => {
      if (job.status === "running") out.innerHTML = progressBox(job, false, title);
    });
    const bad = r.results.filter((x) => !x.ok);
    out.innerHTML = bad.length
      ? `<p class="alert alert--warn">Không đọc được: ${bad.map((x) => `<strong>${esc(x.firewall)}</strong> (${esc(x.error)})`).join(", ")}</p>`
      : "";
    toast(bad.length ? `Đồng bộ xong, ${bad.length} firewall lỗi` : `Đã đồng bộ ${r.results.length} firewall`, bad.length ? "err" : "ok");
    await loadVpn();
  } catch (ex) {
    out.innerHTML = errorBox(ex, "Đồng bộ VPN không thành công");
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Đồng bộ ngay");
});
