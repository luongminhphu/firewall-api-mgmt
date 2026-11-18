/* Trang VPN — tài khoản (B1, chỉ đọc): lọc theo firewall / phạm vi / trạng thái, thống kê, đồng bộ (operator). */
import { api, errorBox, runJob } from "../api.js";
import { progressBox, setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { on, state } from "../store.js";
import { $, esc, fmtTime } from "../util.js";

let searchTimer;

on("firewalls", () => {
  const sel = $("#v-fw");
  const keep = sel.value;
  sel.innerHTML = `<option value="">Tất cả</option>` +
    state.firewalls.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
  sel.value = keep;
});

["#v-fw", "#v-scope", "#v-state"].forEach((id) => $(id).addEventListener("change", loadVpn));
$("#v-q").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadVpn, 300);
});

const vpnChips = (a) =>
  [a.has_sslvpn ? `<span class="chip chip--info">SSL VPN</span>` : "",
   a.has_ipsec ? `<span class="chip chip--info">IPsec</span>` : ""].join(" ") || `<span class="muted">—</span>`;

function statusCell(a) {
  if (a.removed_at) return `<span class="chip chip--err">Đã xóa khỏi firewall</span><div class="muted tiny">${esc(fmtTime(a.removed_at))}</div>`;
  if (!a.enabled) return `<span class="chip chip--warn">Đã khóa</span>`;
  return `<span class="chip chip--ok">Hoạt động</span>`;
}

function renderStats(rows) {
  const n = (f) => rows.filter(f).length;
  $("#v-stats").innerHTML = `
    <div class="stat"><b>${rows.length}</b><span>tài khoản</span></div>
    <div class="stat"><b>${n((a) => a.has_sslvpn)}</b><span>có SSL VPN</span></div>
    <div class="stat"><b>${n((a) => a.has_ipsec)}</b><span>có IPsec</span></div>
    <div class="stat stat--drift"><b>${n((a) => !a.removed_at && !a.enabled)}</b><span>đã khóa trên firewall</span></div>
    <div class="stat stat--add"><b>${n((a) => a.removed_at)}</b><span>đã xóa khỏi firewall</span></div>`;
}

function renderSync(syncs) {
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
      ? `${sum.total ?? 0} tài khoản${sum.removed ? ` · mất ${sum.removed}` : ""}${sum.new ? ` · mới ${sum.new}` : ""}`
      : esc(s.error);
    return `<span class="sync-item">${chip}<strong>${esc(s.firewall)}</strong>
      <span class="muted tiny">${esc(fmtTime(s.synced_at))} · ${detail}</span></span>`;
  }).join("");
}

function renderRows(rows) {
  const tb = $("#v-table tbody");
  if (!rows.length) {
    tableMessage(tb, 6, "empty", "Không có tài khoản nào khớp bộ lọc.");
    return;
  }
  tb.innerHTML = rows.map((a) => `<tr>
      <td><div class="mono">${esc(a.username)}</div><div class="muted tiny">${esc(a.display_name)}</div></td>
      <td>${a.groups.map((g) => `<span class="chip">${esc(g)}</span>`).join(" ") || `<span class="muted">—</span>`}</td>
      <td class="nowrap">${vpnChips(a)}</td>
      <td>${statusCell(a)}</td>
      <td class="nowrap">${esc(a.firewall)}</td>
      <td class="nowrap mono tiny">${esc(fmtTime(a.last_seen_at))}</td>
    </tr>`).join("");
}

export async function loadVpn() {
  const tb = $("#v-table tbody");
  tableMessage(tb, 6, "loading");
  const p = new URLSearchParams({ scope: $("#v-scope").value, state: $("#v-state").value });
  if ($("#v-fw").value) p.set("firewall_id", $("#v-fw").value);
  if ($("#v-q").value.trim()) p.set("q", $("#v-q").value.trim());
  try {
    const r = await api(`/api/vpn/accounts?${p}`);
    renderSync(r.syncs);
    renderStats(r.accounts);
    renderRows(r.accounts);
  } catch (ex) {
    tableMessage(tb, 6, "error", ex.message);
  }
}

$("#v-sync").addEventListener("click", async () => {
  const btn = $("#v-sync");
  const out = $("#v-result");
  const fwId = $("#v-fw").value;
  const fws = state.firewalls.filter((f) => f.enabled && (!fwId || String(f.id) === fwId));
  setBusy(btn, true, "Đang đọc firewall…");
  const title = "Đang đồng bộ tài khoản VPN";
  out.innerHTML = progressBox({ total: fws.length, firewalls: fws.map((f) => ({ id: f.id, name: f.name })), results: [] },
    false, title);
  try {
    const r = await runJob("/api/vpn/sync", fwId ? { firewall_ids: [Number(fwId)] } : {}, (job) => {
      if (job.status === "running")
        out.innerHTML = progressBox(job, false, title);
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
