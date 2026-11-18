/* Tab Cài đặt › Tự động chặn từ Teams (quản trị viên): kết nối Microsoft Graph (secret không bao giờ hiển thị lại),
   tài khoản SOC được phép gửi lệnh (Object ID Entra), khung giờ, ngưỡng IP/giờ, chu kỳ đọc Teams, email nhóm Admin,
   firewall đích, nút Kiểm tra kết nối (liệt kê người gửi gần đây để chọn tài khoản SOC). */
import { api } from "../api.js";
import { setBusy } from "../components/progress.js";
import { toast } from "../components/toast.js";
import { state } from "../store.js";
import { $, esc, fmtTime } from "../util.js";

const cfg = { senders: [], tenants: [], groups: [], groupInfo: {}, own: "", seen: [], wl: [], hol: [] };
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const say = (text, kind) => {
  const el = $("#abs-msg");
  el.textContent = text;
  el.className = `alert alert--${kind}`;
};

export async function loadAutoblockSettings() {
  try {
    fill(await api("/api/autoblock/settings"));
  } catch (ex) {
    toast(ex.message, "err");
  }
}

function fill(s) {
  $("#abs-enabled").checked = s.enabled;
  $("#abs-tenant").value = s.tenant_id;
  $("#abs-client").value = s.client_id;
  $("#abs-chat").value = s.chat_id;
  $("#abs-secret").value = "";
  $("#abs-secret").placeholder = s.has_secret ? "Đã lưu — để trống = giữ nguyên" : "Chưa có";
  $("#abs-window").checked = s.window_enabled;
  $("#abs-wstart").value = s.window_start;
  $("#abs-wend").value = s.window_end;
  $("#abs-weekend").checked = s.weekend_full;
  cfg.hol = (s.holidays || []).map((h) => ({ ...h }));
  renderHolidays();
  $("#abs-limit").value = s.hourly_limit;
  $("#abs-poll").value = Math.round(s.poll_seconds / 60);
  $("#abs-stale").value = s.stale_minutes;
  $("#abs-admins").value = (s.admin_emails || []).join("\n");
  $("#abs-reply").checked = s.reply_enabled;
  $("#abs-reply-url").value = "";
  $("#abs-reply-url").placeholder = s.has_reply_url ? `Đã lưu (${s.reply_url_host}) — để trống = giữ nguyên` : "https://…logic.azure.com/…";
  const st = $("#ab-cfg-state");
  st.textContent = s.enabled ? "Đang bật" : s.configured ? "Đang tắt" : "Chưa cấu hình";
  st.className = `chip ${s.enabled ? "chip--ok" : "chip--warn"}`;
  $("#abs-fws").innerHTML = (state.firewalls || []).map((f) => `<label class="check">
      <input type="checkbox" value="${f.id}" ${s.firewall_ids.includes(f.id) ? "checked" : ""} />
      <span>${esc(f.name)}${f.enabled ? "" : " (đang tắt)"}</span></label>`).join("")
    || `<p class="muted tiny">Chưa có firewall nào.</p>`;
  $("#abs-meta").textContent = s.updated_by ? `Sửa lần cuối bởi ${s.updated_by} lúc ${fmtTime(s.updated_at)}` : "";
  cfg.wl = (s.whitelists || []).map((w) => ({ name: w.name, text: w.entries.join("\n") }));
  renderWhitelists();
  cfg.senders = s.soc_senders.map((x) => ({ ...x }));
  cfg.tenants = (s.soc_tenants || []).map((x) => ({ ...x }));
  cfg.groups = (s.soc_groups || []).map((x) => ({ ...x }));
  cfg.groupInfo = Object.fromEntries((s.groups_info || []).map((g) => [g.id, g]));
  cfg.own = (s.tenant_id || "").toLowerCase();
  cfg.seen = s.seen_senders || [];
  renderSenders();
}

const delBtn = (kind, i, label) =>
  `<button class="btn btn--ghost btn--sm" type="button" data-del-${kind}="${i}" aria-label="Xóa ${esc(label)}">✕</button>`;

function renderSenders() {
  $("#abs-tenants tbody").innerHTML = cfg.tenants.length
    ? cfg.tenants.map((x, i) => `<tr><td>${esc(x.name || "—")}</td><td class="mono tiny">${esc(x.id)}</td>
        <td>${delBtn("tenant", i, x.name || x.id)}</td></tr>`).join("")
    : `<tr><td colspan="3"><p class="empty">Chưa khai báo tenant của đơn vị SOC.</p></td></tr>`;
  $("#abs-groups tbody").innerHTML = cfg.groups.length
    ? cfg.groups.map((x, i) => {
      const info = cfg.groupInfo[x.id];
      return `<tr><td>${esc(info?.name || x.name || "—")}</td><td class="mono tiny">${esc(x.id)}</td>
        <td class="num" title="${esc(info?.fetched_at ? "Đọc lúc " + fmtTime(info.fetched_at) : "Chưa đọc")}">${info ? info.members : "—"}</td>
        <td>${delBtn("group", i, x.name || x.id)}</td></tr>`;
    }).join("")
    : `<tr><td colspan="4"><p class="empty">Chưa khai báo nhóm Entra.</p></td></tr>`;
  $("#abs-senders tbody").innerHTML = cfg.senders.length
    ? cfg.senders.map((x, i) => `<tr><td>${esc(x.name || "—")}</td><td class="mono tiny">${esc(x.id)}</td>
        <td>${delBtn("sender", i, x.name || x.id)}</td></tr>`).join("")
    : `<tr><td colspan="3"><p class="empty">Chưa khai báo tài khoản riêng lẻ.</p></td></tr>`;
  // người gửi gần đây: thêm nhanh theo tài khoản hoặc theo tenant (chỉ tenant external, không phải tenant HSC)
  const ids = new Set(cfg.senders.map((x) => x.id));
  const tids = new Set(cfg.tenants.map((x) => x.id));
  const seen = cfg.seen.filter((x) => !x.is_soc);
  $("#abs-seen").innerHTML = seen.length ? `<p class="muted tiny">Người gửi gần đây trong group chat (chưa được tin cậy):</p>` + seen.map((x) => {
    const ext = x.tenant && x.tenant !== cfg.own;
    return `<div class="ab-seen__row"><span><strong>${esc(x.name || x.id)}</strong>
        <span class="chip ${ext ? "chip--info" : ""}">${ext ? "External" : "HSC"}</span>
        <span class="muted tiny mono">${esc(x.tenant || "")}</span>${x.commands ? ` <span class="muted tiny">· ${x.commands} lệnh</span>` : ""}</span>
      <span class="ab-seen__acts">
        ${ext && !tids.has(x.tenant) ? `<button class="btn btn--ghost btn--sm" type="button" data-add-tenant="${esc(x.tenant)}">+ Tin cậy tenant này</button>` : ""}
        ${ids.has(x.id) ? "" : `<button class="btn btn--ghost btn--sm" type="button" data-add="${esc(x.id)}" data-name="${esc(x.name || "")}">${ext ? "+ Chỉ tài khoản này" : "+ Cho phép tài khoản HSC này"}</button>`}
      </span></div>`;
  }).join("") : "";
}

function addTo(list, id, name, msg) {
  id = id.trim().toLowerCase();
  if (!GUID.test(id)) {
    toast(`${msg} phải có dạng GUID`, "err");
    return false;
  }
  if (!list.some((x) => x.id === id)) list.push({ id, name: name.trim() });
  renderSenders();
  return true;
}

// ------------------------------------------------------------------ ngày lễ
function renderHolidays() {
  $("#abs-hol tbody").innerHTML = cfg.hol.length
    ? cfg.hol.map((h, i) => `<tr>
        <td><input type="date" data-hol="${i}" data-k="from" value="${esc(h.from)}" aria-label="Từ ngày" /></td>
        <td><input type="date" data-hol="${i}" data-k="to" value="${esc(h.to || h.from)}" aria-label="Đến ngày" /></td>
        <td><input data-hol="${i}" data-k="name" value="${esc(h.name || "")}" maxlength="80" placeholder="Tết Nguyên đán" aria-label="Tên ngày lễ" /></td>
        <td><button class="btn btn--ghost btn--sm" type="button" data-hol-del="${i}" aria-label="Xóa ngày lễ">✕</button></td></tr>`).join("")
    : `<tr><td colspan="4"><p class="empty">Chưa có ngày lễ nào.</p></td></tr>`;
}
$("#abs-hol").addEventListener("input", (e) => {
  const t = e.target;
  if (t.dataset.hol === undefined) return;
  cfg.hol[Number(t.dataset.hol)][t.dataset.k] = t.value;
});
$("#abs-hol").addEventListener("click", (e) => {
  const d = e.target.closest("[data-hol-del]");
  if (!d) return;
  cfg.hol.splice(Number(d.dataset.holDel), 1);
  renderHolidays();
});
$("#abs-hol-add").addEventListener("click", () => {
  const today = new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
  cfg.hol.push({ from: today, to: today, name: "" });
  renderHolidays();
});

// ------------------------------------------------------------------ whitelist
const lineCount = (text) => text.split(/\n/).map((x) => x.split("#")[0].trim()).filter(Boolean).length;

function renderWhitelists() {
  $("#abs-wl").innerHTML = cfg.wl.map((w, i) => `<div class="ab-wl__item">
      <div class="ab-wl__head">
        <input data-wl-name="${i}" value="${esc(w.name)}" maxlength="60" placeholder="Tên danh sách" aria-label="Tên danh sách whitelist" />
        <span class="chip" data-wl-count="${i}">${lineCount(w.text)} dòng</span>
        <button class="btn btn--ghost btn--sm" type="button" data-wl-del="${i}" aria-label="Xóa danh sách ${esc(w.name)}">✕</button>
      </div>
      <textarea data-wl-text="${i}" rows="4" spellcheck="false" placeholder="203.113.88.9&#10;23.32.0.0/11   # ghi chú"
        aria-label="IP / CIDR của danh sách ${esc(w.name)}">${esc(w.text)}</textarea></div>`).join("")
    || `<p class="muted tiny">Chưa có danh sách nào — mọi IP hợp lệ đều có thể bị tự chặn.</p>`;
}

$("#abs-wl").addEventListener("input", (e) => {
  const t = e.target;
  if (t.dataset.wlName !== undefined) cfg.wl[Number(t.dataset.wlName)].name = t.value;
  if (t.dataset.wlText !== undefined) {
    const i = Number(t.dataset.wlText);
    cfg.wl[i].text = t.value;
    $(`[data-wl-count="${i}"]`).textContent = `${lineCount(t.value)} dòng`;
  }
});
$("#abs-wl").addEventListener("click", (e) => {
  const d = e.target.closest("[data-wl-del]");
  if (!d) return;
  const w = cfg.wl[Number(d.dataset.wlDel)];
  if (w.text.trim() && !confirm(`Xóa danh sách whitelist "${w.name}"?`)) return;
  cfg.wl.splice(Number(d.dataset.wlDel), 1);
  renderWhitelists();
});
$("#abs-wl-add").addEventListener("click", () => {
  cfg.wl.push({ name: "", text: "" });
  renderWhitelists();
  $(`[data-wl-name="${cfg.wl.length - 1}"]`).focus();
});

function addSender(id, name) {
  id = id.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
    toast("Object ID phải có dạng GUID", "err");
    return;
  }
  if (!cfg.senders.some((x) => x.id === id)) cfg.senders.push({ id, name: name.trim() });
  renderSenders();
}

$("#abs-add-tenant").addEventListener("click", () => {
  const id = $("#abs-new-tenant").value.trim().toLowerCase();
  if (id && id === cfg.own) return toast("Không khai báo tenant của chính HSC — chỉ tenant của đơn vị SOC (external)", "err");
  if (addTo(cfg.tenants, id, $("#abs-new-tenant-name").value, "Tenant ID")) $("#abs-new-tenant").value = $("#abs-new-tenant-name").value = "";
});
$("#abs-add-group").addEventListener("click", () => {
  if (addTo(cfg.groups, $("#abs-new-group").value, $("#abs-new-group-name").value, "Object ID nhóm")) {
    $("#abs-new-group").value = $("#abs-new-group-name").value = "";
  }
});
$("#abs-add").addEventListener("click", () => {
  addSender($("#abs-new-id").value, $("#abs-new-name").value);
  $("#abs-new-id").value = $("#abs-new-name").value = "";
});
$("#ab-form").addEventListener("click", (e) => {
  for (const [kind, list] of [["sender", cfg.senders], ["tenant", cfg.tenants], ["group", cfg.groups]]) {
    const d = e.target.closest(`[data-del-${kind}]`);
    if (d) {
      list.splice(Number(d.getAttribute(`data-del-${kind}`)), 1);
      renderSenders();
    }
  }
  const t = e.target.closest("[data-add-tenant]");
  if (t) addTo(cfg.tenants, t.dataset.addTenant, "", "Tenant ID");
  const a = e.target.closest("[data-add]");
  if (a) addSender(a.dataset.add, a.dataset.name);
});

$("#abs-test").addEventListener("click", async () => {
  const b = $("#abs-test");
  const out = $("#abs-test-out");
  setBusy(b, true, "Đang kiểm tra…");
  try {
    await save(false); // lưu kết nối trước (không đổi trạng thái bật/tắt)
    const r = await api("/api/autoblock/test", { method: "POST" });
    cfg.seen = r.senders;
    cfg.groupInfo = Object.fromEntries((r.groups || []).map((g) => [g.id, { ...cfg.groupInfo[g.id], ...g }]));
    out.innerHTML = `<p class="alert alert--ok">Kết nối OK — đọc được ${r.messages} tin gần nhất của group chat.</p>`
      + (r.group_error ? `<p class="alert alert--warn">Đọc nhóm Entra: ${esc(r.group_error)}</p>` : "");
    renderSenders();
  } catch (ex) {
    out.innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
  } finally {
    setBusy(b, false);
  }
});

async function save(withEnabled = true) {
  const body = {
    tenant_id: $("#abs-tenant").value.trim(), client_id: $("#abs-client").value.trim(),
    chat_id: $("#abs-chat").value.trim(), soc_senders: cfg.senders, soc_tenants: cfg.tenants, soc_groups: cfg.groups,
    window_enabled: $("#abs-window").checked, window_start: $("#abs-wstart").value, window_end: $("#abs-wend").value,
    weekend_full: $("#abs-weekend").checked,
    holidays: cfg.hol.filter((h) => h.from).map((h) => ({ from: h.from, to: h.to || h.from, name: h.name || "" })),
    hourly_limit: Number($("#abs-limit").value), poll_seconds: Number($("#abs-poll").value) * 60,
    stale_minutes: Number($("#abs-stale").value),
    admin_emails: $("#abs-admins").value,
    firewall_ids: [...$("#abs-fws").querySelectorAll("input:checked")].map((x) => Number(x.value)),
    whitelists: cfg.wl.map((w) => ({ name: w.name.trim(), entries: w.text })),
  };
  if ($("#abs-secret").value) body.client_secret = $("#abs-secret").value;
  if ($("#abs-reply-url").value.trim()) body.reply_webhook_url = $("#abs-reply-url").value.trim();
  body.reply_enabled = $("#abs-reply").checked;
  if (withEnabled) body.enabled = $("#abs-enabled").checked;
  const s = await api("/api/autoblock/settings", { method: "PUT", body });
  fill(s);
  return s;
}

$("#abs-reply-test").addEventListener("click", async () => {
  const b = $("#abs-reply-test");
  setBusy(b, true, "Đang gửi…");
  try {
    await save(false);
    const r = await api("/api/autoblock/reply-test", { method: "POST" });
    say(`Đã gửi thử vào group chat: “${r.text}”. Mở Teams để kiểm tra.`, "ok");
  } catch (ex) {
    say(ex.message, "error");
  } finally {
    setBusy(b, false);
  }
});

$("#ab-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const s = await save();
    say(s.enabled ? `Đã lưu. App đọc Teams mỗi ${Math.round(s.poll_seconds / 60)} phút, chỉ xử lý tin gửi từ bây giờ.`
      : "Đã lưu. Tự động chặn đang tắt.", "ok");
  } catch (ex) {
    say(ex.message, "error");
  }
});
