/* Tab Cài đặt (quản trị viên) — 4 nhóm theo công việc vận hành (menu con trái, nhớ nhóm vừa xem):
   - Tự động chặn (Teams) · VPN & rà soát · Email & thông báo · Giao diện (logo).
   Chi tiết:
   - Tự động chặn từ Teams (autoblock-settings.js): Graph, tài khoản SOC, whitelist, khung giờ, ngưỡng, chu kỳ đọc.
   - VPN: ngưỡng "sắp hết hạn", Rule Group được đọc (trong whitelist), firewall có VPN cần đồng bộ.
   - SMTP: máy chủ / bảo mật / tài khoản (mật khẩu không bao giờ hiển thị lại), người gửi, gửi thử.
   - Thông báo: bật/tắt, email Infra, mốc nhắc, báo hằng tuần rule hết hạn còn bật.
   - Group VPN: đại diện + user VPN thuộc group (nhập tay), hàng đợi email + Chạy ngay. */
import { api, errorBox } from "../api.js";
import { loadAutoblockSettings } from "./autoblock-settings.js";
import { confirmAction } from "../components/modal.js";
import { setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { on, state } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

const say = (el, text, kind) => {
  el.textContent = text;
  el.className = `alert alert--${kind}`;
};

export async function loadSettings() {
  await Promise.all([loadAutoblockSettings(), loadVpnSettings(), loadReviewSettings(), loadNotify(), loadOutbox()]);
}

// ------------------------------------------------------------------ rà soát định kỳ
async function loadReviewSettings() {
  try {
    const s = await api("/api/review/settings");
    $("#rs-auto").checked = s.auto_quarterly;
    $("#rs-due").value = s.due_days;
    $("#rs-remind").value = s.remind_days;
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#rs-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/review/settings", {
      method: "PUT",
      body: { auto_quarterly: $("#rs-auto").checked, due_days: Number($("#rs-due").value),
              remind_days: Number($("#rs-remind").value) },
    });
    say($("#rs-msg"), "Đã lưu cấu hình rà soát.", "ok");
  } catch (ex) {
    say($("#rs-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ menu con: nhóm cài đặt
const ST_KEY = "sb_settings_group";
function showGroup(name) {
  const items = $$("#st-nav [data-st]");
  const valid = items.some((b) => b.dataset.st === name) ? name : items[0].dataset.st;
  items.forEach((b) => {
    const on = b.dataset.st === valid;
    b.classList.toggle("is-active", on);
    if (on) b.setAttribute("aria-current", "true");
    else b.removeAttribute("aria-current");
  });
  $$("[data-st-group]").forEach((g) => { g.hidden = g.dataset.stGroup !== valid; });
  try {
    localStorage.setItem(ST_KEY, valid);
  } catch {
    /* trình duyệt chặn lưu trữ — vẫn chuyển nhóm được, chỉ không nhớ */
  }
}
$("#st-nav").addEventListener("click", (e) => {
  const b = e.target.closest("[data-st]");
  if (b) showGroup(b.dataset.st);
});
let remembered = null;
try {
  remembered = localStorage.getItem(ST_KEY);
} catch {
  /* không đọc được lưu trữ → nhóm đầu tiên */
}
showGroup(remembered);
// mục lục các bước của form Tự động chặn: cuộn tới bước, không đổi địa chỉ trang
$("#ab-form").addEventListener("click", (e) => {
  const b = e.target.closest("[data-goto]");
  if (!b) return;
  showStep(b.dataset.goto);
  document.getElementById(b.dataset.goto).querySelector("input, select, textarea, button")?.focus({ preventScroll: true });
});
// Một bước một lúc; form vẫn gửi đủ mọi trường khi Lưu (trường ẩn vẫn thuộc form)
function showStep(id) {
  $$("#ab-form .st-sec").forEach((s) => { s.hidden = s.id !== id; });
  $$("#ab-form [data-goto]").forEach((b) => {
    if (b.dataset.goto === id) b.setAttribute("aria-current", "step");
    else b.removeAttribute("aria-current");
  });
}
showStep("abs-sec-1");

// ------------------------------------------------------------------ VPN
let vpnFwIds = [];
// Phạm vi tường minh: "Tất cả firewall đang bật" là một lựa chọn riêng (trước đây = không tick ô nào, dễ hiểu ngược)
function renderVpnFws() {
  const fws = state.firewalls || [];
  const all = !vpnFwIds.length;
  $("#vs-scope-all").checked = all;
  $("#vs-scope-pick").checked = !all;
  $("#vs-fws").innerHTML = fws.length
    ? fws.map((f) => `<label class="check">
        <input type="checkbox" value="${f.id}" ${vpnFwIds.includes(f.id) ? "checked" : ""} ${all ? "disabled" : ""} />
        <span>${esc(f.name)}${f.enabled ? "" : " (đang tắt)"}</span></label>`).join("")
    : `<p class="muted tiny">Chưa có firewall nào.</p>`;
  $("#vs-fws").classList.toggle("is-off", all);
}
$("#vs-form").addEventListener("change", (e) => {
  if (e.target.name !== "vs-scope") return;
  const all = e.target.value === "all";
  $$("#vs-fws input").forEach((x) => (x.disabled = all));
  $("#vs-fws").classList.toggle("is-off", all);
  if (!all) $("#vs-fws input")?.focus();
});
on("firewalls", renderVpnFws);

async function loadVpnSettings() {
  try {
    const s = await api("/api/vpn/settings");
    $("#vs-days").value = s.expiring_days;
    // Chỉ một group được phép (gắn cứng khi build) → hiện là giá trị cố định, không phải ô chọn giả
    $("#vs-groups").innerHTML = s.allowed_rule_groups.length === 1
      ? `<p class="vs-fixed"><span class="mono">${esc(s.allowed_rule_groups[0])}</span> <span class="muted tiny">· cố định khi build (hardening)</span>
          <input type="checkbox" value="${esc(s.allowed_rule_groups[0])}" checked hidden /></p>`
      : s.allowed_rule_groups.map((g) => `<label class="check">
        <input type="checkbox" value="${esc(g)}" ${s.rule_groups.includes(g) ? "checked" : ""} /> <span>${esc(g)}</span>
      </label>`).join("");
    vpnFwIds = s.firewall_ids || [];
    renderVpnFws();
    $("#vs-meta").textContent = s.updated_by
      ? `Sửa lần cuối bởi ${s.updated_by} lúc ${fmtTime(s.updated_at)}`
      : "Đang dùng giá trị mặc định.";
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#vs-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if ($("#vs-scope-pick").checked && !$$("#vs-fws input:checked").length) {
    say($("#vs-msg"), "Chọn ít nhất một firewall, hoặc chọn \"Tất cả firewall đang bật\".", "error");
    return;
  }
  try {
    await api("/api/vpn/settings", {
      method: "PUT",
      body: {
        expiring_days: Number($("#vs-days").value),
        rule_groups: $$("#vs-groups input:checked").map((c) => c.value),
        firewall_ids: $("#vs-scope-all").checked ? [] : $$("#vs-fws input:checked").map((c) => Number(c.value)),
      },
    });
    say($("#vs-msg"), "Đã lưu cấu hình VPN.", "ok");
    loadVpnSettings();
  } catch (ex) {
    say($("#vs-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ SMTP + thông báo + group VPN
function fillSmtp(s) {
  $("#smtp-enabled").checked = s.enabled;
  $("#smtp-host").value = s.host;
  $("#smtp-port").value = s.port;
  $("#smtp-security").value = s.security;
  $("#smtp-verify").checked = s.verify_tls;
  $("#smtp-user").value = s.username;
  $("#smtp-pass").value = "";
  $("#smtp-pass").placeholder = s.has_password ? "•••••• đã lưu — bỏ trống để giữ" : "";
  $("#smtp-clear").checked = false;
  $("#smtp-clear-row").classList.toggle("hidden", !s.has_password);
  $("#smtp-from").value = s.from_addr;
  $("#smtp-from-name").value = s.from_name;
  const st = $("#smtp-state");
  st.textContent = s.enabled && s.configured ? "Đang bật" : s.configured ? "Đang tắt" : "Chưa cấu hình";
  st.className = `chip ${s.enabled && s.configured ? "chip--ok" : "chip--warn"}`;
}

const memberChip = (u) => `<span class="chip tc-m" data-u="${esc(u)}">${esc(u)}<button type="button" class="tc-m__x" aria-label="Bỏ ${esc(u)} khỏi group">×</button></span>`;

function contactRow(c = { team: "", emails: [], note: "", members: [] }) {
  return `<tr>
    <td data-label="Group" class="tc-gcell"><input class="tc-team" list="tc-teams" value="${esc(c.team)}" aria-label="Tên group" placeholder="RMS RESEARCH" />
      <input class="tc-note" value="${esc(c.note || "")}" aria-label="Ghi chú cho group ${esc(c.team)}" placeholder="Ghi chú (tuỳ chọn)" /></td>
    <td data-label="Email đại diện"><input class="tc-emails" value="${esc(c.emails.join(", "))}" aria-label="Email đại diện (phân cách dấu phẩy)" placeholder="truong.nhom@hsc.com.vn" /></td>
    <td data-label="User VPN"><div class="tc-members">${(c.members || []).map(memberChip).join("")}
      <input class="tc-madd" list="tc-users" aria-label="Thêm user VPN vào group ${esc(c.team)}" placeholder="Thêm user VPN…" /></div></td>
    <td><button class="btn btn--ghost btn--sm tc-del" type="button" aria-label="Xóa group ${esc(c.team)}">Xóa</button></td>
  </tr>`;
}

// ---- Trạng thái chưa lưu: so bảng hiện tại với bản đã lưu; thanh Lưu / Hoàn tác bám đáy khi có thay đổi
let tcSaved = [];
function collectContacts() {
  return $$("#tc-table tbody tr")
    .map((tr) => ({
      team: $(".tc-team", tr).value.trim(),
      emails: $(".tc-emails", tr).value,
      note: $(".tc-note", tr).value.trim(),
      // user đang gõ dở trong ô thêm cũng được lưu
      members: [...$$(".tc-m", tr).map((x) => x.dataset.u), ...$(".tc-madd", tr).value.split(/[,;\s]+/).filter(Boolean)],
    }))
    .filter((c) => c.team || c.emails.trim() || c.members.length);
}
const tcKey = (list) => JSON.stringify(list.map((c) => [c.team, String(Array.isArray(c.emails) ? c.emails.join(",") : c.emails)
  .split(/[,;\s]+/).filter(Boolean).join(","), c.note || "", c.members || []]));
const tcDirty = () => tcKey(collectContacts()) !== tcKey(tcSaved);

function updateDirty() {
  const changed = tcDirty();
  $("#tc-bar").classList.toggle("is-dirty", changed);
  $("#tc-undo").hidden = !changed;
  $("#tc-dirty").textContent = changed ? "Có thay đổi chưa lưu" : "";
}

function renderContacts(list) {
  tcSaved = list;
  $("#tc-table tbody").innerHTML = list.length ? list.map(contactRow).join("") : contactRow();
  refreshUnassigned();
  applyTcFilter();
  updateDirty();
}

// User VPN có quyền nhưng chưa thuộc group nào → Infra biết còn ai chưa gán
let vpnUsers = [];
function refreshUnassigned() {
  const taken = new Set($$("#tc-table .tc-m").map((x) => x.dataset.u.toLowerCase()));
  const free = vpnUsers.filter((u) => !taken.has(u.toLowerCase()));
  $("#tc-users").innerHTML = free.map((u) => `<option value="${esc(u)}"></option>`).join("");
  $("#tc-unassigned").textContent = !vpnUsers.length ? ""
    : free.length ? `${free.length}/${vpnUsers.length} user VPN chưa thuộc group nào: ${free.slice(0, 8).join(", ")}${free.length > 8 ? ", …" : ""}`
      : `Mọi user VPN (${vpnUsers.length}) đã thuộc một group.`;
}

// ---- Lọc nhanh: theo tên group, user VPN, email đại diện, ghi chú (chỉ ẩn dòng — Lưu vẫn gửi mọi group)
function applyTcFilter() {
  const q = $("#tc-filter").value.trim().toLowerCase();
  const rows = $$("#tc-table tbody tr");
  let shown = 0;
  const hits = [];
  for (const tr of rows) {
    const team = $(".tc-team", tr).value;
    const chips = $$(".tc-m", tr);
    chips.forEach((ch) => ch.classList.toggle("is-hit", !!q && ch.dataset.u.toLowerCase().includes(q)));
    const hitUsers = chips.filter((ch) => ch.classList.contains("is-hit")).map((ch) => ch.dataset.u);
    const match = !q || [team, $(".tc-emails", tr).value, $(".tc-note", tr).value].some((v) => v.toLowerCase().includes(q))
      || hitUsers.length > 0;
    tr.hidden = !match;
    shown += match ? 1 : 0;
    if (q && hitUsers.length) hits.push(`${hitUsers.slice(0, 3).join(", ")}${hitUsers.length > 3 ? ", …" : ""} → ${team || "(chưa đặt tên)"}`);
  }
  const free = q ? vpnUsers.filter((u) => u.toLowerCase().includes(q) && !$$("#tc-table .tc-m").some((ch) => ch.dataset.u.toLowerCase() === u.toLowerCase())) : [];
  $("#tc-filter-msg").textContent = !q ? ""
    : `${shown}/${rows.length} group khớp "${q}"${hits.length ? ` · ${hits.join(" · ")}` : ""}${free.length ? ` · chưa thuộc group nào: ${free.slice(0, 5).join(", ")}${free.length > 5 ? ", …" : ""}` : ""}`;
}
$("#tc-filter").addEventListener("input", applyTcFilter);

// ---- Gợi ý group từ tên rule: tick group + từng user muốn lấy, bấm "Chọn" → thêm vào bảng để rà lại, nhập đại diện rồi Lưu
let suggestions = [];
async function openSuggest() {
  const box = $("#tc-sugg");
  box.hidden = false;
  $("#tc-suggest").setAttribute("aria-expanded", "true");
  box.innerHTML = `<p class="muted tiny">Đang đọc rule VPN…</p>`;
  try {
    // gợi ý tính theo các group đang hiện trong bảng (kể cả chưa lưu) → không gợi ý trùng thứ vừa thêm
    suggestions = (await api("/api/notify/contacts/suggest")).suggestions;
    const inTable = new Set($$("#tc-table .tc-team").map((x) => x.value.trim().toLowerCase()).filter(Boolean));
    const taken = new Set($$("#tc-table .tc-m").map((x) => x.dataset.u.toLowerCase()));
    suggestions = suggestions
      .map((s) => ({ ...s, existing: s.existing || inTable.has(s.team_key), users: s.users.filter((u) => !taken.has(u.toLowerCase())) }))
      .filter((s) => !(inTable.has(s.team_key) && !s.users.length));
    box.innerHTML = `<div class="tc-sugg__head"><h3 id="tc-sugg-title">Gợi ý group từ tên rule (${suggestions.length})</h3>
        <p class="muted tiny">Team bóc từ tên rule VPN (vd "RMS RESEARCH - CHAU.NB …"); thành viên là user được cấp quyền trong các rule đó. Bỏ tick user không thuộc group, bấm <strong>Chọn</strong> rồi nhập email đại diện và bấm <strong>Lưu group VPN</strong>.</p></div>
      ${suggestions.length ? `<div class="tc-sugg__list">${suggestions.map((s, i) => `
        <fieldset class="tc-sg">
          <legend><label class="check"><input type="checkbox" class="tc-sg__pick" data-i="${i}"${s.users.length ? " checked" : ""} />
            <strong>${esc(s.team)}</strong></label></legend>
          <p class="muted tiny" title="${esc(s.rules.join("\n"))}"><span class="tc-sg__kind ${s.existing ? "text-info" : "text-ok"}">${s.existing ? "Bổ sung thành viên" : "Group mới"}</span> · ${s.rules.length} rule: ${esc(s.rules.slice(0, 2).join(" · "))}${s.rules.length > 2 ? " · …" : ""}</p>
          <div class="tc-sg__users">${s.users.length ? s.users.map((u) => `<label class="check tc-sg__u"><input type="checkbox" class="tc-sg__user" data-i="${i}" value="${esc(u)}" checked /> <span>${esc(u)}</span></label>`).join("")
            : `<span class="muted tiny">Rule dùng group trên firewall / chưa đồng bộ tài khoản — chưa có user để gợi ý.</span>`}</div>
          ${s.taken.length ? `<p class="tiny text-warn">Đã thuộc group khác (không chuyển): ${s.taken.map((t) => `${esc(t.username)} → ${esc(t.group)}`).join(", ")}</p>` : ""}
        </fieldset>`).join("")}</div>
        <div class="actions"><button class="btn btn--ghost btn--sm" type="button" id="tc-sg-close">Đóng</button>
          <button class="btn btn--primary btn--sm" type="button" id="tc-sg-apply">Chọn các gợi ý đã tick</button></div>`
        : `<p class="empty">Không còn gợi ý: mọi team trong tên rule đã là group và đủ thành viên.</p>
           <div class="actions"><button class="btn btn--ghost btn--sm" type="button" id="tc-sg-close">Đóng</button></div>`}`;
  } catch (ex) {
    box.innerHTML = errorBox(ex);
  }
}

function closeSuggest() {
  $("#tc-sugg").hidden = true;
  $("#tc-suggest").setAttribute("aria-expanded", "false");
  $("#tc-suggest").focus();
}

function applySuggest() {
  const tb = $("#tc-table tbody");
  // bỏ dòng trống mặc định (chưa nhập gì) để group gợi ý không nằm dưới một dòng rỗng
  for (const tr of $$("tr", tb)) {
    if (![".tc-team", ".tc-emails", ".tc-note"].some((k) => $(k, tr).value.trim()) && !$$(".tc-m", tr).length) tr.remove();
  }
  let added = 0, grown = 0;
  let firstNew = null;
  for (const pick of $$("#tc-sugg .tc-sg__pick:checked")) {
    const s = suggestions[Number(pick.dataset.i)];
    const users = $$(`#tc-sugg .tc-sg__user[data-i="${pick.dataset.i}"]:checked`).map((x) => x.value);
    let tr = $$("tr", tb).find((r) => $(".tc-team", r).value.trim().toLowerCase() === s.team_key);
    if (!tr) {
      tb.insertAdjacentHTML("beforeend", contactRow({ team: s.team, emails: [], note: "", members: [] }));
      tr = tb.lastElementChild;
      added++;
    } else if (users.length) grown++;
    tr.classList.add("is-new");
    const input = $(".tc-madd", tr);
    const have = new Set($$(".tc-m", tr).map((x) => x.dataset.u.toLowerCase()));
    for (const u of users) {
      if (have.has(u.toLowerCase())) continue;
      input.insertAdjacentHTML("beforebegin", memberChip(u));
      input.previousElementSibling.classList.add("tc-m--new");
    }
    firstNew = firstNew || tr;
  }
  $("#tc-filter").value = "";
  applyTcFilter();
  refreshUnassigned();
  closeSuggest();
  if (!firstNew) return;
  say($("#tc-msg"), `Đã thêm ${added} group mới${grown ? `, bổ sung thành viên cho ${grown} group` : ""} — rà lại thành viên (bấm × để bỏ), nhập email đại diện rồi bấm Lưu group VPN.`, "ok");
  const email = $$("#tc-table tr.is-new .tc-emails").find((x) => !x.value.trim());
  (email || $(".tc-madd", firstNew)).focus();
  firstNew.scrollIntoView({ block: "center" });
}

$("#tc-suggest").addEventListener("click", () => ($("#tc-sugg").hidden ? openSuggest() : closeSuggest()));
$("#tc-sugg").addEventListener("click", (e) => {
  if (e.target.id === "tc-sg-close") closeSuggest();
  if (e.target.id === "tc-sg-apply") applySuggest();
});
// bỏ tick group → bỏ tick mọi user của group đó; tick user → tự tick group
$("#tc-sugg").addEventListener("change", (e) => {
  const i = e.target.dataset.i;
  if (e.target.classList.contains("tc-sg__pick")) {
    $$(`#tc-sugg .tc-sg__user[data-i="${i}"]`).forEach((x) => (x.checked = e.target.checked));
  } else if (e.target.classList.contains("tc-sg__user") && e.target.checked) {
    $(`#tc-sugg .tc-sg__pick[data-i="${i}"]`).checked = true;
  }
});

function addMembers(input) {
  const box = input.closest(".tc-members");
  const have = new Set($$(".tc-m", box).map((x) => x.dataset.u.toLowerCase()));
  for (const u of input.value.split(/[,;\s]+/).map((x) => x.trim()).filter(Boolean)) {
    if (!have.has(u.toLowerCase())) input.insertAdjacentHTML("beforebegin", memberChip(u));
    have.add(u.toLowerCase());
  }
  input.value = "";
  refreshUnassigned();
}

async function loadNotify() {
  try {
    const r = await api("/api/notify/settings");
    fillSmtp(r.smtp);
    $("#nt-enabled").checked = r.enabled;
    $("#nt-infra").value = r.infra_emails.join("\n");
    $("#nt-days").value = r.reminder_days.join(", ");
    $("#nt-weekly").checked = r.expired_weekly;
    // đang sửa dở bảng group thì không ghi đè (vd vừa bấm Lưu thông báo → tải lại cấu hình)
    if (!tcDirty() || !tcSaved.length) renderContacts(r.contacts);
    try {
      const [rules, accs] = await Promise.all([api("/api/vpn/rules"), api("/api/vpn/accounts")]);
      $("#tc-teams").innerHTML = rules.teams.map((t) => `<option value="${esc(t)}"></option>`).join("");
      vpnUsers = [...new Set(accs.accounts.map((a) => a.username))].sort();
    } catch {
      /* chưa đồng bộ VPN: vẫn nhập tay được */
    }
    refreshUnassigned();
    applyTcFilter();
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#smtp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    enabled: $("#smtp-enabled").checked,
    host: $("#smtp-host").value.trim(),
    port: Number($("#smtp-port").value || 25),
    security: $("#smtp-security").value,
    verify_tls: $("#smtp-verify").checked,
    username: $("#smtp-user").value.trim(),
    from_addr: $("#smtp-from").value.trim(),
    from_name: $("#smtp-from-name").value.trim(),
    clear_password: $("#smtp-clear").checked,
  };
  if ($("#smtp-pass").value) body.password = $("#smtp-pass").value;
  try {
    fillSmtp(await api("/api/settings/smtp", { method: "PUT", body }));
    say($("#smtp-msg"), "Đã lưu cấu hình SMTP.", "ok");
  } catch (ex) {
    say($("#smtp-msg"), ex.message, "error");
  }
});

$("#smtp-test").addEventListener("click", async () => {
  const btn = $("#smtp-test");
  setBusy(btn, true, "Đang gửi…");
  try {
    const r = await api("/api/settings/smtp/test", { method: "POST", body: { to: $("#smtp-test-to").value.trim() } });
    say($("#smtp-msg"), r.message, "ok");
  } catch (ex) {
    say($("#smtp-msg"), ex.message, "error");
  }
  setBusy(btn, false, "Gửi thử");
});

$("#nt-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const days = $("#nt-days").value.split(/[,\s]+/).filter(Boolean).map(Number);
  try {
    await api("/api/notify/settings", {
      method: "PUT",
      body: {
        enabled: $("#nt-enabled").checked,
        infra_emails: $("#nt-infra").value,
        reminder_days: days,
        expired_weekly: $("#nt-weekly").checked,
      },
    });
    say($("#nt-msg"), "Đã lưu cấu hình thông báo.", "ok");
    loadNotify();
  } catch (ex) {
    say($("#nt-msg"), ex.message, "error");
  }
});

$("#tc-add").addEventListener("click", () => {
  $("#tc-filter").value = ""; // dòng mới phải thấy được
  applyTcFilter();
  $("#tc-table tbody").insertAdjacentHTML("beforeend", contactRow());
  $("#tc-table tbody tr:last-child .tc-team").focus();
});
$("#tc-table").addEventListener("click", (e) => {
  const x = e.target.closest(".tc-m__x");
  if (x) {
    const input = x.closest(".tc-members").querySelector(".tc-madd");
    x.closest(".tc-m").remove();
    input.focus();
    refreshUnassigned();
    return;
  }
  const b = e.target.closest(".tc-del");
  if (b) delGroup(b.closest("tr"));
});

async function delGroup(tr) {
  const team = $(".tc-team", tr).value.trim();
  const n = $$(".tc-m", tr).length;
  if ((team || n) && !(await confirmAction({
    title: `Xóa group ${team || "(chưa đặt tên)"}?`, ok: "Xóa group",
    html: `<p>${n ? `${n} user VPN của group sẽ thành <strong>chưa thuộc group nào</strong>; ` : ""}đại diện không còn nhận email rà soát và nhắc hạn của group.
      Thay đổi chỉ áp dụng khi bấm <strong>Lưu group VPN</strong> (trước đó bấm Hoàn tác để lấy lại).</p>`,
  }))) return;
  tr.remove();
  refreshUnassigned();
  updateDirty();
}

// Mọi thay đổi trong bảng (gõ, thêm / bỏ chip, thêm / xóa dòng, chọn gợi ý) → cập nhật trạng thái chưa lưu
$("#tc-table").addEventListener("input", updateDirty);
new window.MutationObserver(updateDirty).observe($("#tc-table tbody"), { childList: true, subtree: true });
$("#tc-undo").addEventListener("click", () => {
  renderContacts(tcSaved);
  say($("#tc-msg"), "Đã hoàn tác về bản đã lưu.", "ok");
});
window.addEventListener("beforeunload", (e) => {
  if (!tcDirty()) return;
  e.preventDefault();
  e.returnValue = ""; // trình duyệt hiện hộp "Rời trang? Thay đổi chưa lưu"
});
// Thêm user: chọn từ gợi ý (change), Enter, hoặc dán nhiều user phân cách dấu phẩy / khoảng trắng
$("#tc-table").addEventListener("change", (e) => {
  if (e.target.classList.contains("tc-madd")) addMembers(e.target);
});
$("#tc-table").addEventListener("keydown", (e) => {
  if (!e.target.classList.contains("tc-madd")) return;
  if (e.key === "Enter") {
    e.preventDefault();
    addMembers(e.target);
  } else if (e.key === "Backspace" && !e.target.value) {
    const prev = e.target.previousElementSibling;
    if (prev?.classList.contains("tc-m")) prev.remove();
    refreshUnassigned();
  }
});
$("#tc-save").addEventListener("click", async () => {
  const contacts = collectContacts();
  try {
    const r = await api("/api/notify/contacts", { method: "PUT", body: { contacts } });
    renderContacts(r.contacts);
    say($("#tc-msg"), `Đã lưu ${r.contacts.length} group VPN.`, "ok");
  } catch (ex) {
    say($("#tc-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ hàng đợi
const OB = { pending: ["chip--warn", "Đang chờ"], sent: ["chip--ok", "Đã gửi"], failed: ["chip--err", "Thất bại"] };

async function loadOutbox() {
  const tb = $("#ob-table tbody");
  tableMessage(tb, 5, "loading");
  try {
    const p = $("#ob-status").value ? `&status=${$("#ob-status").value}` : "";
    const r = await api(`/api/notify/outbox?limit=100${p}`);
    if (!r.emails.length) return tableMessage(tb, 5, "empty", "Chưa có email nào.");
    tb.innerHTML = r.emails.map((m) => {
      const [cls, label] = OB[m.status] || ["", m.status];
      return `<tr>
        <td class="nowrap mono tiny">${esc(fmtTime(m.sent_at || m.created_at))}</td>
        <td class="nowrap"><span class="chip ${cls}">${label}</span></td>
        <td>${esc(m.subject)}</td>
        <td class="tiny">${m.to.map(esc).join("<br>")}</td>
        <td class="tiny">${m.attempts}${m.last_error ? ` · <span class="text-err">${esc(m.last_error)}</span>` : ""}${
          m.status === "pending" && m.attempts ? `<div class="muted">thử lại ${esc(fmtTime(m.next_attempt_at))}</div>` : ""}</td>
      </tr>`;
    }).join("");
  } catch (ex) {
    tableMessage(tb, 5, "error", ex.message);
  }
}

$("#ob-status").addEventListener("change", loadOutbox);
$("#ob-run").addEventListener("click", async () => {
  const btn = $("#ob-run");
  setBusy(btn, true, "Đang chạy…");
  try {
    const r = await api("/api/notify/run", { method: "POST" });
    $("#ob-note").textContent = r.note
      ? r.note
      : `Xếp hàng ${r.queued ?? 0} thư mới · đã gửi ${r.sent} · thử lại ${r.retry} · đang chờ ${r.pending}`;
    toast(r.note || `Đã gửi ${r.sent} thư`, r.retry || r.failed ? "err" : "ok");
    await loadOutbox();
  } catch (ex) {
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Chạy ngay");
});
