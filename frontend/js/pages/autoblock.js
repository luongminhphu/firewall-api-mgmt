/* Tab Tự động chặn — lệnh "ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>" đọc từ group chat Teams.
   - Mọi vai trò (viewer trở lên): trạng thái (công tắc, ngưỡng, khung giờ, lần đọc Teams), danh sách chờ duyệt,
     ca ngoài giờ gần nhất (đêm / cuối tuần / ngày lễ), tất cả lệnh, kiểm tra chuỗi băm.
   - Write: duyệt / từ chối, gỡ chặn (từng IP hoặc cả ca), TẮT KHẨN CẤP.
   - Quản trị viên: bật lại công tắc, mở lại sau khi vượt ngưỡng, đọc Teams ngay. */
import { api, errorBox, runJob } from "../api.js";
import { pageSlice, renderPager } from "../components/pagination.js";
import { tableMessage } from "../components/table.js";
import { resultChip } from "../components/badge.js";
import { toast } from "../components/toast.js";
import { can } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

const ab = { status: null, all: [], page: 1 };
const STATUS = {
  blocking: ["chip--info", "Đang chặn"], blocked: ["chip--ok", "Đã chặn"], failed: ["chip--err", "Lỗi"],
  pending: ["chip--warn", "Chờ duyệt"], rejected: ["", "Từ chối"], invalid: ["", "Không hợp lệ"],
  duplicate: ["", "Trùng"], unblocking: ["chip--info", "Đang gỡ"], unblocked: ["", "Đã gỡ"],
};
const MODE = { auto: "Tự chặn", pending: "Chờ duyệt", invalid: "—", duplicate: "—" };
const chip = (s) => {
  const [cls, label] = STATUS[s] || ["", s];
  return `<span class="chip ${cls}">${label}</span>`;
};
const hhmm = (iso) => fmtTime(iso).replace(/:\d\d$/, "");

export async function loadAutoblock() {
  $$("#panel-autoblock .ab-op").forEach((el) => (el.hidden = !can("operator")));
  await Promise.all([loadStatus(), loadPending(), loadNight(), loadAll()]);
}

// ------------------------------------------------------------------ trạng thái
async function loadStatus() {
  try {
    const s = (ab.status = await api("/api/autoblock/status"));
    renderStatus(s);
  } catch (ex) {
    $("#ab-banner").innerHTML = errorBox(ex);
  }
}

function renderStatus(s) {
  $("#ab-off").hidden = !(can("operator") && s.auto_enabled);
  $("#ab-on").hidden = !(can("admin") && !s.auto_enabled);
  $("#ab-poll").hidden = !(can("admin") && s.enabled);
  let banner = "";
  if (!s.enabled) {
    banner = `<p class="alert alert--info">Chưa bật đọc Teams${can("admin") ? " — cấu hình ở tab <strong>Cài đặt</strong>" : ""}. App chưa tự chặn IP nào.</p>`;
  } else if (s.breaker_tripped_at) {
    banner = `<div class="alert alert--error ab-breaker" role="alert"><div><strong>Đã NGẮT do vượt ngưỡng</strong>
      <p>${esc(s.breaker_reason)} (lúc ${esc(hhmm(s.breaker_tripped_at))}). Mọi lệnh mới chuyển sang chờ duyệt.</p></div>
      ${can("admin") ? `<button class="btn btn--sm" id="ab-reset" type="button">Mở lại tự động chặn</button>` : ""}</div>`;
  } else if (!s.auto_enabled) {
    banner = `<p class="alert alert--warn" role="status"><strong>Tự động chặn đang TẮT (công tắc khẩn cấp).</strong> App vẫn đọc Teams, mọi lệnh chuyển sang chờ duyệt.</p>`;
  } else if (s.last_ok === false) {
    banner = `<p class="alert alert--error" role="alert">Đọc Teams lỗi: ${esc(s.last_error)}</p>`;
  }
  $("#ab-banner").innerHTML = banner;
  $("#ab-today").hidden = !(can("admin") && s.window_enabled && (s.holiday_today || !s.in_window));
  $("#ab-today").textContent = s.holiday_today ? "Tắt tự chặn cả ngày hôm nay" : "Tự chặn cả ngày hôm nay";
  $("#ab-today").dataset.on = s.holiday_today ? "0" : "1";
  const win = s.window_enabled ? (s.in_window ? "ĐANG TỰ CHẶN" : "GIỜ HÀNH CHÍNH") : "24/7";
  const cards = [
    [s.auto_enabled ? "BẬT" : "TẮT", "Công tắc tự động chặn", s.auto_enabled ? "ok" : "err"],
    [`${s.auto_last_hour}/${s.hourly_limit}`, "IP tự chặn trong 60 phút",
     s.breaker_tripped_at ? "err" : s.auto_last_hour >= s.hourly_limit * 0.8 ? "warn" : ""],
    [win, s.window_enabled ? (s.in_window ? s.window_reason : "Lệnh SOC chờ duyệt") : "Tự chặn mọi lúc",
     s.in_window ? "ok" : "warn", s.window_enabled ? `Lịch tự chặn: ${s.schedule}` : ""],
    [String(s.pending), "Lệnh chờ duyệt", s.pending ? "warn" : ""],
    [s.last_poll_at ? fmtTime(s.last_poll_at).split(" ")[0] : "—",
     s.enabled ? `Đọc Teams lần cuối · mỗi ${Math.round(s.poll_seconds / 60)} phút` : "Chưa bật đọc Teams",
     s.last_ok === false ? "err" : ""],
  ];
  $("#ab-cards").innerHTML = cards.map(([v, label, tone, title]) =>
    `<div class="status-card ab-card${tone ? " status-card--" + tone : ""}"${title ? ` title="${esc(title)}"` : ""}>
      <b>${esc(v)}</b><span>${esc(label)}</span></div>`).join("");
  const d = (iso) => new Date(iso).toLocaleString("vi-VN", { hour: "2-digit", minute: "2-digit", day: "2-digit",
    month: "2-digit", weekday: "short", hour12: false, timeZone: "Asia/Ho_Chi_Minh" });
  $("#ab-night-title").textContent = `Ca ngoài giờ: ${d(s.night.start)} → ${d(s.night.end)}`;
  $("#ab-pending-count").textContent = s.pending;
}

$("#ab-banner").addEventListener("click", async (e) => {
  if (!e.target.closest("#ab-reset")) return;
  try {
    renderStatus((ab.status = await api("/api/autoblock/breaker/reset", { method: "POST" })));
    toast("Đã mở lại tự động chặn", "ok");
  } catch (ex) {
    toast(ex.message, "err");
  }
});

async function setSwitch(on) {
  if (!on && !confirm("TẮT KHẨN CẤP tự động chặn?\n\nApp vẫn đọc Teams nhưng mọi lệnh của SOC sẽ chuyển sang chờ duyệt.")) return;
  try {
    renderStatus((ab.status = await api("/api/autoblock/switch", { method: "POST", body: { on } })));
    toast(on ? "Đã bật lại tự động chặn" : "Đã TẮT tự động chặn", on ? "ok" : "");
  } catch (ex) {
    toast(ex.message, "err");
  }
}
$("#ab-off").addEventListener("click", () => setSwitch(false));
$("#ab-on").addEventListener("click", () => setSwitch(true));

$("#ab-today").addEventListener("click", async () => {
  const on = $("#ab-today").dataset.on === "1";
  if (on && !confirm("Tự chặn cả ngày hôm nay (ngày lễ / nghỉ đột xuất)?\n\nLệnh SOC gửi trong hôm nay sẽ được chặn ngay, không chờ duyệt.")) return;
  try {
    renderStatus((ab.status = await api("/api/autoblock/holiday-today", { method: "POST", body: { on } })));
    toast(on ? "Đã bật tự chặn cả ngày hôm nay" : "Đã tắt tự chặn cả ngày hôm nay", "ok");
  } catch (ex) {
    toast(ex.message, "err");
  }
});

$("#ab-poll").addEventListener("click", async () => {
  const b = $("#ab-poll");
  b.disabled = true;
  try {
    const r = await api("/api/autoblock/poll", { method: "POST" });
    if (r.ok === false) toast(`Đọc Teams lỗi: ${r.error}`, "err");
    else if (r.skipped) toast("Bộ đọc đang chạy hoặc chưa bật", "");
    else toast(`Đã đọc ${r.messages} tin mới · ${r.auto} tự chặn · ${r.pending} chờ duyệt`, "ok");
    await loadAutoblock();
  } catch (ex) {
    toast(ex.message, "err");
  } finally {
    b.disabled = false;
  }
});

// ------------------------------------------------------------------ chờ duyệt
async function loadPending() {
  const tb = $("#ab-pending tbody");
  const cols = can("operator") ? 6 : 4;
  try {
    const { items } = await api("/api/autoblock/requests?view=pending");
    $("#ab-pending-all").checked = false;
    $("#ab-approve-sel").disabled = true;
    if (!items.length) return tableMessage(tb, cols, "empty", "Không có lệnh nào chờ duyệt.");
    const op = can("operator");
    tb.innerHTML = items.map((r) => `<tr>
      ${op ? `<td><input type="checkbox" class="ab-pick" value="${r.id}" aria-label="Chọn ${esc(r.ip)}"${r.needs_admin && !can("admin") ? " disabled" : ""} /></td>` : ""}
      <td class="mono" data-label="Thời gian">${esc(hhmm(r.created_at))}</td><td class="mono" data-label="IP"><strong>${esc(r.ip)}</strong></td>
      <td data-label="SOC gửi">${esc(r.sender)}</td>
      <td class="tiny" data-label="Lý do chờ">${r.whitelist ? `<span class="chip chip--info">Whitelist · ${esc(r.whitelist)}</span> ` : ""}${esc(r.pending_reason)}</td>
      ${op ? `<td class="nowrap ab-act">${approveBtn(r)}
        <button class="btn btn--ghost btn--sm" type="button" data-reject="${r.id}">Từ chối</button></td>` : ""}</tr>`).join("");
  } catch (ex) {
    tableMessage(tb, cols, "error", ex.message);
  }
}

// IP thuộc whitelist (HSC / Akamai / đối tác): chỉ quản trị viên Approve — server kiểm lại
const approveBtn = (r) => (r.needs_admin && !can("admin")
  ? `<button class="btn btn--sm" type="button" disabled title="IP thuộc whitelist — chỉ quản trị viên Approve được">Approve</button>`
  : `<button class="btn btn--primary btn--sm" type="button" data-approve="${r.id}"${r.needs_admin
    ? ` data-wl="${esc(r.whitelist)}"` : ""}>Approve</button>`);

const picked = () => $$("#ab-pending .ab-pick:checked").map((x) => Number(x.value));
$("#ab-pending").addEventListener("change", (e) => {
  if (e.target.id === "ab-pending-all") {
    $$("#ab-pending .ab-pick:not(:disabled)").forEach((x) => (x.checked = e.target.checked));
  }
  $("#ab-approve-sel").disabled = !picked().length;
});

async function approve(ids, wl = "") {
  const warn = wl ? `\n\nCẢNH BÁO: IP thuộc whitelist ${wl} (HSC / Akamai / đối tác) — chặn có thể gây gián đoạn dịch vụ.` : "";
  if (!confirm(`Approve: chặn ${ids.length} IP trên mọi firewall đích?${warn}`)) return;
  try {
    const job = await runJob("/api/autoblock/approve", { ids });
    const errs = (job.results || []).filter((r) => !r.ok).length;
    toast(errs ? `Đã chạy, ${errs} firewall báo lỗi — xem cột kết quả` : `Đã chặn ${ids.length} IP`, errs ? "err" : "ok");
  } catch (ex) {
    toast(ex.message, "err");
  }
  loadAutoblock();
}
$("#ab-approve-sel").addEventListener("click", () => approve(picked()));
$("#ab-pending").addEventListener("click", async (e) => {
  const a = e.target.closest("[data-approve]");
  if (a) return approve([Number(a.dataset.approve)], a.dataset.wl || "");
  const r = e.target.closest("[data-reject]");
  if (!r) return;
  const note = window.prompt("Lý do từ chối (không bắt buộc):", "");
  if (note === null) return;
  try {
    await api("/api/autoblock/reject", { method: "POST", body: { ids: [Number(r.dataset.reject)], note } });
    toast("Đã từ chối — IP không bị chặn", "ok");
  } catch (ex) {
    toast(ex.message, "err");
  }
  loadAutoblock();
});

// ------------------------------------------------------------------ ca ngoài giờ
const fwResults = (r) => (r.results || []).map((x) =>
  `<span class="nowrap">${esc(x.firewall)} ${resultChip(x.result)}</span>`).join(" ") || "—";

async function loadNight() {
  const tb = $("#ab-night tbody");
  const cols = can("operator") ? 6 : 5;
  try {
    const { items } = await api("/api/autoblock/requests?view=night");
    $("#ab-night-undo").disabled = !items.some((r) => r.status === "blocked");
    if (!items.length) return tableMessage(tb, cols, "empty", "Ca này app chưa tự chặn IP nào.");
    tb.innerHTML = items.map((r) => `<tr>
      <td class="mono" data-label="Thời gian">${esc(hhmm(r.created_at))}</td><td class="mono" data-label="IP"><strong>${esc(r.ip)}</strong></td>
      <td data-label="SOC gửi">${esc(r.sender)}</td><td data-label="Trạng thái">${chip(r.status)}</td>
      <td class="tiny" data-label="Firewall">${fwResults(r)}</td>
      ${can("operator") ? `<td class="ab-act">${unblockBtn(r)}</td>` : ""}</tr>`).join("");
  } catch (ex) {
    tableMessage(tb, cols, "error", ex.message);
  }
}

const unblockBtn = (r) => ["blocked", "failed"].includes(r.status)
  ? `<button class="btn btn--danger-ghost btn--sm" type="button" data-unblock="${r.id}" data-ip="${esc(r.ip)}">Gỡ chặn</button>` : "";

async function unblock(body, label) {
  if (!confirm(`Gỡ chặn ${label} khỏi SCANPORT GROUP trên mọi firewall đích?`)) return;
  try {
    await runJob("/api/autoblock/unblock", body);
    toast(`Đã gỡ chặn ${label}`, "ok");
  } catch (ex) {
    toast(ex.message, "err");
  }
  loadAutoblock();
}
$("#ab-night-undo").addEventListener("click", () => unblock({ night: true }, "TẤT CẢ IP tự chặn trong ca ngoài giờ"));
$("#panel-autoblock").addEventListener("click", (e) => {
  const b = e.target.closest("[data-unblock]");
  if (b) unblock({ ids: [Number(b.dataset.unblock)] }, b.dataset.ip);
});

// ------------------------------------------------------------------ tất cả lệnh
async function loadAll() {
  const tb = $("#ab-all tbody");
  try {
    ab.all = (await api(`/api/autoblock/requests?status=${encodeURIComponent($("#ab-status").value)}`)).items;
    ab.page = 1;
    renderAll();
  } catch (ex) {
    tableMessage(tb, 7, "error", ex.message);
  }
}

function renderAll() {
  const tb = $("#ab-all tbody");
  const op = can("operator");
  if (!ab.all.length) {
    tableMessage(tb, op ? 7 : 6, "empty", "Chưa có lệnh nào.");
    renderPager($("#ab-pager"), { page: 1, pages: 1, total: 0 }, () => {});
    return;
  }
  const pg = pageSlice(ab.all, ab.page);
  tb.innerHTML = pg.rows.map((r) => {
    const who = r.decided_by ? `duyệt/từ chối: ${r.decided_by}` : "";
    const un = r.unblocked_by ? `gỡ: ${r.unblocked_by} ${hhmm(r.unblocked_at)}` : "";
    const note = [r.pending_reason, r.note, who, un].filter(Boolean).join(" · ");
    const rep = { sent: `<span class="chip chip--ok" title="${esc(fmtTime(r.replied_at))}">Đã báo Teams</span> `,
      failed: `<span class="chip chip--err">Chưa báo Teams (${r.reply_attempts} lần)</span> ` }[r.reply_status] || "";
    return `<tr><td class="mono">${esc(hhmm(r.created_at))}</td><td class="mono">${esc(r.ip)}</td>
      <td>${esc(r.sender)}</td><td>${esc(MODE[r.mode] || r.mode)}</td><td>${chip(r.status)}</td>
      <td class="tiny">${rep}${esc(note)}${r.results?.length ? `<div>${fwResults(r)}</div>` : ""}</td>
      ${op ? `<td>${unblockBtn(r)}</td>` : ""}</tr>`;
  }).join("");
  renderPager($("#ab-pager"), { page: pg.page, pages: pg.pages, total: ab.all.length }, (p) => {
    ab.page = p;
    renderAll();
  });
}
$("#ab-status").addEventListener("change", loadAll);

$("#ab-verify").addEventListener("click", async () => {
  try {
    const v = await api("/api/autoblock/verify");
    $("#ab-verify-msg").innerHTML = `<span class="chip ${v.ok ? "chip--ok" : "chip--err"}">${esc(v.message)}</span>`;
  } catch (ex) {
    toast(ex.message, "err");
  }
});
