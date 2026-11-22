/* Tab Tự động chặn — lệnh "ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>" đọc từ group chat Teams.
   - Mọi vai trò (viewer trở lên): trạng thái (công tắc, ngưỡng, khung giờ, lần đọc Teams), danh sách chờ duyệt,
     ca ngoài giờ gần nhất (đêm / cuối tuần / ngày lễ), tất cả lệnh, kiểm tra chuỗi băm.
   - Write: duyệt / từ chối, gỡ chặn (từng IP hoặc cả ca), TẮT KHẨN CẤP.
   - Quản trị viên: bật lại công tắc, mở lại sau khi vượt ngưỡng, đọc Teams ngay. */
import { API, api, errorBox, runJob } from "../api.js";
import { openModal, confirmAction } from "../components/modal.js";
import { pageSlice, renderPager } from "../components/pagination.js";
import { tableMessage } from "../components/table.js";
import { resultChip } from "../components/badge.js";
import { toast } from "../components/toast.js";
import { can, state } from "../store.js";
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
  } else if (s.last_truncated) {
    banner = `<p class="alert alert--warn" role="status">Lần đọc gần nhất có quá nhiều tin mới (trên 1.000) — app đọc tiếp ở chu kỳ sau; lệnh trễ quá ${s.stale_minutes} phút sẽ chờ duyệt.</p>`;
  }
  $("#ab-banner").innerHTML = banner;
  $("#ab-today").hidden = !(can("admin") && s.window_enabled && (s.holiday_today || !s.in_window));
  $("#ab-today").textContent = s.holiday_today ? "Tắt tự chặn cả ngày hôm nay" : "Tự chặn cả ngày hôm nay";
  $("#ab-today").dataset.on = s.holiday_today ? "0" : "1";
  const win = s.window_enabled ? (s.in_window ? "ĐANG TỰ CHẶN" : "GIỜ HÀNH CHÍNH") : "24/7";
  // Một dòng trạng thái thay cho 5 ô số: mọi thứ ổn thì yên lặng, có vấn đề thì phần đó đổi màu
  const seg = (txt, tone = "", title = "") =>
    `<span class="ab-seg${tone ? " ab-seg--" + tone : ""}"${title ? ` title="${esc(title)}"` : ""}>${txt}</span>`;
  const near = s.auto_last_hour >= s.hourly_limit * 0.8;
  $("#ab-cards").innerHTML = [
    seg(`<strong>Tự động chặn ${s.auto_enabled ? "BẬT" : "TẮT"}</strong>`, s.auto_enabled ? "ok" : "err"),
    seg(`${esc(win)}${s.window_enabled ? ` · ${esc(s.in_window ? s.window_reason : "lệnh SOC chờ duyệt")}` : ""}`,
      s.in_window ? "" : "warn", s.window_enabled ? `Lịch tự chặn: ${s.schedule}` : ""),
    seg(`${s.auto_last_hour} IP tự chặn / 60 phút (giới hạn ${s.hourly_limit})`, s.breaker_tripped_at ? "err" : near ? "warn" : ""),
    seg(s.enabled ? `Đọc Teams ${s.last_poll_at ? esc(fmtTime(s.last_poll_at).split(" ")[0]) : "—"} · ${s.last_fetched} tin mới · mỗi ${Math.round(s.poll_seconds / 60)} phút`
      : "Chưa bật đọc Teams", s.last_ok === false ? "err" : ""),
  ].join('<span class="ab-sep" aria-hidden="true">·</span>');
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
  if (!on && !(await confirmAction({ title: "Tắt khẩn cấp tự động chặn?", ok: "Tắt tự động chặn", html: "<p>App vẫn đọc Teams nhưng <strong>mọi lệnh của SOC chuyển sang chờ duyệt</strong> cho tới khi bật lại.</p>" }))) return;
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
  if (on && !(await confirmAction({ title: "Tự chặn cả ngày hôm nay?", ok: "Tự chặn cả hôm nay", html: "<p>Dùng cho ngày lễ / nghỉ đột xuất: lệnh SOC gửi trong hôm nay được <strong>chặn ngay, không chờ duyệt</strong>.</p>" }))) return;
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
    tb.innerHTML = items.map((r) => `<tr${r.needs_admin ? ' class="is-wl"' : ""}>
      ${op ? `<td>${r.needs_admin
        ? `<span class="sr-only">IP whitelist — duyệt riêng từng dòng</span>`
        : `<input type="checkbox" class="ab-pick" value="${r.id}" aria-label="Chọn ${esc(r.ip)}" />`}</td>` : ""}
      <td class="mono" data-label="SOC gửi lúc">${esc(hhmm(r.requested_at || r.created_at))}</td><td class="mono" data-label="IP"><strong>${esc(r.ip)}</strong></td>
      <td data-label="SOC gửi">${esc(r.sender)}</td>
      <td class="tiny" data-label="Lý do chờ">${r.whitelist ? `<span class="chip chip--info">Whitelist · ${esc(r.whitelist)}</span> ` : ""}${esc(r.pending_reason)}</td>
      ${op ? `<td class="nowrap ab-act">${approveBtn(r)}
        <button class="btn btn--ghost btn--sm" type="button" data-reject="${r.id}">Từ chối</button></td>` : ""}</tr>`).join("");
  } catch (ex) {
    tableMessage(tb, cols, "error", ex.message);
  }
}

// IP thuộc whitelist (HSC / Akamai / đối tác): chỉ quản trị viên duyệt — server kiểm lại
const approveBtn = (r) => (r.needs_admin && !can("admin")
  ? `<button class="btn btn--sm" type="button" disabled title="IP thuộc whitelist — chỉ quản trị viên duyệt được">Duyệt (ghi đè whitelist)</button>`
  : r.needs_admin // IP whitelist: không là nút chính, ghi rõ đang ghi đè; không nằm trong duyệt hàng loạt
    ? `<button class="btn btn--sm btn--warn-ghost" type="button" data-approve="${r.id}" data-ip="${esc(r.ip)}" data-wl="${esc(r.whitelist)}">Duyệt (ghi đè whitelist)</button>`
    : `<button class="btn btn--primary btn--sm" type="button" data-approve="${r.id}" data-ip="${esc(r.ip)}">Duyệt</button>`);

const picked = () => $$("#ab-pending .ab-pick:checked").map((x) => Number(x.value));
$("#ab-pending").addEventListener("change", (e) => {
  if (e.target.id === "ab-pending-all") {
    $$("#ab-pending .ab-pick:not(:disabled)").forEach((x) => (x.checked = e.target.checked));
  }
  $("#ab-approve-sel").disabled = !picked().length;
});

// Bảng thông tin dùng chung cho màn xác nhận (giống Chặn nhanh): firewall đích, group, danh sách IP
const facts = (ips) => {
  const fws = ab.status?.targets || [];
  return `<dl class="confirm-facts">
      <dt>Firewall</dt><dd>${fws.length ? fws.map(esc).join(", ") : "—"}</dd>
      <dt>IP Host Group</dt><dd class="mono">SCANPORT GROUP</dd>
    </dl>${ips.length ? `<div class="confirm-ips">${ips.map((i) => `<span class="mono">${esc(i)}</span>`).join("")}</div>` : ""}`;
};
const nFw = () => (ab.status?.targets || []).length;
const pendingIp = (id) => $(`#ab-pending .ab-pick[value="${id}"]`)?.getAttribute("aria-label")?.replace(/^Chọn /, "")
  || $(`#ab-pending [data-approve="${id}"]`)?.dataset.ip || `#${id}`;

async function approve(ids, wl = "") {
  if (!(await confirmAction({ title: "Duyệt lệnh chặn trên firewall đang chạy?", ok: `Chặn ${ids.length} IP trên ${nFw()} firewall`,
    html: `${facts(ids.map(pendingIp))}${wl ? `<p class="alert alert--warn">IP thuộc whitelist <strong>${esc(wl)}</strong> (HSC / Akamai / đối tác) — chặn có thể gây gián đoạn dịch vụ.</p>` : ""}` }))) return;
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
      <td class="mono" data-label="SOC gửi lúc">${esc(hhmm(r.requested_at || r.created_at))}</td><td class="mono" data-label="IP"><strong>${esc(r.ip)}</strong></td>
      <td data-label="SOC gửi">${esc(r.sender)}</td><td data-label="Trạng thái">${chip(r.status)}</td>
      <td class="tiny" data-label="Firewall">${fwResults(r)}</td>
      ${can("operator") ? `<td class="ab-act">${unblockBtn(r)}</td>` : ""}</tr>`).join("");
  } catch (ex) {
    tableMessage(tb, cols, "error", ex.message);
  }
}

const evBtn = (r) => (["invalid", "duplicate"].includes(r.status) && !r.requested_at ? ""
  : `<button class="btn btn--ghost btn--sm" type="button" data-ev="${r.id}" aria-label="Bằng chứng lệnh ${esc(r.ip)}">Bằng chứng</button>`);

const unblockBtn = (r) => ["blocked", "failed"].includes(r.status)
  ? `<button class="btn btn--sm" type="button" data-unblock="${r.id}" data-ip="${esc(r.ip)}">Gỡ chặn</button>` : "";

async function unblock(body, label) {
  if (!(await confirmAction({ title: "Gỡ chặn — khôi phục truy cập?", ok: body.night ? "Gỡ tất cả IP của ca" : `Gỡ chặn ${label}`, danger: false,
    html: `<p>IP được gỡ khỏi group sẽ <strong>truy cập lại được</strong> qua các firewall này.</p>${facts(body.night ? [] : [label])}${body.night ? `<p><strong>${esc(label)}</strong></p>` : ""}` }))) return;
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
    tableMessage(tb, 7, "empty", "Chưa có lệnh nào.");
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
    return `<tr><td class="mono">${esc(hhmm(r.requested_at || r.created_at))}</td><td class="mono">${esc(r.ip)}</td>
      <td>${esc(r.sender)}</td><td>${esc(MODE[r.mode] || r.mode)}</td><td>${chip(r.status)}</td>
      <td class="tiny">${rep}${esc(note)}${r.results?.length ? `<div>${fwResults(r)}</div>` : ""}</td>
      <td class="nowrap">${evBtn(r)}${op ? unblockBtn(r) : ""}</td></tr>`;
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

// ------------------------------------------------------------------ bằng chứng (bản chụp tin Teams)
const TEAMS_STATE = {
  intact: ["chip--ok", "Tin còn nguyên trên Teams"],
  edited: ["chip--warn", "Tin đã bị SỬA trên Teams"],
  deleted: ["chip--err", "Tin đã bị XÓA trên Teams"],
};

async function showEvidence(id) {
  try {
    const d = await api(`/api/autoblock/requests/${id}/evidence`);
    const e = d.evidence, t = d.teams_now;
    const [cls, label] = TEAMS_STATE[t.state] || ["", t.state];
    const href = `${API}/api/autoblock/requests/${id}/evidence.json?token=${encodeURIComponent(state.token)}`;
    openModal(`Bằng chứng lệnh BLOCK IP ${d.request.ip}`, `
      <p class="ev-state"><span class="chip ${cls}">${label}</span>
        <span class="chip ${e.intact ? "chip--ok" : "chip--err"}">${e.intact ? "Bản chụp toàn vẹn (SHA-256 + chuỗi băm khớp)" : "Bản chụp KHÔNG khớp băm"}</span></p>
      ${t.deleted_at ? `<p class="alert alert--warn">Người gửi đã xóa tin lúc <strong>${esc(fmtTime(t.deleted_at))}</strong> (giờ Microsoft); app phát hiện lúc ${esc(fmtTime(t.deleted_seen_at))}. Bản chụp dưới đây được lưu lúc app nhận tin, trước khi chặn.</p>` : ""}
      ${t.edited_at ? `<p class="alert alert--warn">Tin bị sửa lúc <strong>${esc(fmtTime(t.edited_at))}</strong> sau khi app xử lý; bản chụp giữ nội dung gốc.</p>` : ""}
      <dl class="kv">
        <dt>SOC gửi lúc (Teams)</dt><dd class="mono">${esc(fmtTime(e.teams_created_at))}</dd>
        <dt>App nhận &amp; chụp lúc</dt><dd class="mono">${esc(fmtTime(e.captured_at))}</dd>
        <dt>Chặn xong lúc</dt><dd class="mono">${esc(fmtTime(d.request.blocked_at) || "—")}</dd>
        <dt>Người gửi</dt><dd>${esc(e.sender_name)} <span class="muted tiny mono">${esc(e.sender_id)}</span></dd>
        <dt>Message ID · Chat ID</dt><dd class="mono tiny">${esc(e.msg_id)} · ${esc(e.chat_id)}</dd>
        <dt>Lệnh bóc được</dt><dd>${e.commands.map((c) => `<code>${esc(c.line)}</code>`).join("<br>")}</dd>
        <dt>SHA-256 bản gốc</dt><dd class="mono tiny">${esc(e.sha256)}</dd>
      </dl>
      <h3 class="dialog__sub">Nội dung tin gốc (lúc app nhận)</h3>
      <pre class="ev-text">${esc(e.text)}</pre>
      <div class="actions"><a class="btn btn--primary" href="${href}" download>Tải bằng chứng (JSON)</a></div>`);
  } catch (ex) {
    toast(ex.message, "err");
  }
}
$("#panel-autoblock").addEventListener("click", (e) => {
  const b = e.target.closest("[data-ev]");
  if (b) showEvidence(Number(b.dataset.ev));
});
