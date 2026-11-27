/* Trang Tổng quan: gom tình trạng xuyên module từ các API sẵn có (không API mới), mỗi mục bấm để mở tab xử lý. */
import { api } from "../api.js";
import { go } from "../router.js";
import { can, state } from "../store.js";
import { $, esc } from "../util.js";

const vnDay = (d = new Date()) => d.toLocaleDateString("en-CA", { timeZone: "Asia/Ho_Chi_Minh" }); // YYYY-MM-DD
const DAY_MS = 86400000;
const EMAIL_KIND = { vpn: "VPN", review: "Rà soát", autoblock: "Tự động chặn", report: "Báo cáo" }; // theo tiền tố kind
const kindLabel = (k) => EMAIL_KIND[String(k).split("_")[0]] || k;
let loading = false;

const fail = (r) => ({ error: r.reason?.message || "lỗi không xác định" });
const num = (n) => Number(n || 0).toLocaleString("vi-VN");

/** Mỗi nguồn → {card:{tab,title,level,big,sub}, issues:[{level,tab,text}]}; level: err (nghiêm trọng) | warn | ok. */
function firewallPart(gc) {
  const fws = (gc.firewalls || []).filter((f) => f.enabled);
  const issues = [];
  let ok = 0;
  for (const f of fws) {
    const name = esc(f.firewall);
    if (f.status === "error") issues.push({ level: "err", tab: "groups", text: `Firewall ${name}: cache group lỗi — ${esc(f.error || "không rõ")}` });
    else if (f.cached && f.exists === false) issues.push({ level: "err", tab: "groups", text: `Firewall ${name}: group ${esc(gc.group)} không tồn tại` });
    else if (f.stale) issues.push({ level: "warn", tab: "groups", text: `Firewall ${name}: dữ liệu group đã cũ${f.scanned_at ? "" : " (chưa quét)"}` });
    else ok++;
  }
  if (!fws.length) issues.push({ level: "warn", tab: "firewalls", text: "Chưa có firewall nào đang bật — chưa chặn được IP" });
  const bad = fws.filter((f) => f.status === "error" || (f.cached && f.exists === false)).length;
  const lastBad = state.firewalls.filter((f) => f.enabled && ["error", "auth_error"].includes(f.last_status)).length;
  const level = bad ? "err" : issues.length ? "warn" : "ok";
  const total = fws.reduce((s, f) => s + (f.total || 0), 0);
  return {
    issues,
    cards: [
      { tab: "firewalls", title: "Firewall", level, big: `${ok}/${fws.length}`, sub: `đang bật, dữ liệu group bình thường${lastBad ? ` · ${lastBad} lần kiểm tra kết nối gần nhất lỗi` : ""}` },
      { tab: "groups", title: "IP Host Group", level: "ok", big: num(total), sub: `IP trong ${esc(gc.group)} (tổng các firewall)` },
    ],
  };
}

function autoblockPart(s) {
  const issues = [];
  if (s.breaker_tripped_at) issues.push({ level: "err", tab: "autoblock", text: `Cầu dao tự động chặn đã ngắt — ${esc(s.breaker_reason || "không rõ lý do")}` });
  if (s.enabled && s.last_ok === false) issues.push({ level: "err", tab: "autoblock", text: `Tự động chặn không đọc được Teams — ${esc(s.last_error || "không rõ")}` });
  if (s.enabled && !s.auto_enabled) issues.push({ level: "warn", tab: "autoblock", text: "Công tắc khẩn cấp đang TẮT — mọi lệnh SOC chuyển sang chờ duyệt" });
  const lastPoll = s.last_poll_at ? Date.parse(s.last_poll_at) : null; // bộ đọc Teams đứng (quá 3 chu kỳ không đọc)
  if (s.enabled && lastPoll && Date.now() - lastPoll > 3 * Math.max(s.poll_seconds || 300, 60) * 1000) {
    issues.push({ level: "warn", tab: "autoblock", text: "Đã lâu không đọc được tin Teams — kiểm tra tiến trình nền" });
  }
  if (s.pending) issues.push({ level: "warn", tab: "autoblock", text: `${num(s.pending)} lệnh SOC đang chờ duyệt` });
  const level = issues.some((i) => i.level === "err") ? "err" : issues.length ? "warn" : "ok";
  const mode = !s.enabled ? "Chưa bật đọc Teams" : s.breaker_tripped_at ? "Đã ngắt do vượt ngưỡng"
    : !s.auto_enabled ? "Công tắc khẩn cấp đang TẮT" : s.in_window ? "Đang trong lịch tự chặn" : "Ngoài lịch tự chặn";
  return {
    issues,
    cards: [{ tab: "autoblock", title: "Tự động chặn", level, big: num(s.pending), sub: `lệnh chờ duyệt · ${esc(mode)} · ${num(s.auto_last_hour)}/${num(s.hourly_limit)} IP giờ qua` }],
  };
}

function vpnPart(v) {
  const sm = v.summary || {};
  const issues = [];
  if (sm.expired_enabled) issues.push({ level: "err", tab: "vpn", text: `${num(sm.expired_enabled)} rule VPN đã hết hạn nhưng vẫn bật` });
  for (const s of v.syncs || []) if (s.status === "error") issues.push({ level: "warn", tab: "vpn", text: `Đồng bộ VPN từ ${esc(s.firewall)} lỗi — ${esc(s.error || "không rõ")}` });
  if (sm.expiring) issues.push({ level: "warn", tab: "vpn", text: `${num(sm.expiring)} rule VPN sắp hết hạn` });
  const level = sm.expired_enabled ? "err" : issues.length ? "warn" : "ok";
  return {
    issues,
    cards: [{ tab: "vpn", title: "VPN (chỉ đọc)", level, big: num(sm.expired_enabled), sub: `hết hạn còn bật · ${num(sm.expiring)} sắp hết hạn · ${num(v.total)} rule` }],
  };
}

function reviewPart(list, today) {
  const open = (list || []).filter((c) => c.status === "open");
  const issues = [];
  let pending = 0;
  for (const c of open) {
    pending += c.totals?.pending || 0;
    if (c.due_date < today) issues.push({ level: "err", tab: "review", text: `Đợt rà soát "${esc(c.name)}" quá hạn ${esc(c.due_date)} — còn ${num(c.totals?.pending)} mục chưa phản hồi` });
  }
  const level = issues.length ? "err" : "ok";
  return {
    issues,
    cards: [{ tab: "review", title: "Rà soát", level, big: num(open.length), sub: open.length ? `đợt đang mở · ${num(pending)} mục chờ phản hồi${issues.length ? ` · ${issues.length} quá hạn` : ""}` : "không có đợt đang mở" }],
  };
}

function driftPart(c) {
  const n = c.totals?.drift || 0;
  return {
    issues: n ? [{ level: "warn", tab: "changes", text: `${num(n)} lần group bị sửa ngoài app (drift) trong 7 ngày` }] : [],
    cards: [{ tab: "changes", title: "Sửa ngoài app", level: n ? "warn" : "ok", big: num(n), sub: "lần drift trong 7 ngày" }],
  };
}

function emailPart(o) {
  const since = Date.now() - 7 * DAY_MS;
  const mails = (o.emails || []).filter((m) => m.created_at && Date.parse(m.created_at) >= since);
  const kinds = {};
  mails.forEach((m) => (kinds[m.kind] = (kinds[m.kind] || 0) + 1)); // chỉ đếm theo loại, không hiện người nhận / tiêu đề
  const detail = Object.entries(kinds).map(([k, n]) => `${esc(kindLabel(k))}: ${n}`).join(", ");
  return {
    issues: mails.length ? [{ level: "warn", tab: "settings", text: `${num(mails.length)} email gửi lỗi trong 7 ngày (${detail})` }] : [],
    cards: [{ tab: "settings", title: "Email", level: mails.length ? "warn" : "ok", big: num(mails.length), sub: mails.length ? `thư lỗi trong 7 ngày · ${detail}` : "không có thư lỗi trong 7 ngày" }],
  };
}

function reportPart(r) {
  const s = r.summary || {};
  const lat = r.autoblock?.latency_avg == null ? "" : r.autoblock.latency_avg_text;
  return {
    issues: [],
    cards: [{ tab: "reports", title: "7 ngày qua", level: "ok", big: num(s.unique_ips), sub: `IP đã chặn · ${num(s.still_blocked)} còn bị chặn · tự động ${num(s.auto_share)}%${lat ? ` · phản hồi TB ${esc(lat)}` : ""}` }],
  };
}

const errCard = (title, tab, msg) => ({ tab, title, level: "unk", big: "—", sub: `Không đọc được: ${esc(msg)}` });
const LEVEL_LABEL = { err: "Nghiêm trọng", warn: "Cảnh báo", ok: "Ổn", unk: "Lỗi tải" };
const cardHtml = (c) => `<button type="button" class="status-card ov-card ov-card--${c.level}" data-go="${esc(c.tab)}">
  <span class="ov-card__title">${esc(c.title)} <em class="ov-tag">${LEVEL_LABEL[c.level]}</em></span><b>${esc(c.big)}</b><span>${c.sub}</span></button>`;
const issueHtml = (i) => `<li><button type="button" class="ov-issue ov-issue--${i.level}" data-go="${esc(i.tab)}"><em class="ov-tag">${LEVEL_LABEL[i.level]}</em><span>${i.text}</span></button></li>`;

export async function loadOverview() {
  if (loading) return;
  loading = true;
  const root = $("#ov-body");
  if (!root.dataset.loaded) root.innerHTML = '<p class="muted ov-loading">Đang tải…</p>';
  $("#ov-refresh").disabled = true;
  try {
    const today = vnDay();
    const from = vnDay(new Date(Date.now() - 6 * DAY_MS));
    const admin = can("admin");
    const jobs = [
      api("/api/group-cache"), api("/api/autoblock/status"), api("/api/vpn/rules"), api("/api/review/campaigns"),
      api(`/api/changes?type=drift&from=${from}&limit=500`), api("/api/reports/summary?days=7"),
      admin ? api("/api/notify/outbox?status=failed&limit=1000") : Promise.resolve(null),
    ];
    const [gc, ab, vpn, rv, ch, rep, mail] = await Promise.allSettled(jobs);
    const parts = [
      [gc, "Firewall", "firewalls", (v) => firewallPart(v)],
      [ab, "Tự động chặn", "autoblock", autoblockPart],
      [vpn, "VPN (chỉ đọc)", "vpn", vpnPart],
      [rv, "Rà soát", "review", (v) => reviewPart(v.campaigns || v, vpn.value?.today || today)],
      [ch, "Sửa ngoài app", "changes", driftPart],
      [rep, "7 ngày qua", "reports", reportPart],
    ];
    if (admin) parts.push([mail, "Email", "settings", emailPart]);
    const issues = [], cards = [];
    for (const [r, title, tab, fn] of parts) {
      if (r.status === "rejected") { cards.push(errCard(title, tab, fail(r).error)); continue; }
      try { // response 200 không phải JSON (vd trang đăng nhập của proxy) → api() trả null: chỉ thẻ này lỗi
        if (!r.value) throw new Error("máy chủ trả dữ liệu không hợp lệ");
        const p = fn(r.value);
        issues.push(...p.issues);
        cards.push(...p.cards);
      } catch (e) {
        cards.push(errCard(title, tab, e.message));
      }
    }
    const order = { err: 0, warn: 1 };
    issues.sort((a, b) => order[a.level] - order[b.level]);
    root.dataset.loaded = "1";
    root.innerHTML = `<section class="card ov-todo" aria-labelledby="ov-todo-h">
        <h2 id="ov-todo-h">Cần xử lý</h2>
        ${issues.length ? `<ul class="ov-issues">${issues.map(issueHtml).join("")}</ul>`
          : '<p class="alert alert--ok">Không có việc cần xử lý.</p>'}
      </section>
      <div class="ov-grid">${cards.map(cardHtml).join("")}</div>`;
    $("#ov-updated").textContent = `Cập nhật lúc ${new Date().toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "Asia/Ho_Chi_Minh" })}`;
  } finally {
    loading = false;
    $("#ov-refresh").disabled = false;
  }
}

$("#ov-refresh").addEventListener("click", loadOverview);
$("#ov-body").addEventListener("click", (e) => {
  const b = e.target.closest("[data-go]");
  if (!b) return;
  go(b.dataset.go);
  $(".tab.is-active")?.focus(); // panel Tổng quan bị ẩn → giữ focus bàn phím ở mục menu vừa mở
});
