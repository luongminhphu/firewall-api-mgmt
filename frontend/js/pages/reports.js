/* Tab Báo cáo — thống kê IP bị chặn theo phương thức (thủ công / tự động) và thời gian thực hiện.
   - Kỳ: 7 / 14 / 30 ngày gần nhất hoặc chọn từ ngày – đến ngày trên lịch (tối đa 366 ngày).
   - Executive Summary (câu tổng quan, thẻ chỉ số, nhận định, cần lưu ý) → chi tiết: biểu đồ theo ngày,
     người thực hiện, danh sách IP.
   - Tải PDF / Excel (theo HSC Design System, có logo); Write trở lên gửi email qua SMTP đã cấu hình. */
import { API, api, errorBox } from "../api.js";
import { pageSlice, renderPager } from "../components/pagination.js";
import { setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { can, state } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

const rp = { days: 7, from: "", to: "", data: null, ips: [], page: 1 };
const today = () => new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
const shiftDay = (iso, n) => {
  const d = new Date(`${iso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
};

function query() {
  return rp.days === "custom" ? `from=${encodeURIComponent(rp.from)}&to=${encodeURIComponent(rp.to)}` : `days=${rp.days}`;
}

function setLinks() {
  const q = `${query()}&token=${encodeURIComponent(state.token)}`;
  $("#rp-pdf").href = `${API}/api/reports/blocks.pdf?${q}`;
  $("#rp-xlsx").href = `${API}/api/reports/blocks.xlsx?${q}`;
}

export async function loadReports() {
  $("#rp-mail").hidden = !can("operator");
  if (!$("#rp-from").value) {
    $("#rp-to").value = today();
    $("#rp-from").value = shiftDay(today(), -6);
    $("#rp-from").max = $("#rp-to").max = today();
  }
  await load();
}

async function load() {
  setLinks();
  $("#rp-headline").innerHTML = `<span class="skeleton"></span>`;
  try {
    const d = (rp.data = await api(`/api/reports/summary?${query()}`));
    render(d);
  } catch (ex) {
    $("#rp-headline").innerHTML = errorBox(ex);
  }
}

function render(d) {
  const s = d.summary, ab = d.autoblock, ex = d.executive;
  $("#rp-label").textContent = `Kỳ: ${fmtTime(d.start)} → ${fmtTime(d.end)} · ${d.label}`;
  $("#rp-headline").textContent = ex.headline;
  const cards = [
    [s.unique_ips, "IP bị chặn (duy nhất)", ""],
    [s.manual_ips, "Chặn thủ công (con người)", ""],
    [s.auto_ips, "Tự động chặn (lệnh SOC)", s.auto_ips ? "ok" : ""],
    [`${s.auto_share}%`, "Tỷ lệ tự động", ""],
    [s.actions, "Lượt chặn (IP × firewall)", ""],
    [ab.latency_avg_text, "SOC gửi → chặn xong (TB)", ""],
  ];
  $("#rp-cards").innerHTML = cards.map(([v, l, t]) =>
    `<div class="status-card ab-card${t ? " status-card--" + t : ""}"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join("");
  $("#rp-highlights").innerHTML = (ex.highlights.length ? ex.highlights : ["Không có dữ liệu trong kỳ."])
    .map((x) => `<li>${esc(x)}</li>`).join("");
  $("#rp-attention").innerHTML = ex.attention.map((x) => `<li>${esc(x)}</li>`).join("");
  renderChart(d.daily);
  const tb = $("#rp-actors tbody");
  if (!d.actors.length) tableMessage(tb, 4, "empty", "Không có thao tác chặn trong kỳ.");
  else {
    tb.innerHTML = d.actors.map((a) => `<tr><td>${esc(a.actor)}</td>
      <td><span class="chip ${a.method_label === "Tự động" ? "chip--warn" : "chip--info"}">${esc(a.method_label)}</span></td>
      <td class="num">${a.ips}</td><td class="num">${a.actions}</td></tr>`).join("");
  }
  $("#rp-ips-note").textContent = d.ips_total > d.ips.length
    ? `${d.ips_total} IP — hiển thị ${d.ips.length} IP gần nhất; đầy đủ trong file Excel.`
    : `${d.ips_total} IP · mỗi IP một dòng (gộp các firewall).`;
  rp.page = 1;
  filterIps();
}

function renderChart(daily) {
  const max = Math.max(1, ...daily.map((x) => x.total));
  const every = Math.max(1, Math.ceil(daily.length / 15)); // kỳ dài: nhãn ngày thưa ra
  $("#rp-chart").style.setProperty("--n", daily.length);
  $("#rp-chart").innerHTML = daily.map((x, i) => {
    const [y, m, dd] = x.date.split("-");
    const tip = `${dd}/${m}/${y}: ${x.total} IP (thủ công ${x.manual}, tự động ${x.auto})`;
    const pct = (x.total / max) * 88; // chừa chỗ cho nhãn số trên cột cao nhất
    return `<div class="rp-bar" title="${tip}" style="--h:${pct}%">
      <div class="rp-bar__stack" style="height:${pct}%">
        <span class="rp-bar__auto" style="flex:${x.auto}"></span><span class="rp-bar__manual" style="flex:${x.manual}"></span>
      </div>
      <span class="rp-bar__v">${x.total || ""}</span>
      <span class="rp-bar__d">${i % every === 0 ? `${dd}/${m}` : ""}</span>
      <span class="sr-only">${tip}</span></div>`;
  }).join("");
}

function filterIps() {
  const q = $("#rp-q").value.trim().toLowerCase();
  const all = rp.data?.ips || [];
  rp.ips = q ? all.filter((i) => [i.ip, i.reason, ...i.actors, ...i.firewalls, ...i.sources].join(" ").toLowerCase().includes(q)) : all;
  renderIps();
}

function renderIps() {
  const tb = $("#rp-ips tbody");
  if (!rp.ips.length) {
    tableMessage(tb, 7, "empty", rp.data?.ips.length ? "Không có IP khớp bộ lọc." : "Không có IP nào bị chặn trong kỳ.");
    renderPager($("#rp-pager"), { page: 1, pages: 1, total: 0 }, () => {});
    return;
  }
  const pg = pageSlice(rp.ips, rp.page);
  tb.innerHTML = pg.rows.map((i) => `<tr>
    <td class="mono">${esc(i.ip)}</td><td class="mono">${esc(fmtTime(i.first))}</td>
    <td><span class="chip ${i.method === "auto" ? "chip--warn" : "chip--info"}">${esc(i.method_label)}</span></td>
    <td>${esc(i.actors.join(", "))}<div class="muted tiny">${esc(i.sources.join(", "))}</div></td>
    <td>${esc(i.firewalls.join(", "))}</td>
    <td><span class="chip ${i.status === "Đang chặn" ? "chip--ok" : ""}">${esc(i.status)}</span></td>
    <td class="tiny">${esc(i.reason)}</td></tr>`).join("");
  renderPager($("#rp-pager"), { page: pg.page, pages: pg.pages, total: rp.ips.length }, (p) => {
    rp.page = p;
    renderIps();
  });
}

// ------------------------------------------------------------------ sự kiện
$("#rp-seg").addEventListener("click", (e) => {
  const b = e.target.closest("[data-days]");
  if (!b) return;
  $$("#rp-seg .seg-btn").forEach((x) => x.classList.toggle("is-active", x === b));
  const custom = b.dataset.days === "custom";
  $("#rp-dates").hidden = !custom;
  if (custom) return $("#rp-from").focus();
  rp.days = Number(b.dataset.days);
  load();
});
$("#rp-apply").addEventListener("click", () => {
  const f = $("#rp-from").value, t = $("#rp-to").value;
  if (!f || !t) return toast("Chọn đủ từ ngày và đến ngày", "err");
  if (t < f) return toast("Đến ngày phải sau hoặc bằng từ ngày", "err");
  Object.assign(rp, { days: "custom", from: f, to: t });
  load();
});
$("#rp-q").addEventListener("input", () => {
  rp.page = 1;
  filterIps();
});

$("#rp-mail").addEventListener("submit", async (e) => {
  e.preventDefault();
  const formats = [["pdf", "#rp-f-pdf"], ["xlsx", "#rp-f-xlsx"]].filter(([, id]) => $(id).checked).map(([k]) => k);
  const msg = $("#rp-mail-msg");
  const b = $("#rp-send");
  setBusy(b, true, "Đang gửi…");
  try {
    const body = { to: $("#rp-to-addr").value, formats, note: $("#rp-note").value };
    if (rp.days === "custom") Object.assign(body, { date_from: rp.from, date_to: rp.to });
    else body.days = rp.days;
    const r = await api("/api/reports/email", { method: "POST", body });
    msg.textContent = `Đã gửi “${r.subject}” tới ${r.to.join(", ")} (${r.files.join(", ")}).`;
    msg.className = "alert alert--ok";
  } catch (ex) {
    msg.textContent = ex.message;
    msg.className = "alert alert--error";
  } finally {
    setBusy(b, false);
  }
});
