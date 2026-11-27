/* Trang IP Host Group: tổng quan cache theo firewall, danh sách thành viên SCANPORT GROUP (cache + quét lại), bỏ chặn. */
import { confirmAction } from "../components/modal.js";
import { api, errorBox, runJob } from "../api.js";
import { resultChip } from "../components/badge.js";
import { progressBox, setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { can, on, state } from "../store.js";
import { $, $$, esc, applyFilterParams } from "../util.js";

// ----------------------------------------------------------- object group
on("firewalls", () => renderFwSelect());

export function renderFwSelect() {
  const sel = $("#g-fw");
  const prev = sel.value;
  sel.innerHTML = state.firewalls
    .map((f) => `<option value="${f.id}">${esc(f.name)}</option>`)
    .join("");
  if (prev) sel.value = prev;
}

$("#g-fw").addEventListener("change", loadGroupsForSelectedFw);
$("#g-reload").addEventListener("click", () => loadMembers({ refresh: true }));
$("#g-ov-reload").addEventListener("click", loadOverview);
$("#g-overview").addEventListener("click", (e) => {
  const it = e.target.closest("[data-fw]");
  if (!it) return;
  $("#g-fw").value = it.dataset.fw;
  loadGroupsForSelectedFw();
});

// ------------------------------------------------------------ group cache
const pad = (n) => String(n).padStart(2, "0");
const fmtScan = (iso) => {
  if (!iso) return "chưa quét";
  const d = new Date(new Date(iso).toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}/${pad(
    d.getMonth() + 1
  )}/${d.getFullYear()}`;
};
const fmtAge = (s) => {
  if (s == null) return "";
  if (s < 60) return `${s} giây trước`;
  if (s < 3600) return `${Math.floor(s / 60)} phút trước`;
  if (s < 86400) return `${Math.floor(s / 3600)} giờ trước`;
  return `${Math.floor(s / 86400)} ngày trước`;
};
function cacheTag(c) {
  if (c.refreshing || c.dirty) return `<span class="chip chip--info"><span class="spinner spinner--xs" aria-hidden="true"></span>Đang quét lại</span>`;
  if (c.status === "error") return `<span class="chip chip--err" title="${esc(c.error)}">Lỗi lần quét cuối</span>`;
  if (!c.cached) return `<span class="chip">Chưa có cache</span>`;
  if (c.details_mode === "partial")
    return `<span class="chip chip--warn" title="${esc(c.note || "")}">Chi tiết chưa đầy đủ</span>`;
  if (c.stale) return `<span class="chip chip--warn">Đến hạn quét lại</span>`;
  return `<span class="chip chip--ok">Mới</span>`;
}
const fmtTtl = (m) => (m >= 60 && m % 60 === 0 ? `${m / 60} giờ` : `${m} phút`);

async function loadOverview() {
  const box = $("#g-overview");
  if (!box.children.length) box.innerHTML = `<div class="skeleton"></div>`;
  try {
    const r = await api("/api/group-cache");
    $("#g-ov-note").textContent =
      `Danh sách ${r.group} được lưu cache để hiển thị tức thì: cập nhật ngay sau mỗi lần chặn/bỏ chặn, ` +
      `quét đầy đủ định kỳ mỗi ${fmtTtl(r.ttl_minutes)}${r.daily_at ? ` và lúc ${r.daily_at} hằng ngày` : ""}.`;
    const cur = $("#g-fw").value;
    box.innerHTML = r.firewalls.length
      ? r.firewalls
          .map(
            (f) => `<button type="button" class="fw-cache${String(f.firewall_id) === cur ? " is-current" : ""}" data-fw="${f.firewall_id}">
              <span class="fw-cache__name">${esc(f.firewall)}</span>
              <span class="fw-cache__count mono">${f.total ?? "—"}<small> IP</small></span>
              <span class="fw-cache__time tiny muted" title="Thời điểm quét gần nhất">${f.cached ? fmtScan(f.scanned_at) : "Chưa quét"}</span>
              ${cacheTag(f)}
            </button>`
          )
          .join("")
      : `<p class="empty">Chưa có firewall nào.</p>`;
    return r;
  } catch (ex) {
    box.innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
  }
}

// Sau khi chặn/bỏ chặn: backend đánh dấu dirty + quét nền. Hỏi trạng thái mỗi giây đến khi xong.
const watching = new Set();
on("cache-refresh", (ids) => watchCache(ids));

function watchCache(ids) {
  ids.forEach((id) => {
    if (watching.has(id)) return;
    watching.add(id);
    let tries = 0;
    const tick = async () => {
      tries += 1;
      let c = null;
      try {
        c = await api(`/api/firewalls/${id}/group-cache`);
      } catch {}
      const busy = c && (c.dirty || c.refreshing);
      if (busy && tries < 60) {
        if (String(id) === $("#g-fw").value) renderCacheMeta(null, c);
        setTimeout(tick, 1000);
        return;
      }
      watching.delete(id);
      if ($('[data-panel="groups"]').classList.contains("is-active")) {
        loadOverview();
        if (String(id) === $("#g-fw").value) loadMembers({ quiet: true });
      }
    };
    setTimeout(tick, 800);
  });
  if ($('[data-panel="groups"]').classList.contains("is-active")) loadOverview();
}

function renderCacheMeta(r, c) {
  const el = $("#g-cache");
  if (!el) return;
  const src = r?.source === "live" ? "Vừa quét trực tiếp từ firewall" : "Từ cache";
  const busy = c.dirty || c.refreshing;
  const full = c.full_scanned_at
    ? ` · quét đầy đủ lúc <strong class="mono">${fmtScan(c.full_scanned_at)}</strong>, kế tiếp ~<span class="mono">${fmtScan(c.next_full_scan_at)}</span>`
    : "";
  el.innerHTML = `${cacheTag(c)}
    <span class="muted">${r ? src + " · " : ""}cập nhật lúc <strong class="mono">${fmtScan(c.scanned_at)}</strong>${
    c.age_s != null ? ` (${fmtAge(c.age_s)})` : ""
  }${c.scan_ms != null ? ` · quét mất ${c.scan_ms < 1000 ? c.scan_ms + " ms" : (c.scan_ms / 1000).toFixed(1) + " giây"}` : ""}${full}</span>
    ${c.status === "error" && c.error ? `<span class="chip chip--err">${esc(c.error)}</span>` : ""}
    ${c.details_mode === "partial" && c.note ? `<span class="cache-note tiny">${esc(c.note)}</span>` : ""}`;
  el.classList.toggle("is-busy", busy);
}
$("#g-search").addEventListener("input", () => renderMembers(filterMembers()));

export async function loadGroupsForSelectedFw(params) {
  applyFilterParams(params, { fw: "#g-fw", q: "#g-search" }, ["#g-search"]); // #g-fw không có option rỗng: link thiếu/sai fw giữ giá trị hiện tại
  if (params instanceof URLSearchParams && params.has("fw") && params.get("fw") !== $("#g-fw").value) {
    toast("Không tìm thấy firewall trong link — đang hiện firewall đã chọn trước đó", "err"); // tránh thao tác nhầm firewall
  }
  const id = $("#g-fw").value;
  if (!id) return;
  $("#g-meta").innerHTML = `<span class="skeleton" style="width:220px"></span>`;
  try {
    const r = await api(`/api/firewalls/${id}/groups`);
    if (r.pending) {
      await loadMembers();
      loadOverview();
      return;
    }
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
  loadOverview();
}

async function loadMembers({ refresh = false, quiet = false } = {}) {
  const id = $("#g-fw").value;
  const group = state.blockGroup;
  if (!id) return;
  const btn = $("#g-reload");
  if (!quiet)
    tableMessage($("#g-table tbody"), 5, "loading");
  if (refresh) {
    btn.disabled = true;
    $("#g-cache") && ($("#g-cache").innerHTML = `<span class="chip chip--info"><span class="spinner spinner--xs" aria-hidden="true"></span>Đang quét lại từ firewall…</span>`);
  }
  try {
    const r = await api(
      `/api/firewalls/${id}/group-members?group=${encodeURIComponent(group)}${refresh ? "&refresh=1" : ""}`
    );
    state.groupMembers = r.members;
    if (r.pending) {
      $("#g-meta").innerHTML = `<span class="cache-meta" id="g-cache"></span>`;
      $("#g-cache").innerHTML = `<span class="chip chip--info"><span class="spinner spinner--xs" aria-hidden="true"></span>Đang quét lần đầu</span>
        <span class="muted">Firewall phản hồi chậm — danh sách sẽ tự hiện khi quét xong.</span>`;
      tableMessage($("#g-table tbody"), 5, "loading");
      watchCache([Number(id)]);
      btn.disabled = false;
      return;
    }
    if (refresh && r.source === "cache" && r.cache?.refreshing)
      toast("Firewall phản hồi chậm — đang hiển thị cache, quét tiếp ở chế độ nền", "");
    $("#g-meta").innerHTML = `
      <span>Firewall: <strong>${esc(r.firewall)}</strong></span>
      <span>Group: <strong>${esc(r.group)}</strong></span>
      <span>Thành viên: <strong class="mono">${r.total}</strong></span>
      <span>IP family: ${esc(r.ip_family)}</span>
      ${r.description ? `<span>${esc(r.description)}</span>` : ""}
      <span class="cache-meta" id="g-cache"></span>`;
    if (r.cache) {
      renderCacheMeta(r, r.cache);
      if (r.cache.dirty || r.cache.refreshing) watchCache([Number(id)]);
    }
    renderMembers(filterMembers());
    if (refresh) loadOverview();
  } catch (ex) {
    $("#g-meta").innerHTML = `<span class="chip chip--err">${esc(ex.message)}</span>`;
    renderMembers([]);
  }
  btn.disabled = false;
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
    tableMessage(tb, 5, "empty", "Không có object nào khớp.");
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
  if (!(await confirmAction({ title: "Gỡ chặn — khôi phục truy cập?", ok: `Gỡ chặn ${targets.length} object trên ${fw.name}`, danger: false, html: `<dl class="confirm-facts"><dt>Firewall</dt><dd>${esc(fw.name)}</dd><dt>IP Host Group</dt><dd class="mono">${esc(group)}</dd></dl><div class="confirm-ips">${targets.map((t) => `<span class="mono">${esc(t)}</span>`).join("")}</div>` }))) return;
  const btn = $("#do-unblock");
  setBusy(btn, true, "Đang gỡ chặn…");
  const out = $("#unblock-result");
  out.innerHTML = progressBox({ total: 1, firewalls: [{ id: fwId, name: fw.name }], results: [] }, false);
  try {
    const r = await runJob(
      "/api/unblock",
      {
        firewall_ids: [fwId],
        targets,
        delete_object: $("#delete-object").checked,
        reason: "Gỡ chặn từ mini app",
      },
      (job) => {
        if (job.status === "running") out.innerHTML = progressBox(job, false);
      }
    );
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
    toast("Đã cập nhật group — đang quét lại để làm mới cache", "ok");
    if (r.cache_refresh?.length) watchCache(r.cache_refresh);
    await loadMembers({ quiet: true });
  } catch (ex) {
    out.innerHTML = errorBox(ex, "Gỡ chặn không thành công");
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Gỡ chặn mục đã chọn");
  refreshUnblockButton();
});
