/* Trang Chặn nhanh: nguồn IP (dán Teams / nhập tay / CSV), danh sách IP, chọn firewall, chặn (công việc nền + tiến độ), kết quả. */
import { api, errorBox, runJob } from "../api.js";
import { resultChip, statusChip } from "../components/badge.js";
import { confirmAction } from "../components/modal.js";
import { progressBox, reduceMotion, setBusy } from "../components/progress.js";
import { toast } from "../components/toast.js";
import { can, emit, on, state } from "../store.js";
import { $, $$, esc, ICON } from "../util.js";
import { loadFirewalls } from "./firewalls.js";

on("firewalls", () => renderFwPicker());

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
          <span class="fw-opt__meta">${esc(f.host)}:${f.port} → ${esc(state.blockGroup)}</span>
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

state.allowWl = new Set(); // IP thuộc whitelist người dùng đã chủ động bấm "Vẫn chặn"
state.rejected = [];
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
    const r = await api("/api/parse", { method: "POST", body: { text, allow_whitelist: [...state.allowWl] } });
    const incoming = r.accepted.map((a) => ({ value: a.value, kind: a.kind, object: a.object, whitelist: a.whitelist }));
    state.candidates = replace
      ? incoming
      : [...state.candidates, ...incoming.filter((i) => !state.candidates.some((c) => c.value === i.value))];
    state.rejected = replace ? r.rejected : [...state.rejected.filter((x) => !r.rejected.some((y) => y.value === x.value)), ...r.rejected];
    renderCandidates(state.rejected);
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
          <span class="chip ${c.kind === "Network" ? "chip--info" : ""}">${c.kind === "Network" ? "CIDR" : "IP"}</span>
          <span class="cand__ip">${esc(c.value)}</span>
          ${c.whitelist ? `<span class="chip chip--warn" title="Đã xác nhận ghi đè whitelist ${esc(c.whitelist)}">Whitelist · ${esc(c.whitelist.split(":")[0])}</span>` : ""}
          ${
            c.object && c.object !== c.value // từ v1.4 tên object = chính IP → chỉ hiện khi khác
              ? `<span class="cand__obj" title="Tên object trên firewall">${esc(c.object)}</span>`
              : ""
          }
          <button class="cand__x" type="button" data-i="${i}" aria-label="Bỏ ${esc(c.value)} khỏi danh sách" title="Bỏ khỏi danh sách">${ICON.x}</button>
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
        .map((r) => `<span class="rej"><code>${esc(r.value)}</code> — ${esc(r.reason)}${
          r.whitelist && can("operator")
            ? ` <button class="btn btn--ghost btn--sm" type="button" data-allow="${esc(r.value)}">Vẫn chặn</button>`
            : ""}</span>`)
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
  const [gone] = state.candidates.splice(Number(btn.dataset.i), 1);
  state.allowWl.delete(gone.value);
  renderCandidates(state.rejected);
});

// IP thuộc whitelist: chỉ vào danh sách chặn khi người dùng chủ động ghi đè (ghi vào lý do để audit)
$("#rejected-box").addEventListener("click", (e) => {
  const b = e.target.closest("[data-allow]");
  if (!b) return;
  const r = state.rejected.find((x) => x.value === b.dataset.allow);
  state.allowWl.add(r.value);
  state.rejected = state.rejected.filter((x) => x !== r);
  state.candidates.push({ value: r.value, kind: r.kind, object: r.value, whitelist: r.whitelist });
  renderCandidates(state.rejected);
});

$("#clear-list").addEventListener("click", () => {
  state.candidates = [];
  state.rejected = [];
  state.allowWl.clear();
  $("#paste-text").value = "";
  $("#csv-info").textContent = "";
  renderCandidates([]);
  $("#block-result").innerHTML = "";
});

function refreshBlockButton() {
  $("#do-block").disabled = !can("operator") || !(state.candidates.length && selectedFwIds().length);
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
  if (!dry && !(await confirmBlock(ids.length, fwNames))) return;

  const btn = $("#do-block");
  const box = $("#block-result");
  setBusy(btn, true, dry ? "Đang chạy thử…" : "Đang đẩy cấu hình…");
  $("#clear-list").disabled = true;
  box.innerHTML = progressBox({ total: ids.length, done: 0, firewalls: ids.map((id, i) => ({ id, name: fwNames[i] })), results: [] }, dry);
  box.scrollIntoView({ block: "nearest", behavior: reduceMotion() ? "auto" : "smooth" }); // điện thoại: kết quả nằm dưới nút
  try {
    const r = await runJob(
      "/api/block",
      {
        firewall_ids: ids,
        values: state.candidates.map((c) => c.value),
        reason: $("#block-reason").value.trim(),
        source: state.source === "paste" ? "teams-paste" : state.source,
        dry_run: dry,
        allow_whitelist: state.candidates.filter((c) => c.whitelist).map((c) => c.value),
      },
      (job) => {
        if (job.status === "running") box.innerHTML = progressBox(job, dry) + renderBlockResult(job);
      }
    );
    box.innerHTML = blockSummary(r, dry) + renderBlockResult(r);
    if (r.cache_refresh?.length) emit("cache-refresh", r.cache_refresh); // trang IP Host Group theo dõi quét lại
    const okCount = r.results.filter((x) => x.ok).length;
    toast(
      dry
        ? "Chạy thử xong — chưa ghi gì lên firewall"
        : `Hoàn tất trên ${okCount}/${r.results.length} firewall`,
      okCount === r.results.length ? "ok" : "err"
    );
  } catch (ex) {
    box.innerHTML = errorBox(ex, dry ? "Chạy thử không thành công" : "Chặn IP không thành công");
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Chặn ngay");
  $("#clear-list").disabled = false;
  refreshBlockButton();
  loadFirewalls();
});

/** Màn xác nhận trước khi ghi lên firewall thật: liệt kê đúng những gì sẽ đẩy đi. */
function confirmBlock(nFw, fwNames) {
  const c = state.candidates;
  const addrs = c.reduce((n, x) => n + (x.kind === "Network" ? 2 ** (32 - Number(x.value.split("/")[1])) : 1), 0);
  const wl = c.filter((x) => x.whitelist);
  const reason = $("#block-reason").value.trim();
  return confirmAction({
    title: "Chặn trên firewall đang chạy",
    ok: `Chặn ${c.length} IP trên ${nFw} firewall`,
    html: `<dl class="confirm-facts">
        <dt>Firewall</dt><dd>${fwNames.map(esc).join(", ")}</dd>
        <dt>IP Host Group</dt><dd class="mono">${esc(state.blockGroup)}</dd>
        <dt>Số địa chỉ</dt><dd>${c.length} mục${addrs > c.length ? ` · ${addrs.toLocaleString("vi-VN")} địa chỉ (có dải CIDR)` : ""}</dd>
        <dt>Lý do / ticket</dt><dd>${reason ? esc(reason) : '<span class="text-warn">Chưa nhập — audit sẽ không có lý do</span>'}</dd>
      </dl>
      ${wl.length ? `<p class="alert alert--warn">Ghi đè whitelist: ${wl.map((x) => `<strong class="mono">${esc(x.value)}</strong> (${esc(x.whitelist)})`).join(", ")}</p>` : ""}
      <div class="confirm-ips">${c.map((x) => `<span class="mono${x.whitelist ? " is-wl" : ""}">${esc(x.value)}</span>`).join("")}</div>`,
  });
}

/** Tóm tắt cuối cùng ở đầu kết quả: tổng thêm / đã có / lỗi trên mọi firewall. */
function blockSummary(r, dry) {
  const t = { added: 0, existed: 0, error: 0, dry_run: 0 };
  r.results.forEach((x) => Object.keys(t).forEach((k) => (t[k] += x.summary?.[k] || 0)));
  const fwErr = r.results.filter((x) => !x.ok).length;
  const cls = fwErr ? "alert--warn" : "alert--ok";
  const parts = dry
    ? [`${t.dry_run} sẽ tạo`, `${t.existed} đã có`]
    : [`${t.added} đã thêm`, `${t.existed} đã có`, `${t.error} lỗi`];
  return `<div class="alert ${cls} result-summary" role="status">
    <strong>${dry ? "Chạy thử xong" : fwErr ? `Xong, ${fwErr}/${r.results.length} firewall có lỗi` : "Đã chặn xong"}</strong>
    <span>${r.results.length} firewall · ${parts.join(" · ")}</span>
  </div>`;
}

const ROWS_OPEN_MAX = 5; // nhiều dòng hơn thì thu gọn (tổng kết đã nằm ở đầu), luôn mở sẵn khi có lỗi

function renderBlockResult(r) {
  return (r.results || [])
    .map((fw) => {
      const s = fw.summary || {};
      const head = `<div class="result-fw__head">
          <span>${esc(fw.firewall)}</span>
          ${fw.ok ? '<span class="chip chip--ok">OK</span>' : '<span class="chip chip--err">Có lỗi</span>'}
          <span class="muted tiny">thêm ${s.added || 0} · đã có ${s.existed || 0} · lỗi ${s.error || 0}${
            s.dry_run ? ` · chạy thử ${s.dry_run}` : ""
          }</span>
        </div>`;
      if (fw.error) {
        return `<div class="result-fw">${head}<div class="result-row result-row--err">${esc(fw.error)}</div></div>`;
      }
      const rows = (fw.rows || [])
        .map(
          (row) => `<div class="result-row">
            ${resultChip(row.result)}
            <span class="mono">${esc(row.value)}</span>
            ${row.object && row.object !== row.value ? `<span class="muted tiny mono">${esc(row.object)}</span>` : ""}
            <span class="result-row__msg">${esc(row.code ? row.code + " · " : "")}${esc(row.message)}</span>
          </div>`
        )
        .join("");
      const open = (fw.rows || []).length <= ROWS_OPEN_MAX || (s.error || 0) > 0;
      const list = `<details class="result-rows"${open ? " open" : ""}>
          <summary>Chi tiết ${(fw.rows || []).length} IP</summary>${rows}</details>`;
      const xml = fw.group_xml
        ? `<details class="xml-preview"${s.dry_run ? " open" : ""}>
            <summary>Payload IPHostGroup ${s.dry_run ? "dự kiến" : "đã gửi"} ·
              <span class="mono">Set operation="${esc(fw.group_operation)}"</span> · ${esc(fw.ip_family || "IPv4")}</summary>
            <pre class="mono">${esc(fw.group_xml)}</pre>
          </details>`
        : "";
      return `<div class="result-fw">${head}${list}${xml}</div>`;
    })
    .join("");
}
