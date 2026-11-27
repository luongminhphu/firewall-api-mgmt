/* Trang Lịch sử thay đổi SCANPORT GROUP: lọc, thống kê, diff từng lô, đồng bộ phát hiện thay đổi ngoài app, kiểm tra chuỗi băm, xuất CSV. */
import { api, API } from "../api.js";
import { toast } from "../components/toast.js";
import { state } from "../store.js";
import { $, esc, fmtTime, actorLabel, applyFilterParams } from "../util.js";

// ===================================================== LỊCH SỬ THAY ĐỔI
const KIND = {
  change: ["", "Thao tác trong app"],
  drift: ["chip--warn", "Thay đổi ngoài app"],
  baseline: ["", "Bắt đầu theo dõi"],
  create_group: ["chip--info", "Tạo group"],
};
const METHOD = { "entra-oidc": "Entra ID + MFA", "entra-header": "Entra App Proxy", local: "Mật khẩu app", drift: "Phát hiện tự động", system: "Hệ thống" };
const DIFF_PREVIEW = 12;

function changeParams() {
  const p = new URLSearchParams();
  const add = (k, v) => v && p.set(k, v);
  add("firewall_id", $("#c-fw").value);
  add("type", $("#c-type").value);
  add("q", $("#c-q").value.trim());
  add("actor", $("#c-actor").value.trim());
  add("from", $("#c-from").value);
  add("to", $("#c-to").value);
  return p;
}

function fillChangeFilters() {
  const fwSel = $("#c-fw");
  const keepFw = fwSel.value;
  fwSel.innerHTML = `<option value="">Tất cả</option>` +
    state.firewalls.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
  fwSel.value = keepFw;
}

function diffList(b) {
  const lines = [
    ...b.added.map((i) => ({ ...i, s: "+", c: "add" })),
    ...b.removed.map((i) => ({ ...i, s: "−", c: "rm" })),
  ];
  if (!lines.length) return "";
  const row = (l, extra) => `<li class="${l.c}${extra ? " extra hidden" : ""}"><span class="sg">${l.s}</span><span>${esc(l.value || "(không rõ IP)")}</span><span class="ob">${l.object && l.object !== l.value ? esc(l.object) : ""}</span></li>`;
  const head = lines.slice(0, DIFF_PREVIEW).map((l) => row(l, false)).join("");
  const rest = lines.slice(DIFF_PREVIEW);
  return `<ul class="diff">${head}${
    rest.map((l) => row(l, true)).join("")
  }</ul>${rest.length ? `<div class="diff-more"><button type="button" data-more>Xem thêm ${rest.length} dòng</button></div>` : ""}`;
}

function renderChanges(r) {
  const t = r.totals;
  const callout = t.drift
    ? `<div class="alert alert--warn drift-callout" role="status"><span><strong>${t.drift} lần sửa trực tiếp trên firewall (ngoài app)</strong>
        — không qua app, không có người duyệt. Kiểm tra ai đã sửa và vì sao.</span>
        <button class="btn btn--sm" type="button" data-drift>Chỉ xem các lần này</button></div>`
    : "";
  $("#c-stats").innerHTML = callout + `
    <div class="stat"><b>${t.batches}</b><span>lần thay đổi</span></div>
    <div class="stat stat--add"><b>${t.added ? "+" + t.added : 0}</b><span>IP đưa vào group chặn (tính theo từng firewall)</span></div>
    <div class="stat stat--rm"><b>${t.removed ? "−" + t.removed : 0}</b><span>IP gỡ khỏi group (tính theo từng firewall)</span></div>
    <div class="stat${t.drift ? " stat--drift" : ""}"><b>${t.drift}</b><span>lần sửa ngoài app</span></div>`;
  const box = $("#c-list");
  if (!r.batches.length) {
    box.innerHTML = `<p class="empty">Không có thay đổi nào khớp bộ lọc. Lịch sử bắt đầu ghi từ phiên bản 1.2 — thao tác chặn/bỏ chặn đầu tiên sẽ xuất hiện tại đây.</p>`;
    return;
  }
  // Một thao tác (cùng người, lý do, nguồn, cùng danh sách IP, trong 2 phút) trên nhiều firewall → gộp một thẻ
  const groups = [];
  const sig = (b) => [b.kind, b.actor, b.reason, b.source, b.added.map((x) => x.value).sort().join(","),
    b.removed.map((x) => x.value).sort().join(",")].join("|");
  for (const b of r.batches) {
    const g = groups.find((x) => x.sig === sig(b) && b.kind !== "drift"
      && Math.abs(new Date(x.items[0].ts) - new Date(b.ts)) < 120000);
    if (g) g.items.push(b);
    else groups.push({ sig: sig(b), items: [b] });
  }
  box.innerHTML = groups.map(({ items }) => {
    const b = items[0];
    const [cls, label] = KIND[b.kind] || KIND.change;
    const delta = b.kind === "baseline"
      ? `<span class="cb__count">${b.count_after} object</span>`
      : `${b.added.length ? `<span class="d-add">+${b.added.length}</span>` : ""}${
          b.removed.length ? `<span class="d-rm">−${b.removed.length}</span>` : ""
        }<span class="cb__count">${b.count_before} → ${b.count_after} object</span>`;
    return `<article class="cb cb--${b.kind}">
      <div class="cb__head">
        <span class="cb__time">${esc(fmtTime(b.ts))}</span>
        <span class="cb__who">${esc(actorLabel(b.actor_name || b.actor))}${
          b.actor && b.actor !== b.actor_name && actorLabel(b.actor) === b.actor ? `<small>${esc(b.actor)}</small>` : ""
        }</span>
        <span class="chip ${cls}">${label}</span>
        <span class="cb__target">${items.map((x) => esc(x.firewall_name)).join(", ")} › ${esc(b.group_name)}</span>
        <span class="cb__delta">${delta}</span>
      </div>
      <div class="cb__meta">
        ${b.reason ? `<span>Lý do: <strong>${esc(b.reason)}</strong></span>` : ""}
        ${b.source ? `<span>Nguồn: ${esc(actorLabel(b.source))}</span>` : ""}
        ${b.auth_method ? `<span>Xác thực: ${esc(METHOD[b.auth_method] || b.auth_method)}</span>` : ""}
        ${b.client_ip ? `<span>IP client: <span class="mono">${esc(b.client_ip)}</span></span>` : ""}
        <span class="mono" title="Mã lô thao tác">${items.map((x) => `#${esc(x.batch_id)}`).join(" ")}</span>
      </div>
      ${items.length > 1 ? `<p class="cb__fws tiny muted">${items.map((x) => `${esc(x.firewall_name)}: ${x.count_before} → ${x.count_after} object`).join(" · ")}</p>` : ""}
      ${diffList(b)}
    </article>`;
  }).join("");
}

const LINK = { fw: "#c-fw", type: "#c-type", q: "#c-q", actor: "#c-actor", from: "#c-from", to: "#c-to" };

export async function loadChanges(params) {
  fillChangeFilters(); // option #c-fw phải có trước khi áp tham số deep link
  applyFilterParams(params, LINK, Object.values(LINK));
  const box = $("#c-list");
  box.innerHTML = `<div class="skeleton"></div><div class="skeleton"></div>`;
  const p = changeParams();
  $("#c-export").href = `${API}/api/changes.csv?token=${encodeURIComponent(state.token)}&${p}`;
  try {
    const r = await api(`/api/changes?${p}`);
    renderChanges(r);
  } catch (ex) {
    box.innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
  }
}

let changeTimer;
["#c-fw", "#c-type", "#c-from", "#c-to"].forEach((id) =>
  $(id).addEventListener("change", loadChanges)
);
["#c-q", "#c-actor"].forEach((id) =>
  $(id).addEventListener("input", () => {
    clearTimeout(changeTimer);
    changeTimer = setTimeout(loadChanges, 350);
  })
);
$("#c-list").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-more]");
  if (!btn) return;
  btn.closest(".cb").querySelectorAll(".extra").forEach((li) => li.classList.remove("hidden"));
  btn.parentElement.remove();
});

$("#c-sync").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "Đang đọc firewall…";
  try {
    const body = $("#c-fw").value ? { firewall_ids: [Number($("#c-fw").value)] } : {};
    const r = await api("/api/changes/sync", { method: "POST", body });
    const drift = r.results.filter((x) => x.ok && (x.added?.length || x.removed?.length));
    const errs = r.results.filter((x) => !x.ok);
    if (errs.length) toast(`Không đọc được: ${errs.map((x) => x.firewall).join(", ")}`, "err");
    else if (drift.length)
      toast(`Phát hiện thay đổi ngoài app trên ${drift.map((x) => `${x.firewall}/${x.group}`).join(", ")}`, "err");
    else toast(`Đã đối chiếu ${r.results.length} group — không có thay đổi ngoài app`, "ok");
    await loadChanges();
  } catch (ex) {
    toast(ex.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

$("#c-verify").addEventListener("click", async () => {
  const el = $("#c-verify-msg");
  try {
    const r = await api("/api/changes/verify");
    el.textContent = r.message;
    el.className = `alert ${r.ok ? "alert--ok" : "alert--error"}`;
  } catch (ex) {
    el.textContent = ex.message;
    el.className = "alert alert--error";
  }
});

$("#c-stats").addEventListener("click", (e) => {
  if (!e.target.closest("[data-drift]")) return;
  $("#c-type").value = "drift";
  $("#c-type").dispatchEvent(new window.Event("change", { bubbles: true }));
});
