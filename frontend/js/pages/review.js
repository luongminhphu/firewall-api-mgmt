/* Tab Rà soát — rà soát quyền truy cập VPN định kỳ (ISO 27001 A.5.18).
   - Mọi người (kể cả vai trò reviewer = đại diện team): mục thuộc team mình, quyết định Còn cần / Thu hồi / Cần điều chỉnh
     (Thu hồi / điều chỉnh bắt buộc lý do). Quản trị viên thấy thêm phạm vi Infra và quyết định thay được.
   - viewer trở lên: danh sách đợt, tiến độ theo team, CSV bằng chứng / cần xử lý, kiểm tra chuỗi băm;
     quản trị viên: mở / đóng đợt. */
import { API, api, errorBox } from "../api.js";
import { toast } from "../components/toast.js";
import { can, state } from "../store.js";
import { $, esc, fmtTime } from "../util.js";

const rv = { items: [], camp: null, isAdmin: false, editing: null };
const DEC = {
  keep: ["chip--ok", "Còn cần"], revoke: ["chip--err", "Thu hồi"], change: ["chip--warn", "Cần điều chỉnh"],
  pending: ["", "Chưa quyết định"], no_response: ["chip--err", "Không phản hồi"],
};
const fmtDate = (iso) => (iso ? iso.split("-").reverse().join("/") : "—");
const chips = (xs) => (xs || []).map((x) => `<span class="chip">${esc(x)}</span>`).join(" ");

export async function loadReview() {
  $("#rv-admin").classList.toggle("hidden", !can("viewer"));
  $("#rv-open").classList.toggle("hidden", !can("admin"));
  await Promise.all([loadMine(), can("viewer") ? loadCampaigns() : null]);
}

// ------------------------------------------------------------------ việc của tôi
async function loadMine() {
  const box = $("#rv-list");
  box.innerHTML = `<div class="skeleton"></div>`;
  try {
    const r = await api(`/api/review/my?decision=${$("#rv-show").value}`);
    rv.items = r.items;
    rv.camp = r.campaign;
    rv.isAdmin = r.is_admin;
    await renderMine(r);
  } catch (ex) {
    box.innerHTML = errorBox(ex);
  }
}

async function renderMine(r) {
  const c = r.campaign;
  $("#rv-title").textContent = c ? c.name : "Rà soát quyền truy cập VPN";
  if (!c) {
    $("#rv-progress").innerHTML = "";
    $("#rv-list").innerHTML = `<p class="empty">Hiện không có đợt rà soát nào đang mở.</p>`;
    return;
  }
  const scopes = r.scopes.map((s) => esc(s.name)).join(", ");
  $("#rv-sub").innerHTML = r.scopes.length
    ? `Bạn rà soát: <strong>${scopes}</strong> · hạn <strong>${fmtDate(c.due_date)}</strong>. Xác nhận từng quyền còn cần, cần thu hồi hay cần điều chỉnh.`
    : `Bạn không phải đại diện team nào trong đợt này.`;
  // tiến độ của phạm vi mình (lấy tất cả mục, không theo bộ lọc) — vẽ cùng lúc với danh sách
  await renderProgress();
  if (!r.items.length) {
    $("#rv-list").innerHTML = `<p class="empty">${$("#rv-show").value === "pending" ? "Bạn đã quyết định hết các mục — cảm ơn!" : "Không có mục nào."}</p>`;
    return;
  }
  $("#rv-list").innerHTML = r.items.map(itemCard).join("");
}

async function renderProgress() {
  try {
    const all = $("#rv-show").value ? (await api("/api/review/my")).items : rv.items;
    const done = all.filter((i) => i.decision !== "pending").length;
    $("#rv-progress").innerHTML = all.length ? `
      <div class="progress-box__head"><strong>Đã quyết định ${done}/${all.length}</strong>
        <span class="muted tiny">${all.length - done} mục còn lại</span></div>
      <progress max="${all.length}" value="${done}" aria-label="Tiến độ rà soát"></progress>` : "";
  } catch {}
}

function itemCard(it) {
  const s = it.snapshot;
  const [cls, label] = DEC[it.decision] || ["", it.decision];
  const isRule = it.kind === "rule";
  const detail = isRule
    ? `<dl class="kv kv--compact">
        <dt>Người dùng</dt><dd>${chips(s.accounts?.length ? s.accounts : s.identities) || "—"}</dd>
        <dt>Đích · dịch vụ</dt><dd>${esc([...(s.dst_zones || []), ...(s.dst_networks || [])].join(", ") || "—")} · ${esc((s.services || []).join(", ") || "—")}</dd>
        <dt>Hạn hiện tại</dt><dd>${fmtDate(s.expiry_date)} <span class="muted">(${esc(s.status_label || "")})</span></dd>
      </dl>`
    : `<dl class="kv kv--compact">
        <dt>Tên</dt><dd>${esc(s.display_name || "—")}</dd>
        <dt>Quyền</dt><dd>${s.has_sslvpn ? "SSL VPN " : ""}${s.has_ipsec ? "IPsec" : ""} · nhóm ${chips(s.groups) || "—"}</dd>
        <dt>Ghi chú</dt><dd class="muted">Có quyền VPN nhưng không gắn rule VPN nào</dd>
      </dl>`;
  const editing = rv.editing?.id === it.id;
  const sel = editing ? rv.editing.dec : it.decision; // nút đang chọn (kể cả khi đang nhập lý do)
  const actions = rv.camp?.status === "open" ? `
    <div class="rv-actions" role="group" aria-label="Quyết định cho ${esc(it.title)}">
      <button class="btn btn--sm${sel === "keep" ? " btn--primary" : ""}" aria-pressed="${sel === "keep"}" type="button" data-dec="keep" data-id="${it.id}">Còn cần</button>
      <button class="btn btn--sm${sel === "revoke" ? " btn--primary" : ""}" aria-pressed="${sel === "revoke"}" type="button" data-dec="revoke" data-id="${it.id}">Thu hồi</button>
      <button class="btn btn--sm${sel === "change" ? " btn--primary" : ""}" aria-pressed="${sel === "change"}" type="button" data-dec="change" data-id="${it.id}">Cần điều chỉnh</button>
    </div>
    ${editing ? `<div class="rv-reason">
      <label class="field"><span>Lý do ${rv.editing.dec === "revoke" ? "thu hồi" : "điều chỉnh"} (bắt buộc)</span>
        <input id="rv-comment" value="${esc(it.comment || "")}" placeholder="vd: đã nghỉ việc / chỉ cần cổng 443" maxlength="500" /></label>
      <button class="btn btn--primary btn--sm" type="button" data-confirm="${it.id}">Xác nhận</button>
      <button class="btn btn--ghost btn--sm" type="button" data-cancel>Hủy</button></div>` : ""}` : "";
  return `<article class="rv-item" id="rv-item-${it.id}">
    <div class="rv-item__head">
      <div><div class="rule-name">${esc(it.title)}</div>
        <div class="muted tiny">${isRule ? "Rule VPN" : "Tài khoản không gắn rule"} · ${esc(it.firewall)}${it.team ? ` · team ${esc(it.team)}` : ""}${it.scope === "infra" ? ` · <span class="chip">Infra</span>` : ""}</div></div>
      <span class="chip ${cls}">${label}</span>
    </div>
    ${detail}
    ${it.decided_by ? `<p class="tiny muted">${esc(it.decided_by)} · ${esc(fmtTime(it.decided_at))}${it.on_behalf ? " · Infra quyết định thay" : ""}${it.comment ? ` — “${esc(it.comment)}”` : ""}</p>` : ""}
    ${actions}
  </article>`;
}

async function decide(id, decision, comment = "") {
  try {
    await api(`/api/review/items/${id}/decision`, { method: "POST", body: { decision, comment } });
    rv.editing = null;
    toast(`Đã ghi: ${DEC[decision][1]}`, "ok");
    await loadMine();
    if (can("viewer")) loadCampaigns();
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#rv-show").addEventListener("change", loadMine);
$("#rv-list").addEventListener("click", (e) => {
  const b = e.target.closest("[data-dec]");
  if (b) {
    const id = Number(b.dataset.id);
    if (b.dataset.dec === "keep") return decide(id, "keep");
    rv.editing = { id, dec: b.dataset.dec };
    $("#rv-list").innerHTML = rv.items.map(itemCard).join("");
    $("#rv-comment")?.focus();
    return;
  }
  if (e.target.closest("[data-cancel]")) {
    rv.editing = null;
    $("#rv-list").innerHTML = rv.items.map(itemCard).join("");
    return;
  }
  const ok = e.target.closest("[data-confirm]");
  if (ok) decide(Number(ok.dataset.confirm), rv.editing.dec, $("#rv-comment").value.trim());
});
$("#rv-list").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.id === "rv-comment") {
    e.preventDefault();
    decide(rv.editing.id, rv.editing.dec, e.target.value.trim());
  }
});

// ------------------------------------------------------------------ quản lý đợt
async function loadCampaigns() {
  const tb = $("#rv-camps tbody");
  try {
    const r = await api("/api/review/campaigns");
    const tok = encodeURIComponent(state.token);
    tb.innerHTML = r.campaigns.length ? r.campaigns.map((c) => {
      const t = c.totals;
      return `<tr>
        <td><strong>${esc(c.name)}</strong><div class="muted tiny">${esc(c.period_key)} · mở bởi ${esc(c.created_by)}</div></td>
        <td class="nowrap">${c.status === "open" ? `<span class="chip chip--info">Đang mở</span>${can("admin") ? ` <button class="btn btn--sm btn--ghost" type="button" data-close="${c.id}">Đóng đợt</button>` : ""}` : `<span class="chip">Đã đóng</span><div class="muted tiny">${esc(fmtTime(c.closed_at))}</div>`}</td>
        <td class="nowrap mono">${fmtDate(c.due_date)}</td>
        <td class="tiny">Còn cần ${t.keep} · Thu hồi ${t.revoke} · Điều chỉnh ${t.change}${t.pending ? ` · <strong>chờ ${t.pending}</strong>` : ""}${t.no_response ? ` · <span class="text-err">không phản hồi ${t.no_response}</span>` : ""}</td>
        <td class="nowrap tiny"><a href="${API}/api/review/campaigns/${c.id}/evidence.csv?token=${tok}" download>Bằng chứng</a> ·
          <a href="${API}/api/review/campaigns/${c.id}/revocations.csv?token=${tok}" download>Cần xử lý</a></td>
      </tr>`;
    }).join("") : `<tr><td colspan="5"><p class="empty">Chưa có đợt rà soát nào.</p></td></tr>`;
    const open = r.campaigns.find((c) => c.status === "open");
    $("#rv-open").disabled = !!open;
    $("#rv-scopes").innerHTML = open ? `<div class="rv-scopes">${open.by_scope.map((s) => {
      const done = s.total - s.pending;
      return `<div class="rv-scope"><div class="rv-scope__head"><strong>${esc(s.name)}</strong><span class="tiny muted">${done}/${s.total}</span></div>
        <progress max="${s.total}" value="${done}" aria-label="Tiến độ ${esc(s.name)}"></progress></div>`;
    }).join("")}</div>` : "";
  } catch (ex) {
    tb.innerHTML = `<tr><td colspan="5">${errorBox(ex)}</td></tr>`;
  }
}

$("#rv-camps").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-close]");
  if (!b || !confirm("Đóng đợt rà soát? Mục chưa quyết định sẽ ghi 'Không phản hồi' và không sửa được nữa.")) return;
  try {
    await api(`/api/review/campaigns/${b.dataset.close}/close`, { method: "POST" });
    toast("Đã đóng đợt rà soát", "ok");
    loadReview();
  } catch (ex) {
    toast(ex.message, "err");
  }
});

$("#rv-open").addEventListener("click", async () => {
  if (!confirm("Mở đợt rà soát mới? Ảnh chụp rule VPN + tài khoản hiện tại sẽ được gửi cho đại diện team và Infra.")) return;
  try {
    const c = await api("/api/review/campaigns", { method: "POST", body: {} });
    toast(`Đã mở ${c.name}: ${c.totals.total} mục`, "ok");
    loadReview();
  } catch (ex) {
    toast(ex.message, "err");
  }
});

$("#rv-verify").addEventListener("click", async () => {
  const el = $("#rv-verify-msg");
  try {
    const r = await api("/api/review/verify");
    el.textContent = r.message;
    el.className = `tiny ${r.ok ? "text-ok" : "text-err"}`;
  } catch (ex) {
    el.textContent = ex.message;
    el.className = "tiny text-err";
  }
});
