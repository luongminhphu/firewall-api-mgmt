/* Tab Rà soát — rà soát quyền truy cập VPN định kỳ (ISO 27001 A.5.18).
   - Mọi người (kể cả vai trò reviewer = đại diện team): mục thuộc team mình, quyết định Còn cần / Thu hồi / Cần điều chỉnh
     (Thu hồi / điều chỉnh bắt buộc lý do). Quản trị viên thấy thêm phạm vi Infra và quyết định thay được.
   - viewer trở lên: danh sách đợt, tiến độ theo team, CSV bằng chứng / cần xử lý, kiểm tra chuỗi băm;
     quản trị viên: mở / đóng đợt. */
import { closeModal, confirmAction, openModal } from "../components/modal.js";
import { API, api, errorBox } from "../api.js";
import { toast } from "../components/toast.js";
import { can, state } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

const rv = { items: [], camp: null, isAdmin: false, editing: null, openCamp: null };
const DEC = {
  keep: ["chip--ok", "Còn cần"], revoke: ["chip--err", "Thu hồi"], change: ["chip--warn", "Cần điều chỉnh"],
  pending: ["", "Chưa quyết định"], no_response: ["chip--err", "Không phản hồi"],
};
const fmtDate = (iso) => (iso ? iso.split("-").reverse().join("/") : "—");
const chips = (xs) => (xs || []).map((x) => `<span class="chip">${esc(x)}</span>`).join(" ");

// Hai phần, hai nhóm người dùng: "Việc của tôi" (quyết định) và "Quản lý đợt" (tiến độ, email, bằng chứng)
function setView(v) {
  const manage = v === "manage" && can("viewer");
  $$("#rv-views [data-rv-view]").forEach((b) => {
    const on = b.dataset.rvView === (manage ? "manage" : "mine");
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-selected", String(on));
  });
  $("#rv-mine").hidden = manage;
  $("#rv-admin").hidden = !manage;
  if (!manage) $("#rv-mail").hidden = true;
  else if (rv.openCamp) loadDrafts(rv.openCamp);
  try {
    window.localStorage.setItem("rv_view", manage ? "manage" : "mine");
  } catch {
    /* trình duyệt chặn lưu trữ: không nhớ được phần đang xem */
  }
}
$("#rv-views").addEventListener("click", (e) => {
  const b = e.target.closest("[data-rv-view]");
  if (b) setView(b.dataset.rvView);
});

export async function loadReview() {
  $("#rv-views").hidden = !can("viewer"); // vai trò Rà soát (đại diện group) chỉ có "Việc của tôi"
  let v = "mine";
  try {
    v = window.localStorage.getItem("rv_view") || "mine";
  } catch {
    /* mặc định Việc của tôi */
  }
  $("#rv-open").classList.toggle("hidden", !can("admin"));
  await Promise.all([loadMine(), can("viewer") ? loadCampaigns() : null]);
  setView(v);
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
    $("#rv-list").innerHTML = `<p class="empty">Hiện không có đợt rà soát nào đang mở. Đợt mới mở vào đầu mỗi quý;
      khi mở, đại diện group nhận email kèm đường link, vào đây chọn <strong>Còn cần / Thu hồi / Cần điều chỉnh</strong> cho từng quyền VPN của group mình.</p>`;
    return;
  }
  const scopes = r.scopes.map((s) => esc(s.name)).join(", ");
  $("#rv-sub").innerHTML = r.scopes.length
    ? `Bạn rà soát: <strong>${scopes}</strong> · hạn <strong>${fmtDate(c.due_date)}</strong>. Xác nhận từng quyền còn cần, cần thu hồi hay cần điều chỉnh.`
    : `Bạn không phải đại diện group nào trong đợt này.`;
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
      <button class="btn btn--sm rv-dec" aria-pressed="${sel === "keep"}" type="button" data-dec="keep" data-id="${it.id}">Còn cần</button>
      <button class="btn btn--sm rv-dec" aria-pressed="${sel === "revoke"}" type="button" data-dec="revoke" data-id="${it.id}">Thu hồi</button>
      <button class="btn btn--sm rv-dec" aria-pressed="${sel === "change"}" type="button" data-dec="change" data-id="${it.id}">Cần điều chỉnh</button>
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
        <td data-label="Đợt"><strong>${esc(c.name)}</strong><div class="muted tiny">${esc(c.period_key)} · mở bởi ${esc(c.created_by)}</div></td>
        <td class="nowrap" data-label="Trạng thái">${c.status === "open" ? `<span class="chip chip--info">Đang mở</span>${can("admin") ? ` <button class="btn btn--sm btn--danger-ghost" type="button" data-close="${c.id}">Đóng đợt</button>` : ""}` : `<span class="chip">Đã đóng</span><div class="muted tiny">${esc(fmtTime(c.closed_at))}</div>`}</td>
        <td class="nowrap mono" data-label="Hạn">${fmtDate(c.due_date)}</td>
        <td class="tiny" data-label="Kết quả">Còn cần ${t.keep} · Thu hồi ${t.revoke} · Điều chỉnh ${t.change}${t.pending ? ` · <strong>chờ ${t.pending}</strong>` : ""}${t.no_response ? ` · <span class="text-err">không phản hồi ${t.no_response}</span>` : ""}</td>
        <td class="nowrap tiny" data-label="Tải CSV"><a href="${API}/api/review/campaigns/${c.id}/evidence.csv?token=${tok}" download>Bằng chứng</a> ·
          <a href="${API}/api/review/campaigns/${c.id}/revocations.csv?token=${tok}" download>Cần xử lý</a></td>
      </tr>`;
    }).join("") : `<tr><td colspan="5"><p class="empty">Chưa có đợt rà soát nào.</p></td></tr>`;
    const open = r.campaigns.find((c) => c.status === "open");
    rv.openCamp = open || null;
    $("#rv-open").disabled = !!open;
    $("#rv-open-hint").textContent = open && can("admin") ? `Đang có đợt "${open.name}" mở — đóng đợt đó trước khi mở đợt mới.` : "";
    if (!$("#rv-admin").hidden) loadDrafts(open);
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
  if (!b || !(await confirmAction({ title: "Đóng đợt rà soát?", ok: "Đóng đợt", html: "<p>Mục chưa quyết định sẽ ghi <strong>Không phản hồi</strong> và không sửa được nữa.</p>" }))) return;
  try {
    await api(`/api/review/campaigns/${b.dataset.close}/close`, { method: "POST" });
    toast("Đã đóng đợt rà soát", "ok");
    loadReview();
  } catch (ex) {
    toast(ex.message, "err");
  }
});

$("#rv-open").addEventListener("click", async () => {
  if (!(await confirmAction({ title: "Mở đợt rà soát mới?", ok: "Mở đợt rà soát", danger: false, html: "<p>Ảnh chụp rule VPN và tài khoản hiện tại sẽ được gửi cho đại diện group và Infra.</p>" }))) return;
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

// ------------------------------------------------------------------ email rà soát theo group (quản trị viên)
const mail = { cid: null, scope: null, sent: null };

async function loadDrafts(open) {
  const sec = $("#rv-mail");
  sec.hidden = !(open && can("admin")) || $("#rv-admin").hidden;
  if (sec.hidden) return;
  mail.cid = open.id;
  const tb = $("#rv-mail-table tbody");
  try {
    const { drafts } = await api(`/api/review/campaigns/${open.id}/drafts`);
    tb.innerHTML = drafts.map((d) => `<tr>
      <td data-label="Group"><strong>${esc(d.name)}</strong>${d.scope === "infra" ? "" : `<div class="muted tiny">${d.members} user VPN</div>`}</td>
      <td data-label="Gửi tới" class="tiny">${d.to.length ? d.to.map(esc).join(", ") : `<span class="text-warn">Chưa có email — khai báo ở Cài đặt › VPN &amp; rà soát</span>`}</td>
      <td data-label="Quyền" class="nowrap">${d.total}${d.pending && d.pending < d.total ? ` <span class="muted tiny">· chờ ${d.pending}</span>` : ""}</td>
      <td data-label="Đã gửi" class="tiny">${sentCell(d.sent)}</td>
      <td><button class="btn btn--sm${d.sent ? "" : " btn--primary"}" type="button" data-draft="${esc(d.scope)}">${d.sent ? "Gửi lại" : "Soạn email"}</button></td>
    </tr>`).join("");
  } catch (ex) {
    tb.innerHTML = `<tr><td colspan="5">${errorBox(ex)}</td></tr>`;
  }
}

const sentCell = (x) => (x
  ? `<span class="text-ok">${esc(fmtTime(x.at))}</span><div class="muted">${esc(x.method)} · ${esc(x.by)}${x.count > 1 ? ` · ${x.count} lần` : ""}</div>`
  : `<span class="muted">Chưa gửi</span>`);

const draftBody = () => ({
  to: $("#dm-to").value, cc: $("#dm-cc").value, subject: $("#dm-subject").value.trim(), body: $("#dm-body").value,
});

$("#rv-mail-table").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-draft]");
  if (!b) return;
  try {
    const d = await api(`/api/review/campaigns/${mail.cid}/drafts/${encodeURIComponent(b.dataset.draft)}`);
    mail.scope = d.scope;
    mail.sent = d.sent;
    openModal(`Email rà soát — ${d.name}`, `
      <form class="draft-form" id="draft-form" autocomplete="off">
        ${d.sent ? `<p class="alert alert--warn" role="status">Đã gửi cho group này ${esc(fmtTime(d.sent.at))} (${esc(d.sent.method)}, ${esc(d.sent.by)}${d.sent.count > 1 ? `, ${d.sent.count} lần` : ""}). Gửi lại sẽ là thư thứ ${d.sent.count + 1}.</p>` : ""}
        <div class="row row--2">
          <label class="field"><span>Gửi tới</span><input id="dm-to" value="${esc(d.to.join(", "))}" placeholder="dai.dien@hsc.com.vn" /></label>
          <label class="field"><span>Cc</span><input id="dm-cc" value="${esc(d.cc.join(", "))}" /></label>
        </div>
        <label class="field"><span>Tiêu đề</span><input id="dm-subject" value="${esc(d.subject)}" maxlength="250" /></label>
        <label class="field"><span>Nội dung (sửa được)</span><textarea id="dm-body" rows="18">${esc(d.body)}</textarea></label>
        <p id="dm-msg" class="alert hidden" role="status"></p>
        <div class="actions">
          <button class="btn btn--ghost" type="button" id="dm-copy">Sao chép nội dung</button>
          <button class="btn" type="button" id="dm-eml">Tải .eml (thư nháp Outlook)</button>
          <button class="btn btn--primary" type="button" id="dm-send">Gửi qua SMTP</button>
        </div>
      </form>`);
  } catch (ex) {
    toast(ex.message, "err");
  }
});

function dmSay(text, kind) {
  const el = $("#dm-msg");
  el.textContent = text;
  el.className = `alert alert--${kind === "ok" ? "ok" : "error"}`;
}

$("#modal").addEventListener("click", async (e) => {
  if (!mail.scope || !$("#draft-form")) return;
  const url = `/api/review/campaigns/${mail.cid}/drafts/${encodeURIComponent(mail.scope)}`;
  if (e.target.id === "dm-copy") {
    const d = draftBody();
    try {
      await window.navigator.clipboard.writeText(`Tiêu đề: ${d.subject}\n\n${d.body}`);
      dmSay("Đã sao chép tiêu đề + nội dung.", "ok");
    } catch {
      $("#dm-body").select(); // trình duyệt chặn clipboard: chọn sẵn để Ctrl+C
      dmSay("Trình duyệt không cho sao chép tự động — nội dung đã được chọn, bấm Ctrl+C.", "error");
    }
  } else if (e.target.id === "dm-eml") {
    try {
      const res = await fetch(`${API}${url}/eml`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Auth-Token": state.token },
        body: JSON.stringify(draftBody()),
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `Lỗi ${res.status}`);
      const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || "ra-soat-vpn.eml";
      const a = document.createElement("a");
      a.href = window.URL.createObjectURL(await res.blob());
      a.download = name;
      a.click();
      window.setTimeout(() => window.URL.revokeObjectURL(a.href), 5000);
      dmSay(`Đã tải ${name} — mở bằng Outlook, kiểm tra rồi bấm Gửi. Lần tạo thư đã được ghi vào nhật ký rà soát.`, "ok");
      loadDrafts(rv.openCamp);
    } catch (ex) {
      dmSay(ex.message, "error");
    }
  } else if (e.target.id === "dm-send") {
    const d = draftBody();
    if (!(await confirmAction({ title: mail.sent ? "Gửi lại email rà soát?" : "Gửi email rà soát?", ok: mail.sent ? "Gửi lại" : "Gửi email", danger: false,
      html: `<p>Gửi tới <strong>${esc(d.to)}</strong>${d.cc.trim() ? `, Cc ${esc(d.cc)}` : ""} qua máy chủ SMTP của app.</p>
        ${mail.sent ? `<p class="text-warn">Group này đã nhận email lúc ${esc(fmtTime(mail.sent.at))} (${esc(mail.sent.method)}).</p>` : ""}` }))) return;
    const btn = $("#dm-send");
    btn.disabled = true;
    try {
      const r = await api(`${url}/send`, { method: "POST", body: d });
      toast(r.message, "ok");
      closeModal();
      loadDrafts(rv.openCamp);
    } catch (ex) {
      dmSay(ex.message, "error");
    }
    btn.disabled = false;
  }
});
