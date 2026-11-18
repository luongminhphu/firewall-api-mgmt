/* Tab Cài đặt › Tự động chặn từ Teams (quản trị viên): kết nối Microsoft Graph (secret không bao giờ hiển thị lại),
   tài khoản SOC được phép gửi lệnh (Object ID Entra), khung giờ, ngưỡng IP/giờ, chu kỳ đọc Teams, email nhóm Admin,
   firewall đích, nút Kiểm tra kết nối (liệt kê người gửi gần đây để chọn tài khoản SOC). */
import { api } from "../api.js";
import { setBusy } from "../components/progress.js";
import { toast } from "../components/toast.js";
import { state } from "../store.js";
import { $, esc, fmtTime } from "../util.js";

const cfg = { senders: [], seen: [], wl: [] };
const say = (text, kind) => {
  const el = $("#abs-msg");
  el.textContent = text;
  el.className = `alert alert--${kind}`;
};

export async function loadAutoblockSettings() {
  try {
    fill(await api("/api/autoblock/settings"));
  } catch (ex) {
    toast(ex.message, "err");
  }
}

function fill(s) {
  $("#abs-enabled").checked = s.enabled;
  $("#abs-tenant").value = s.tenant_id;
  $("#abs-client").value = s.client_id;
  $("#abs-chat").value = s.chat_id;
  $("#abs-secret").value = "";
  $("#abs-secret").placeholder = s.has_secret ? "Đã lưu — để trống = giữ nguyên" : "Chưa có";
  $("#abs-window").checked = s.window_enabled;
  $("#abs-wstart").value = s.window_start;
  $("#abs-wend").value = s.window_end;
  $("#abs-limit").value = s.hourly_limit;
  $("#abs-poll").value = Math.round(s.poll_seconds / 60);
  $("#abs-admins").value = (s.admin_emails || []).join("\n");
  $("#abs-reply").checked = s.reply_enabled;
  $("#abs-reply-url").value = "";
  $("#abs-reply-url").placeholder = s.has_reply_url ? `Đã lưu (${s.reply_url_host}) — để trống = giữ nguyên` : "https://…logic.azure.com/…";
  const st = $("#ab-cfg-state");
  st.textContent = s.enabled ? "Đang bật" : s.configured ? "Đang tắt" : "Chưa cấu hình";
  st.className = `chip ${s.enabled ? "chip--ok" : "chip--warn"}`;
  $("#abs-fws").innerHTML = (state.firewalls || []).map((f) => `<label class="check">
      <input type="checkbox" value="${f.id}" ${s.firewall_ids.includes(f.id) ? "checked" : ""} />
      <span>${esc(f.name)}${f.enabled ? "" : " (đang tắt)"}</span></label>`).join("")
    || `<p class="muted tiny">Chưa có firewall nào.</p>`;
  $("#abs-meta").textContent = s.updated_by ? `Sửa lần cuối bởi ${s.updated_by} lúc ${fmtTime(s.updated_at)}` : "";
  cfg.wl = (s.whitelists || []).map((w) => ({ name: w.name, text: w.entries.join("\n") }));
  renderWhitelists();
  cfg.senders = s.soc_senders.map((x) => ({ ...x }));
  cfg.seen = s.seen_senders || [];
  renderSenders();
}

function renderSenders() {
  $("#abs-senders tbody").innerHTML = cfg.senders.length
    ? cfg.senders.map((x, i) => `<tr><td>${esc(x.name || "—")}</td><td class="mono tiny">${esc(x.id)}</td>
        <td><button class="btn btn--ghost btn--sm" type="button" data-del="${i}" aria-label="Xóa ${esc(x.name || x.id)}">✕</button></td></tr>`).join("")
    : `<tr><td colspan="3"><p class="empty">Chưa có tài khoản SOC — app sẽ không nhận lệnh nào.</p></td></tr>`;
  const ids = new Set(cfg.senders.map((x) => x.id));
  const seen = cfg.seen.filter((x) => !ids.has(x.id));
  $("#abs-seen").innerHTML = seen.length ? `<p class="muted tiny">Người gửi gần đây trong group chat:</p>` + seen.map((x) =>
    `<button class="btn btn--ghost btn--sm" type="button" data-add="${esc(x.id)}" data-name="${esc(x.name || "")}"
       title="${esc(x.id)}">+ ${esc(x.name || x.id)}${x.commands ? ` · ${x.commands} lệnh` : ""}</button>`).join(" ") : "";
}

// ------------------------------------------------------------------ whitelist
const lineCount = (text) => text.split(/\n/).map((x) => x.split("#")[0].trim()).filter(Boolean).length;

function renderWhitelists() {
  $("#abs-wl").innerHTML = cfg.wl.map((w, i) => `<div class="ab-wl__item">
      <div class="ab-wl__head">
        <input data-wl-name="${i}" value="${esc(w.name)}" maxlength="60" placeholder="Tên danh sách" aria-label="Tên danh sách whitelist" />
        <span class="chip" data-wl-count="${i}">${lineCount(w.text)} dòng</span>
        <button class="btn btn--ghost btn--sm" type="button" data-wl-del="${i}" aria-label="Xóa danh sách ${esc(w.name)}">✕</button>
      </div>
      <textarea data-wl-text="${i}" rows="4" spellcheck="false" placeholder="203.113.88.9&#10;23.32.0.0/11   # ghi chú"
        aria-label="IP / CIDR của danh sách ${esc(w.name)}">${esc(w.text)}</textarea></div>`).join("")
    || `<p class="muted tiny">Chưa có danh sách nào — mọi IP hợp lệ đều có thể bị tự chặn.</p>`;
}

$("#abs-wl").addEventListener("input", (e) => {
  const t = e.target;
  if (t.dataset.wlName !== undefined) cfg.wl[Number(t.dataset.wlName)].name = t.value;
  if (t.dataset.wlText !== undefined) {
    const i = Number(t.dataset.wlText);
    cfg.wl[i].text = t.value;
    $(`[data-wl-count="${i}"]`).textContent = `${lineCount(t.value)} dòng`;
  }
});
$("#abs-wl").addEventListener("click", (e) => {
  const d = e.target.closest("[data-wl-del]");
  if (!d) return;
  const w = cfg.wl[Number(d.dataset.wlDel)];
  if (w.text.trim() && !confirm(`Xóa danh sách whitelist "${w.name}"?`)) return;
  cfg.wl.splice(Number(d.dataset.wlDel), 1);
  renderWhitelists();
});
$("#abs-wl-add").addEventListener("click", () => {
  cfg.wl.push({ name: "", text: "" });
  renderWhitelists();
  $(`[data-wl-name="${cfg.wl.length - 1}"]`).focus();
});

function addSender(id, name) {
  id = id.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
    toast("Object ID phải có dạng GUID", "err");
    return;
  }
  if (!cfg.senders.some((x) => x.id === id)) cfg.senders.push({ id, name: name.trim() });
  renderSenders();
}

$("#abs-add").addEventListener("click", () => {
  addSender($("#abs-new-id").value, $("#abs-new-name").value);
  $("#abs-new-id").value = $("#abs-new-name").value = "";
});
$("#ab-form").addEventListener("click", (e) => {
  const d = e.target.closest("[data-del]");
  if (d) {
    cfg.senders.splice(Number(d.dataset.del), 1);
    renderSenders();
  }
  const a = e.target.closest("[data-add]");
  if (a) addSender(a.dataset.add, a.dataset.name);
});

$("#abs-test").addEventListener("click", async () => {
  const b = $("#abs-test");
  const out = $("#abs-test-out");
  setBusy(b, true, "Đang kiểm tra…");
  try {
    await save(false); // lưu kết nối trước (không đổi trạng thái bật/tắt)
    const r = await api("/api/autoblock/test", { method: "POST" });
    cfg.seen = r.senders;
    out.innerHTML = `<p class="alert alert--ok">Kết nối OK — đọc được ${r.messages} tin gần nhất của group chat.</p>`;
    renderSenders();
  } catch (ex) {
    out.innerHTML = `<p class="alert alert--error">${esc(ex.message)}</p>`;
  } finally {
    setBusy(b, false);
  }
});

async function save(withEnabled = true) {
  const body = {
    tenant_id: $("#abs-tenant").value.trim(), client_id: $("#abs-client").value.trim(),
    chat_id: $("#abs-chat").value.trim(), soc_senders: cfg.senders,
    window_enabled: $("#abs-window").checked, window_start: $("#abs-wstart").value, window_end: $("#abs-wend").value,
    hourly_limit: Number($("#abs-limit").value), poll_seconds: Number($("#abs-poll").value) * 60,
    admin_emails: $("#abs-admins").value,
    firewall_ids: [...$("#abs-fws").querySelectorAll("input:checked")].map((x) => Number(x.value)),
    whitelists: cfg.wl.map((w) => ({ name: w.name.trim(), entries: w.text })),
  };
  if ($("#abs-secret").value) body.client_secret = $("#abs-secret").value;
  if ($("#abs-reply-url").value.trim()) body.reply_webhook_url = $("#abs-reply-url").value.trim();
  body.reply_enabled = $("#abs-reply").checked;
  if (withEnabled) body.enabled = $("#abs-enabled").checked;
  const s = await api("/api/autoblock/settings", { method: "PUT", body });
  fill(s);
  return s;
}

$("#abs-reply-test").addEventListener("click", async () => {
  const b = $("#abs-reply-test");
  setBusy(b, true, "Đang gửi…");
  try {
    await save(false);
    const r = await api("/api/autoblock/reply-test", { method: "POST" });
    say(`Đã gửi thử vào group chat: “${r.text}”. Mở Teams để kiểm tra.`, "ok");
  } catch (ex) {
    say(ex.message, "error");
  } finally {
    setBusy(b, false);
  }
});

$("#ab-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const s = await save();
    say(s.enabled ? `Đã lưu. App đọc Teams mỗi ${Math.round(s.poll_seconds / 60)} phút, chỉ xử lý tin gửi từ bây giờ.`
      : "Đã lưu. Tự động chặn đang tắt.", "ok");
  } catch (ex) {
    say(ex.message, "error");
  }
});
