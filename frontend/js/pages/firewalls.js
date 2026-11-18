/* Trang Firewall: danh sách, kiểm tra kết nối, thêm/sửa/xóa (quản trị viên). loadFirewalls() phát sự kiện "firewalls" cho các trang khác. */
import { api } from "../api.js";
import { statusChip } from "../components/badge.js";
import { toast } from "../components/toast.js";
import { can, emit, state } from "../store.js";
import { $, esc, fmtTime } from "../util.js";

// ------------------------------------------------------------- firewalls
export async function loadFirewalls() {
  state.firewalls = await api("/api/firewalls");
  emit("firewalls"); // trang Chặn: ô chọn firewall; trang IP Host Group: danh sách chọn
  renderFwList();
}

function renderFwList() {
  const box = $("#fw-list");
  if (!state.firewalls.length) {
    box.innerHTML = `<p class="empty">Chưa khai báo firewall nào.</p>`;
    return;
  }
  box.innerHTML = state.firewalls
    .map(
      (f) => `<article class="fw-card">
      <div class="fw-card__top">
        <span class="fw-card__title">${esc(f.name)}</span>
        ${statusChip(f)}
        ${f.enabled ? "" : '<span class="chip chip--warn">Đang tắt</span>'}
        <span class="fw-card__acts">
          ${can("operator") ? `<button class="btn btn--sm" data-act="test" data-id="${f.id}">Kiểm tra</button>` : ""}
          ${can("admin") ? `<button class="btn btn--sm" data-act="edit" data-id="${f.id}">Sửa</button>
          <button class="btn btn--sm btn--ghost" data-act="del" data-id="${f.id}">Xóa</button>` : ""}
        </span>
      </div>
      <dl class="fw-card__grid">
        <div><dt>Địa chỉ</dt><dd>${esc(f.host)}:${f.port}</dd></div>
        <div><dt>Tài khoản</dt><dd>${esc(f.username)}</dd></div>
        <div><dt>IP Host Group</dt><dd>${esc(state.blockGroup)}</dd></div>
        <div><dt>Site</dt><dd>${esc(f.site || "—")}</dd></div>
        <div><dt>TLS verify</dt><dd>${f.verify_ssl ? "Bật" : "Tắt"}</dd></div>
        <div><dt>Kiểm tra lần cuối</dt><dd>${esc(fmtTime(f.last_checked) || "—")}</dd></div>
      </dl>
      ${f.last_message ? `<p class="tiny muted">${esc(f.last_message)}</p>` : ""}
      ${f.note ? `<p class="tiny muted">Ghi chú: ${esc(f.note)}</p>` : ""}
    </article>`
    )
    .join("");
}

$("#fw-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const fw = state.firewalls.find((f) => f.id === id);
  if (btn.dataset.act === "test") {
    btn.disabled = true;
    btn.textContent = "Đang kiểm tra…";
    try {
      const r = await api(`/api/firewalls/${id}/test`, { method: "POST" });
      toast(`${r.firewall}: ${r.message}`, r.ok ? "ok" : "err");
    } catch (ex) {
      toast(ex.message, "err");
    }
    await loadFirewalls();
  } else if (btn.dataset.act === "edit") {
    fillFwForm(fw);
  } else if (btn.dataset.act === "del") {
    if (!confirm(`Xóa firewall "${fw.name}" khỏi mini app? (Không ảnh hưởng cấu hình trên firewall)`)) return;
    try {
      await api(`/api/firewalls/${id}`, { method: "DELETE" });
      toast("Đã xóa", "ok");
      await loadFirewalls();
    } catch (ex) {
      toast(ex.message, "err");
    }
  }
});

$("#test-all").addEventListener("click", async (e) => {
  e.target.disabled = true;
  try {
    const r = await api("/api/firewalls/test-all", { method: "POST", body: {} });
    const ok = r.results.filter((x) => x.ok).length;
    toast(`${ok}/${r.results.length} firewall phản hồi tốt`, ok === r.results.length ? "ok" : "err");
    await loadFirewalls();
  } catch (ex) {
    toast(ex.message, "err");
  }
  e.target.disabled = false;
});

function fillFwForm(fw) {
  $("#fw-id").value = fw ? fw.id : "";
  $("#fw-name").value = fw?.name || "";
  $("#fw-site").value = fw?.site || "";
  $("#fw-host").value = fw?.host || "";
  $("#fw-port").value = fw?.port || 4444;
  $("#fw-user").value = fw?.username || "";
  $("#fw-pass").value = "";
  $("#fw-pass").placeholder = fw ? "Bỏ trống = giữ mật khẩu cũ" : "••••••";
  $("#fw-note").value = fw?.note || "";
  $("#fw-verify").checked = !!fw?.verify_ssl;
  $("#fw-enabled").checked = fw ? fw.enabled : true;
  $("#fw-form-title").textContent = fw ? `Sửa: ${fw.name}` : "Thêm firewall";
  $("#fw-form-reset").classList.toggle("hidden", !fw);
  $("#fw-form-msg").classList.add("hidden");
  if (fw) $("#fw-form").scrollIntoView({ behavior: "smooth", block: "center" });
}
$("#fw-form-reset").addEventListener("click", () => fillFwForm(null));

$("#fw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#fw-form-msg");
  const id = $("#fw-id").value;
  const payload = {
    name: $("#fw-name").value,
    site: $("#fw-site").value,
    host: $("#fw-host").value,
    port: Number($("#fw-port").value),
    username: $("#fw-user").value,
    note: $("#fw-note").value,
    verify_ssl: $("#fw-verify").checked,
    enabled: $("#fw-enabled").checked,
  };
  if ($("#fw-pass").value) payload.password = $("#fw-pass").value;
  if (!id && !payload.password) {
    msg.textContent = "Cần nhập mật khẩu khi thêm firewall mới";
    msg.className = "alert alert--error";
    return;
  }
  try {
    await api(id ? `/api/firewalls/${id}` : "/api/firewalls", {
      method: id ? "PUT" : "POST",
      body: payload,
    });
    fillFwForm(null); // đặt lại form trước — fillFwForm ẩn ô thông báo
    msg.textContent = id ? "Đã cập nhật firewall" : "Đã thêm firewall";
    msg.className = "alert alert--ok";
    await loadFirewalls();
  } catch (ex) {
    msg.textContent = ex.message;
    msg.className = "alert alert--error";
  }
});
