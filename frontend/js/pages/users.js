/* Trang Người dùng (quản trị viên): thêm/sửa/khóa/xóa, quyền Write/Readonly, đặt lại mật khẩu; hộp thoại tự đổi mật khẩu. */
import { api } from "../api.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { state } from "../store.js";
import { $, $$, esc, fmtTime } from "../util.js";

// ======================================================= NGƯỜI DÙNG
const userState = { list: [], auth: "local", perm: "readonly", minLen: 10 };

function segSet(id, v) {
  $$(`#${id} .seg-btn`).forEach((b) => b.classList.toggle("is-active", b.dataset.v === v));
}
function permChip(u) {
  if (u.is_admin) return `<span class="chip chip--warn">Quản trị · Write</span>`;
  return u.permission === "write"
    ? `<span class="chip chip--info">Write</span>`
    : `<span class="chip">Readonly</span>`;
}

export async function loadUsers() {
  const tb = $("#u-table tbody");
  tableMessage(tb, 6, "loading");
  try {
    const r = await api("/api/users");
    userState.list = r.users;
    userState.minLen = r.password_min_length || 10;
    const pol = [];
    pol.push(r.shared_password_login
      ? "Mật khẩu chung APP_PASSWORD đang BẬT (dự phòng khẩn cấp)."
      : "Mật khẩu chung APP_PASSWORD đã tắt.");
    pol.push(r.users_strict
      ? "Đăng nhập Microsoft chỉ chấp nhận người có trong danh sách."
      : "Người dùng Microsoft chưa có trong danh sách sẽ dùng App Role của Entra ID.");
    $("#u-policy").textContent = pol.join(" ");
    renderUsers();
    updateAuthHint();
  } catch (ex) {
    tableMessage(tb, 6, "error", ex.message);
  }
}

function renderUsers() {
  const q = ($("#u-search").value || "").trim().toLowerCase();
  const rows = userState.list.filter((u) =>
    !q || [u.username, u.display_name, u.permission, u.note, u.is_admin ? "quản trị admin" : ""]
      .join(" ").toLowerCase().includes(q));
  const tb = $("#u-table tbody");
  if (!rows.length) {
    tableMessage(tb, 6, "empty", userState.list.length ? "Không có kết quả"
    : "Chưa có người dùng nào — thêm người đầu tiên ở khung bên phải.");
    return;
  }
  tb.innerHTML = rows.map((u) => {
    const self = u.username === state.user;
    return `<tr>
      <td><div class="mono">${esc(u.username)}${self ? ' <span class="muted">(bạn)</span>' : ""}</div>
          <div class="muted">${esc(u.display_name || "")}</div>
          ${u.enabled ? "" : '<span class="chip chip--err only-mobile">Đã khóa</span>'}</td>
      <td class="nowrap">${u.auth_type === "microsoft" ? "Microsoft" + (u.entra_linked ? '<div class="muted small">đã liên kết Entra</div>' : '<div class="muted small">chờ đăng nhập lần đầu</div>') : "Mật khẩu"}</td>
      <td>${permChip(u)}</td>
      <td>${u.enabled ? '<span class="chip chip--ok">Hoạt động</span>' : '<span class="chip chip--err">Đã khóa</span>'}</td>
      <td class="nowrap">${esc(fmtTime(u.last_login) || "—")}</td>
      <td class="nowrap">
        <button class="btn btn--sm" data-uact="edit" data-id="${u.id}" type="button">Sửa</button>
        ${self ? "" : `<button class="btn btn--sm btn--danger-ghost" data-uact="del" data-id="${u.id}" type="button">Xóa</button>`}
      </td>
    </tr>`;
  }).join("");
}

function updateAuthHint() {
  const local = userState.auth === "local";
  const editing = !!$("#u-id").value;
  $("#u-pass-row").classList.toggle("hidden", !local);
  $("#u-pass-label").textContent = editing ? "Đặt lại mật khẩu (bỏ trống = giữ nguyên)" : "Mật khẩu *";
  $("#u-auth-hint").textContent = local
    ? `Đăng nhập bằng tên + mật khẩu riêng. Tối thiểu ${userState.minLen} ký tự, có chữ và số.`
    : "Đăng nhập bằng tài khoản công ty qua Microsoft (MFA). Tên đăng nhập phải là UPN, vd phu.luong@hsc.com.vn.";
}

function resetUserForm() {
  $("#u-form").reset();
  $("#u-id").value = "";
  $("#u-username").disabled = false;
  userState.auth = "local"; userState.perm = "readonly";
  segSet("u-auth", "local"); segSet("u-perm", "readonly");
  $("#u-enabled").checked = true;
  $("#u-form-title").textContent = "Thêm người dùng";
  $("#u-form-reset").classList.add("hidden");
  $("#u-form-msg").classList.add("hidden");
  $("#u-perm").classList.remove("is-disabled");
  updateAuthHint();
}

function editUser(u) {
  resetUserForm();
  $("#u-id").value = u.id;
  $("#u-username").value = u.username;
  $("#u-username").disabled = true;
  $("#u-display").value = u.display_name || "";
  $("#u-note").value = u.note || "";
  $("#u-admin").checked = u.is_admin;
  $("#u-enabled").checked = u.enabled;
  userState.auth = u.auth_type; userState.perm = u.permission;
  segSet("u-auth", u.auth_type); segSet("u-perm", u.permission);
  $("#u-perm").classList.toggle("is-disabled", u.is_admin);
  $("#u-form-title").textContent = `Sửa người dùng ${u.username}`;
  $("#u-form-reset").classList.remove("hidden");
  updateAuthHint();
  $("#u-form").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#u-auth").addEventListener("click", (e) => {
  const b = e.target.closest(".seg-btn"); if (!b) return;
  userState.auth = b.dataset.v; segSet("u-auth", b.dataset.v); updateAuthHint();
});
$("#u-perm").addEventListener("click", (e) => {
  const b = e.target.closest(".seg-btn"); if (!b || $("#u-admin").checked) return;
  userState.perm = b.dataset.v; segSet("u-perm", b.dataset.v);
});
$("#u-admin").addEventListener("change", (e) => {
  if (e.target.checked) { userState.perm = "write"; segSet("u-perm", "write"); }
  $("#u-perm").classList.toggle("is-disabled", e.target.checked);
});
$("#u-search").addEventListener("input", renderUsers);
$("#u-new").addEventListener("click", () => { resetUserForm(); $("#u-username").focus(); });
$("#u-form-reset").addEventListener("click", resetUserForm);

$("#u-table").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-uact]"); if (!b) return;
  const u = userState.list.find((x) => String(x.id) === b.dataset.id); if (!u) return;
  if (b.dataset.uact === "edit") return editUser(u);
  if (!confirm(`Xóa người dùng ${u.username}? Phiên đăng nhập hiện tại của người này bị vô hiệu ngay.`)) return;
  try {
    await api(`/api/users/${u.id}`, { method: "DELETE" });
    toast(`Đã xóa ${u.username}`, "ok");
    if ($("#u-id").value === String(u.id)) resetUserForm();
    loadUsers();
  } catch (ex) { toast(ex.message, "err"); }
});

$("#u-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#u-form-msg");
  msg.classList.add("hidden");
  const id = $("#u-id").value;
  const pw = $("#u-pass").value, pw2 = $("#u-pass2").value;
  const show = (t, kind = "error") => { msg.textContent = t; msg.className = `alert alert--${kind}`; };
  if (userState.auth === "local" && (pw || !id) && pw !== pw2) return show("Hai lần nhập mật khẩu không khớp");
  const body = {
    display_name: $("#u-display").value,
    auth_type: userState.auth,
    permission: $("#u-admin").checked ? "write" : userState.perm,
    is_admin: $("#u-admin").checked,
    enabled: $("#u-enabled").checked,
    note: $("#u-note").value,
  };
  if (pw) body.password = pw;
  try {
    if (id) {
      await api(`/api/users/${id}`, { method: "PUT", body });
      toast("Đã cập nhật người dùng", "ok");
    } else {
      body.username = $("#u-username").value;
      await api("/api/users", { method: "POST", body });
      toast(`Đã tạo người dùng ${body.username.trim().toLowerCase()}`, "ok");
    }
    resetUserForm();
    loadUsers();
  } catch (ex) { show(ex.message); }
});

// Đổi mật khẩu của chính mình
const pd = $("#pass-dialog");
$("#my-pass-btn").addEventListener("click", () => {
  $("#pass-form").reset(); $("#pd-msg").classList.add("hidden"); pd.showModal();
});
$("#pd-cancel").addEventListener("click", () => pd.close());
$("#pass-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const m = $("#pd-msg");
  const show = (t) => { m.textContent = t; m.className = "alert alert--error"; };
  if ($("#pd-new").value !== $("#pd-new2").value) return show("Hai lần nhập mật khẩu mới không khớp");
  try {
    await api("/api/me/password", { method: "POST",
      body: { current_password: $("#pd-cur").value, new_password: $("#pd-new").value } });
    pd.close();
    toast("Đã đổi mật khẩu", "ok");
  } catch (ex) { show(ex.message); }
});
