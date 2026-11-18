/* Tab Cài đặt (quản trị viên):
   - VPN: ngưỡng "sắp hết hạn", Rule Group được đọc (trong whitelist).
   - SMTP: máy chủ / bảo mật / tài khoản (mật khẩu không bao giờ hiển thị lại), người gửi, gửi thử.
   - Thông báo: bật/tắt, email Infra, mốc nhắc, báo hằng tuần rule hết hạn còn bật.
   - Đại diện team (nhập tay), hàng đợi email + Chạy ngay. */
import { api } from "../api.js";
import { setBusy } from "../components/progress.js";
import { tableMessage } from "../components/table.js";
import { toast } from "../components/toast.js";
import { $, $$, esc, fmtTime } from "../util.js";

const say = (el, text, kind) => {
  el.textContent = text;
  el.className = `alert alert--${kind}`;
};

export async function loadSettings() {
  await Promise.all([loadVpnSettings(), loadReviewSettings(), loadNotify(), loadOutbox()]);
}

// ------------------------------------------------------------------ rà soát định kỳ
async function loadReviewSettings() {
  try {
    const s = await api("/api/review/settings");
    $("#rs-auto").checked = s.auto_quarterly;
    $("#rs-due").value = s.due_days;
    $("#rs-remind").value = s.remind_days;
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#rs-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/review/settings", {
      method: "PUT",
      body: { auto_quarterly: $("#rs-auto").checked, due_days: Number($("#rs-due").value),
              remind_days: Number($("#rs-remind").value) },
    });
    say($("#rs-msg"), "Đã lưu cấu hình rà soát.", "ok");
  } catch (ex) {
    say($("#rs-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ VPN
async function loadVpnSettings() {
  try {
    const s = await api("/api/vpn/settings");
    $("#vs-days").value = s.expiring_days;
    $("#vs-groups").innerHTML = s.allowed_rule_groups.map((g) => `<label class="check">
        <input type="checkbox" value="${esc(g)}" ${s.rule_groups.includes(g) ? "checked" : ""} /> <span>${esc(g)}</span>
      </label>`).join("");
    $("#vs-meta").textContent = s.updated_by
      ? `Sửa lần cuối bởi ${s.updated_by} lúc ${fmtTime(s.updated_at)}`
      : "Đang dùng giá trị mặc định.";
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#vs-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/vpn/settings", {
      method: "PUT",
      body: {
        expiring_days: Number($("#vs-days").value),
        rule_groups: $$("#vs-groups input:checked").map((c) => c.value),
      },
    });
    say($("#vs-msg"), "Đã lưu cấu hình VPN.", "ok");
    loadVpnSettings();
  } catch (ex) {
    say($("#vs-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ SMTP + thông báo + đại diện team
function fillSmtp(s) {
  $("#smtp-enabled").checked = s.enabled;
  $("#smtp-host").value = s.host;
  $("#smtp-port").value = s.port;
  $("#smtp-security").value = s.security;
  $("#smtp-verify").checked = s.verify_tls;
  $("#smtp-user").value = s.username;
  $("#smtp-pass").value = "";
  $("#smtp-pass").placeholder = s.has_password ? "•••••• đã lưu — bỏ trống để giữ" : "";
  $("#smtp-clear").checked = false;
  $("#smtp-clear-row").classList.toggle("hidden", !s.has_password);
  $("#smtp-from").value = s.from_addr;
  $("#smtp-from-name").value = s.from_name;
  const st = $("#smtp-state");
  st.textContent = s.enabled && s.configured ? "Đang bật" : s.configured ? "Đang tắt" : "Chưa cấu hình";
  st.className = `chip ${s.enabled && s.configured ? "chip--ok" : "chip--warn"}`;
}

function contactRow(c = { team: "", emails: [], note: "" }) {
  return `<tr>
    <td><input class="tc-team" list="tc-teams" value="${esc(c.team)}" aria-label="Tên team" /></td>
    <td><input class="tc-emails" value="${esc(c.emails.join(", "))}" aria-label="Email đại diện" placeholder="truong.nhom@hsc.com.vn" /></td>
    <td><input class="tc-note" value="${esc(c.note || "")}" aria-label="Ghi chú" /></td>
    <td><button class="btn btn--ghost btn--sm tc-del" type="button" aria-label="Xóa team ${esc(c.team)}">✕</button></td>
  </tr>`;
}

async function loadNotify() {
  try {
    const r = await api("/api/notify/settings");
    fillSmtp(r.smtp);
    $("#nt-enabled").checked = r.enabled;
    $("#nt-infra").value = r.infra_emails.join("\n");
    $("#nt-days").value = r.reminder_days.join(", ");
    $("#nt-weekly").checked = r.expired_weekly;
    $("#tc-table tbody").innerHTML = r.contacts.length ? r.contacts.map(contactRow).join("") : contactRow();
    try {
      const teams = (await api("/api/vpn/rules")).teams;
      $("#tc-teams").innerHTML = teams.map((t) => `<option value="${esc(t)}"></option>`).join("");
    } catch {}
  } catch (ex) {
    toast(ex.message, "err");
  }
}

$("#smtp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    enabled: $("#smtp-enabled").checked,
    host: $("#smtp-host").value.trim(),
    port: Number($("#smtp-port").value || 25),
    security: $("#smtp-security").value,
    verify_tls: $("#smtp-verify").checked,
    username: $("#smtp-user").value.trim(),
    from_addr: $("#smtp-from").value.trim(),
    from_name: $("#smtp-from-name").value.trim(),
    clear_password: $("#smtp-clear").checked,
  };
  if ($("#smtp-pass").value) body.password = $("#smtp-pass").value;
  try {
    fillSmtp(await api("/api/settings/smtp", { method: "PUT", body }));
    say($("#smtp-msg"), "Đã lưu cấu hình SMTP.", "ok");
  } catch (ex) {
    say($("#smtp-msg"), ex.message, "error");
  }
});

$("#smtp-test").addEventListener("click", async () => {
  const btn = $("#smtp-test");
  setBusy(btn, true, "Đang gửi…");
  try {
    const r = await api("/api/settings/smtp/test", { method: "POST", body: { to: $("#smtp-test-to").value.trim() } });
    say($("#smtp-msg"), r.message, "ok");
  } catch (ex) {
    say($("#smtp-msg"), ex.message, "error");
  }
  setBusy(btn, false, "Gửi thử");
});

$("#nt-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const days = $("#nt-days").value.split(/[,\s]+/).filter(Boolean).map(Number);
  try {
    await api("/api/notify/settings", {
      method: "PUT",
      body: {
        enabled: $("#nt-enabled").checked,
        infra_emails: $("#nt-infra").value,
        reminder_days: days,
        expired_weekly: $("#nt-weekly").checked,
      },
    });
    say($("#nt-msg"), "Đã lưu cấu hình thông báo.", "ok");
    loadNotify();
  } catch (ex) {
    say($("#nt-msg"), ex.message, "error");
  }
});

$("#tc-add").addEventListener("click", () => {
  $("#tc-table tbody").insertAdjacentHTML("beforeend", contactRow());
  $("#tc-table tbody tr:last-child .tc-team").focus();
});
$("#tc-table").addEventListener("click", (e) => {
  const b = e.target.closest(".tc-del");
  if (b) b.closest("tr").remove();
});
$("#tc-save").addEventListener("click", async () => {
  const contacts = $$("#tc-table tbody tr")
    .map((tr) => ({
      team: $(".tc-team", tr).value.trim(),
      emails: $(".tc-emails", tr).value,
      note: $(".tc-note", tr).value.trim(),
    }))
    .filter((c) => c.team || c.emails.trim());
  try {
    const r = await api("/api/notify/contacts", { method: "PUT", body: { contacts } });
    $("#tc-table tbody").innerHTML = r.contacts.length ? r.contacts.map(contactRow).join("") : contactRow();
    say($("#tc-msg"), `Đã lưu ${r.contacts.length} team.`, "ok");
  } catch (ex) {
    say($("#tc-msg"), ex.message, "error");
  }
});

// ------------------------------------------------------------------ hàng đợi
const OB = { pending: ["chip--warn", "Đang chờ"], sent: ["chip--ok", "Đã gửi"], failed: ["chip--err", "Thất bại"] };

async function loadOutbox() {
  const tb = $("#ob-table tbody");
  tableMessage(tb, 5, "loading");
  try {
    const p = $("#ob-status").value ? `&status=${$("#ob-status").value}` : "";
    const r = await api(`/api/notify/outbox?limit=100${p}`);
    if (!r.emails.length) return tableMessage(tb, 5, "empty", "Chưa có email nào.");
    tb.innerHTML = r.emails.map((m) => {
      const [cls, label] = OB[m.status] || ["", m.status];
      return `<tr>
        <td class="nowrap mono tiny">${esc(fmtTime(m.sent_at || m.created_at))}</td>
        <td class="nowrap"><span class="chip ${cls}">${label}</span></td>
        <td>${esc(m.subject)}</td>
        <td class="tiny">${m.to.map(esc).join("<br>")}</td>
        <td class="tiny">${m.attempts}${m.last_error ? ` · <span class="text-err">${esc(m.last_error)}</span>` : ""}${
          m.status === "pending" && m.attempts ? `<div class="muted">thử lại ${esc(fmtTime(m.next_attempt_at))}</div>` : ""}</td>
      </tr>`;
    }).join("");
  } catch (ex) {
    tableMessage(tb, 5, "error", ex.message);
  }
}

$("#ob-status").addEventListener("change", loadOutbox);
$("#ob-run").addEventListener("click", async () => {
  const btn = $("#ob-run");
  setBusy(btn, true, "Đang chạy…");
  try {
    const r = await api("/api/notify/run", { method: "POST" });
    $("#ob-note").textContent = r.note
      ? r.note
      : `Xếp hàng ${r.queued ?? 0} thư mới · đã gửi ${r.sent} · thử lại ${r.retry} · đang chờ ${r.pending}`;
    toast(r.note || `Đã gửi ${r.sent} thư`, r.retry || r.failed ? "err" : "ok");
    await loadOutbox();
  } catch (ex) {
    toast(ex.message, "err");
  }
  setBusy(btn, false, "Chạy ngay");
});
