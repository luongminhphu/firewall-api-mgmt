/* Tab Cài đặt (quản trị viên): cấu hình module VPN — ngưỡng "sắp hết hạn", Rule Group được đọc (trong whitelist).
   Phase 5 bổ sung SMTP và người nhận thông báo vào tab này. */
import { api } from "../api.js";
import { toast } from "../components/toast.js";
import { $, $$, esc, fmtTime } from "../util.js";

export async function loadSettings() {
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
  const msg = $("#vs-msg");
  try {
    await api("/api/vpn/settings", {
      method: "PUT",
      body: {
        expiring_days: Number($("#vs-days").value),
        rule_groups: $$("#vs-groups input:checked").map((c) => c.value),
      },
    });
    msg.textContent = "Đã lưu cấu hình VPN.";
    msg.className = "alert alert--ok";
    loadSettings();
  } catch (ex) {
    msg.textContent = ex.message;
    msg.className = "alert alert--error";
  }
});
