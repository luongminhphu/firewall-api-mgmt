/* Trang Audit log: lọc theo hành động / từ khóa, xuất CSV. */
import { api } from "../api.js";
import { resultChip } from "../components/badge.js";
import { tableMessage } from "../components/table.js";
import { $, esc, fmtTime, actorLabel, fwMessage } from "../util.js";

// ------------------------------------------------------------------ audit
$("#a-reload").addEventListener("click", loadAudit);
$("#a-action").addEventListener("change", loadAudit);
let auditTimer;
$("#a-search").addEventListener("input", () => {
  clearTimeout(auditTimer);
  auditTimer = setTimeout(loadAudit, 300);
});

export async function loadAudit() {
  const tb = $("#a-table").querySelector("tbody");
  tableMessage(tb, 8, "loading");
  try {
    const params = new URLSearchParams({
      limit: "300",
      action: $("#a-action").value,
      q: $("#a-search").value.trim(),
    });
    const r = await api(`/api/audit?${params}`);
    if (!r.rows.length) {
      tableMessage(tb, 8, "empty", "Chưa có bản ghi nào.");
      return;
    }
    const actionLabel = {
      block: "Chặn",
      unblock: "Gỡ chặn",
      test: "Kiểm tra kết nối",
      firewall_cud: "Sửa firewall",
      login: "Đăng nhập",
      settings_cud: "Sửa cài đặt",
      vpn_sync: "Đồng bộ VPN",
      review: "Rà soát",
      autoblock_switch: "Công tắc tự động chặn",
      autoblock_decision: "Duyệt / từ chối lệnh",
      smtp_test: "Gửi thư thử",
      report_email: "Gửi báo cáo",
      report_export: "Xuất báo cáo",
      evidence_export: "Tải bằng chứng",
      policy_violation: "Vi phạm chính sách",
      branding: "Đổi logo",
      user_mgmt: "Quản lý người dùng",
      notify_run: "Chạy hàng đợi email",
    };
    // "ok" chỉ là "đã thêm" với thao tác chặn; bỏ chặn là "đã bỏ"; mọi hành động khác là "thành công"
    const okAs = { block: "added", unblock: "removed" };
    tb.innerHTML = r.rows
      .map(
        (row) => `<tr>
          <td class="mono nowrap">${esc(fmtTime(row.ts))}</td>
          <td class="nowrap">${esc(actorLabel(row.actor))}</td>
          <td class="nowrap">${esc(actionLabel[row.action] || row.action)}</td>
          <td class="nowrap">${esc(row.firewall_name || "—")}</td>
          <td class="mono">${esc(row.group_name || "—")}</td>
          <td class="mono">${esc(row.target)}</td>
          <td>${resultChip(row.result === "ok" ? okAs[row.action] || "ok" : row.result)}</td>
          <td class="muted"${row.status_code ? ` title="Mã phản hồi firewall: ${esc(row.status_code)} · ${esc(row.message)}"` : ""}>${esc(fwMessage(row.message))}${
            row.reason ? `<br /><em>${esc(row.reason)}</em>` : ""
          }</td>
        </tr>`
      )
      .join("");
  } catch (ex) {
    tableMessage(tb, 8, "error", ex.message);
  }
}
