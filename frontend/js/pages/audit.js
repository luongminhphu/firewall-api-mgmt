/* Trang Audit log: lọc theo hành động / từ khóa, xuất CSV. */
import { api } from "../api.js";
import { resultChip } from "../components/badge.js";
import { tableMessage } from "../components/table.js";
import { $, esc, fmtTime } from "../util.js";

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
      unblock: "Bỏ chặn",
      test: "Kiểm tra",
      firewall_cud: "Sửa firewall",
    };
    tb.innerHTML = r.rows
      .map(
        (row) => `<tr>
          <td class="mono nowrap">${esc(fmtTime(row.ts))}</td>
          <td class="nowrap">${esc(row.actor)}</td>
          <td class="nowrap">${esc(actionLabel[row.action] || row.action)}</td>
          <td class="nowrap">${esc(row.firewall_name || "—")}</td>
          <td class="mono">${esc(row.group_name || "—")}</td>
          <td class="mono">${esc(row.target)}</td>
          <td>${resultChip(row.result === "ok" ? "added" : row.result)}</td>
          <td class="muted">${esc(row.status_code ? row.status_code + " · " : "")}${esc(row.message)}${
            row.reason ? `<br /><em>${esc(row.reason)}</em>` : ""
          }</td>
        </tr>`
      )
      .join("");
  } catch (ex) {
    tableMessage(tb, 8, "error", ex.message);
  }
}
