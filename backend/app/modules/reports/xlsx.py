"""Xuất báo cáo Excel (.xlsx, openpyxl): Tổng quan · Theo ngày · Danh sách IP · Chi tiết lượt chặn · Tự động chặn.

Cột thời gian là kiểu ngày giờ thật (giờ VN, không múi giờ — Excel không hỗ trợ tz) để lọc / sắp xếp được;
mỗi sheet có cố định dòng tiêu đề + bộ lọc.
"""
from __future__ import annotations

import io

from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from .data import executive, fmt, fmt_dur

# HSC Design System (light): font Inter, chữ navy #0B2D5C, tiêu đề bảng brand-deep #00468C,
# nhấn brand #2681FF, cảnh báo sy10 #8F7611, viền black-a12 #E0E0E0
FONT = "Inter"
HEAD_FILL = PatternFill("solid", fgColor="00468C")
HEAD_FONT = Font(name=FONT, bold=True, color="FFFFFF")
TITLE_FONT = Font(name="Inter Display", bold=True, size=16, color="00468C")
MUTED = Font(name=FONT, color="474747")
THIN = Side(style="thin", color="E0E0E0")
BORDER = Border(bottom=THIN)
DT_FMT = "dd/mm/yyyy hh:mm:ss"


def _naive(t):
    return t.replace(tzinfo=None) if t else None


def _table(ws, row: int, headers: list[str], rows: list[list], widths: list[int] | None = None,
           dt_cols: tuple[int, ...] = ()) -> int:
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=row, column=c, value=h)
        cell.fill, cell.font = HEAD_FILL, HEAD_FONT
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    for r_i, vals in enumerate(rows, row + 1):
        for c, v in enumerate(vals, 1):
            cell = ws.cell(row=r_i, column=c, value=v)
            cell.border = BORDER
            cell.font = Font(name=FONT, color="0B2D5C")
            cell.alignment = Alignment(vertical="top", wrap_text=isinstance(v, str) and len(v) > 40)
            if c in dt_cols and v is not None:
                cell.number_format = DT_FMT
    if widths:
        for c, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(c)].width = w
    return row + len(rows) + 1


def build_xlsx(rep: dict, *, generated_by: str, generated_at: str,
               logo: tuple[bytes, int, int, bool] | None = None) -> bytes:
    s, ab = rep["summary"], rep["autoblock"]
    wb = Workbook()
    normal = next(st for st in wb._named_styles if st.name == "Normal")  # font mặc định toàn workbook = Inter
    normal.font = Font(name=FONT, size=10, color="0B2D5C")

    # ------------------------------------------------------------ Executive Summary
    ex = executive(rep)
    ws = wb.active
    ws.title = "Executive Summary"
    ws["A1"] = f"Báo cáo chặn IP — {rep['label']} · Executive Summary"
    ws["A1"].font = TITLE_FONT
    ws["A2"] = f"Kỳ: {fmt(rep['start'])} → {fmt(rep['end'])} (giờ Việt Nam)"
    ws["A3"] = f"Lập bởi {generated_by} lúc {generated_at} · SOC Rapid Block · group SCANPORT GROUP"
    ws["A2"].font = ws["A3"].font = MUTED
    if logo:  # logo header — góc phải, cao 48px
        from openpyxl.drawing.image import Image as XLImage

        png, w, h, _ = logo
        im = XLImage(io.BytesIO(png))
        im.height, im.width = 48, max(1, round(48 * w / h))
        ws.add_image(im, "C1")
        ws.row_dimensions[1].height = 26
    r = 5
    ws.cell(row=r, column=1, value="Tổng quan").font = Font(name="Inter Display", bold=True, size=12, color="00468C")
    hc = ws.cell(row=r + 1, column=1, value=ex["headline"])
    hc.alignment, hc.font = Alignment(wrap_text=True, vertical="top"), Font(name=FONT, size=11, color="0B2D5C")
    ws.merge_cells(start_row=r + 1, start_column=1, end_row=r + 1, end_column=2)
    ws.row_dimensions[r + 1].height = 48
    r += 3
    for title, items, color in (("Nhận định nổi bật", ex["highlights"], "00468C"),
                                ("Cần lưu ý / hành động", ex["attention"], "8F7611")):
        ws.cell(row=r, column=1, value=title).font = Font(name="Inter Display", bold=True, size=12, color=color)
        r += 1
        for it in items:
            c = ws.cell(row=r, column=1, value=f"• {it}")
            c.font = Font(name=FONT, color="0B2D5C")
            c.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
            ws.row_dimensions[r].height = 32
            r += 1
        r += 1
    ws.cell(row=r, column=1, value="Chỉ số chính").font = Font(name="Inter Display", bold=True, size=12, color="00468C")
    kpi_row = r + 1
    rows = [
        ["IP bị chặn (duy nhất)", s["unique_ips"]],
        ["  · chặn thủ công (con người)", s["manual_ips"]],
        ["  · tự động chặn (lệnh SOC qua Teams)", s["auto_ips"]],
        ["Tỷ lệ tự động (%)", s["auto_share"]],
        ["Lượt chặn (IP × firewall)", s["actions"]],
        ["  · thủ công", s["manual_actions"]],
        ["  · tự động", s["auto_actions"]],
        ["Số firewall có thay đổi", s["firewalls"]],
        ["IP còn đang bị chặn", s["still_blocked"]],
        ["Lượt gỡ chặn trong kỳ", s["removed_in_period"]],
        ["Lệnh SOC nhận qua Teams", ab["requests"]],
        ["  · tự chặn ngay", ab["auto"]],
        ["  · chờ duyệt rồi được Approve", ab["approved"]],
        ["  · đang chờ duyệt", ab["pending"]],
        ["  · bị từ chối", ab["rejected"]],
        ["  · thuộc whitelist", ab["whitelist"]],
        ["  · không hợp lệ / trùng", ab["invalid"] + ab["duplicate"]],
        ["Thời gian SOC gửi → chặn xong (trung bình)", fmt_dur(ab["latency_avg"])],
        ["Thời gian SOC gửi → chặn xong (trung vị)", fmt_dur(ab["latency_median"])],
        ["Thời gian SOC gửi → chặn xong (lâu nhất)", fmt_dur(ab["latency_max"])],
    ]
    _table(ws, kpi_row, ["Chỉ số", "Giá trị"], rows, [70, 26])

    # ------------------------------------------------------------ Theo ngày
    wd = wb.create_sheet("Theo ngày")
    end = _table(wd, 1, ["Ngày", "Thủ công (IP)", "Tự động (IP)", "Tổng IP"],
                 [[d["date"], d["manual"], d["auto"], d["total"]] for d in rep["daily"]], [14, 16, 16, 12])
    for r in range(2, end):
        wd.cell(row=r, column=1).number_format = "dd/mm/yyyy"
    wd.freeze_panes = "A2"
    wd.auto_filter.ref = f"A1:D{end - 1}"
    ch = BarChart()
    ch.type, ch.grouping, ch.overlap = "col", "stacked", 100
    ch.title, ch.y_axis.title = "IP bị chặn theo ngày", "IP"
    ch.style = 10
    ch.add_data(Reference(wd, min_col=2, max_col=3, min_row=1, max_row=end - 1), titles_from_data=True)
    ch.set_categories(Reference(wd, min_col=1, min_row=2, max_row=end - 1))
    ch.height, ch.width = 8, 20
    from openpyxl.chart.shapes import GraphicalProperties
    for series, color in zip(ch.series, ("2681FF", "FFD400")):  # brand (thủ công) · sy50 (tự động)
        series.graphicalProperties = GraphicalProperties(solidFill=color)
    wd.add_chart(ch, "F2")

    # ------------------------------------------------------------ Danh sách IP (gộp firewall)
    wi = wb.create_sheet("Danh sách IP")
    end = _table(wi, 1, ["IP / CIDR", "Chặn lần đầu", "Chặn lần cuối", "Phương thức", "Người / nguồn thực hiện",
                         "Kênh", "Firewall", "Số lượt", "Trạng thái", "Lý do"],
                 [[i["ip"], _naive(i["first"]), _naive(i["last"]), i["method_label"], ", ".join(i["actors"]),
                   ", ".join(i["sources"]), ", ".join(i["firewalls"]), i["count"], i["status"], i["reason"]]
                  for i in rep["ips"]],
                 [20, 20, 20, 18, 30, 24, 30, 9, 12, 60], dt_cols=(2, 3))
    wi.freeze_panes = "B2"
    wi.auto_filter.ref = f"A1:J{max(end - 1, 1)}"

    # ------------------------------------------------------------ Chi tiết từng lượt
    we = wb.create_sheet("Chi tiết lượt chặn")
    end = _table(we, 1, ["Thời gian thực hiện", "IP / CIDR", "Firewall", "Phương thức", "Người thực hiện", "Kênh",
                         "Object", "Lý do", "Trạng thái", "Gỡ lúc", "Gỡ bởi"],
                 [[_naive(e["ts"]), e["ip"], e["firewall"], e["method_label"], e["actor_name"], e["source"],
                   e["object"], e["reason"], e["status"], _naive(e["removed_at"]), e["removed_by"]]
                  for e in rep["entries"]],
                 [20, 20, 22, 14, 28, 24, 22, 60, 12, 20, 20], dt_cols=(1, 10))
    we.freeze_panes = "C2"
    we.auto_filter.ref = f"A1:K{max(end - 1, 1)}"

    # ------------------------------------------------------------ Người thực hiện
    wa = wb.create_sheet("Người thực hiện")
    end = _table(wa, 1, ["Người / tác nhân", "Phương thức", "IP (duy nhất)", "Lượt chặn"],
                 [[a["actor"], a["method_label"], a["ips"], a["actions"]] for a in rep["actors"]], [36, 16, 16, 14])
    wa.auto_filter.ref = f"A1:D{max(end - 1, 1)}"

    for w in wb.worksheets:
        w.sheet_view.showGridLines = w.title != "Executive Summary"
    wb.properties.title = f"Báo cáo chặn IP {rep['label']}"
    wb.properties.creator = "SOC Rapid Block"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
