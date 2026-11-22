"""Xuất báo cáo PDF (reportlab, A4 ngang) theo HSC Design System — để trình lãnh đạo.

Font: Inter (nội dung, số liệu) + Inter Display (tiêu đề) — font chuẩn của HSC Design System, nhúng TTF tĩnh
(tạo từ Inter variable chính thức, giấy phép OFL), đủ dấu tiếng Việt.
Màu: token HSC chế độ sáng — chữ navy #0B2D5C, brand #2681FF, brand-deep #00468C, cover gradient
#0058AF → #00468C, trạng thái sg30 / sr40 / sy50.

Bố cục:
  1. Tóm tắt điều hành — câu tổng quan, thẻ chỉ số, nhận định nổi bật, điểm cần lưu ý (trang đầu).
  2. Nội dung chi tiết — biểu đồ + bảng theo ngày, tự động chặn, người thực hiện, danh sách IP.
Chân trang: tên báo cáo · kỳ · "Trang x/y".
"""
from __future__ import annotations

import io
import os

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from .data import executive, fmt, fmt_dur

_FONTS = os.path.join(os.path.dirname(__file__), "fonts")
_registered = False

# ---- token HSC Design System (light) ----
NAVY = colors.HexColor("#00468C")        # --brand-deep: nền tiêu đề bảng, tiêu đề mục
COVER = colors.HexColor("#0058AF")       # --cover-gradient (đầu)
BLUE = colors.HexColor("#2681FF")        # --brand: biểu đồ "Thủ công", số liệu nổi bật
AMBER = colors.HexColor("#FFD400")       # --sy50 (price-reference / status-warning): biểu đồ "Tự động"
INK = colors.HexColor("#0B2D5C")         # --text-primary (light)
MUTED = colors.HexColor("#474747")       # --text-secondary (black-a72)
LINE = colors.HexColor("#E0E0E0")        # --border (black-a12)
ZEBRA = colors.HexColor("#F4F6F6")       # --sc100
TINT_BLUE = colors.HexColor("#DFE9F6")   # --sb100
TINT_AMBER = colors.HexColor("#EAE1BD")  # --sy100
AMBER_LINE = colors.HexColor("#D9B420")  # --sy60
GREEN = colors.HexColor("#187A2C")       # --sg30
RED = colors.HexColor("#B82E37")         # --sr40


def _fonts() -> None:
    global _registered
    if _registered:
        return
    for alias, f in (("Inter", "Inter-Regular.ttf"), ("Inter-SemiBold", "Inter-SemiBold.ttf"),
                     ("Inter-Bold", "Inter-Bold.ttf"), ("InterDisplay", "InterDisplay-SemiBold.ttf"),
                     ("InterDisplay-Bold", "InterDisplay-Bold.ttf")):
        pdfmetrics.registerFont(TTFont(alias, os.path.join(_FONTS, f)))
    pdfmetrics.registerFontFamily("Inter", normal="Inter", bold="Inter-SemiBold", italic="Inter",
                                  boldItalic="Inter-SemiBold")
    _registered = True


def _styles() -> dict:
    base = ParagraphStyle("base", fontName="Inter", fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_LEFT)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=11, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10.5),
        "mono": ParagraphStyle("mono", parent=base, fontName="Inter", fontSize=8, leading=10.5),
        "title": ParagraphStyle("title", parent=base, fontName="InterDisplay-Bold", fontSize=22, leading=27,
                                textColor=colors.white),
        "sub": ParagraphStyle("sub", parent=base, fontSize=8.5, leading=12, textColor=colors.HexColor("#DFE9F6")),
        "h1": ParagraphStyle("h1", parent=base, fontName="InterDisplay-Bold", fontSize=15, leading=20, textColor=NAVY,
                             spaceBefore=6, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base, fontName="InterDisplay", fontSize=12, leading=16, textColor=INK,
                             spaceBefore=12, spaceAfter=5, keepWithNext=1),
        "note": ParagraphStyle("note", parent=base, fontSize=8, leading=11, textColor=MUTED, keepWithNext=1),
        "lead": ParagraphStyle("lead", parent=base, fontSize=11, leading=16),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3),
        "kpi_v": ParagraphStyle("kpi_v", parent=base, fontName="InterDisplay-Bold", fontSize=19, leading=23, textColor=NAVY),
        "kpi_l": ParagraphStyle("kpi_l", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
    }


def _esc(s) -> str:
    return (str(s if s is not None else "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _NumberedCanvas(rl_canvas.Canvas):
    """Chân trang "Trang x/y" (cần biết tổng số trang → vẽ sau khi xếp xong)."""

    footer = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for st in self._pages:
            self.__dict__.update(st)
            w, h = self._pagesize
            self.setFillColor(NAVY)  # dải màu thương hiệu đầu mỗi trang (brand-deep)
            self.rect(0, h - 3 * mm, w, 3 * mm, stroke=0, fill=1)
            self.setFont("Inter", 7.5)
            self.setFillColor(MUTED)
            self.drawString(14 * mm, 8 * mm, self.footer)
            self.drawRightString(w - 14 * mm, 8 * mm, f"Trang {self._pageNumber}/{total}")
            self.setStrokeColor(LINE)
            self.line(14 * mm, 11 * mm, w - 14 * mm, 11 * mm)
            super().showPage()
        super().save()


def _grid(data, widths, *, header=True, zebra=True, align_right=()) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    st = [("FONT", (0, 0), (-1, -1), "Inter", 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
          ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
          ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE)]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
               ("FONT", (0, 0), (-1, 0), "Inter-SemiBold", 8), ("VALIGN", (0, 0), (-1, 0), "MIDDLE")]
    if zebra:
        for r in range(2 if header else 1, len(data), 2):
            st.append(("BACKGROUND", (0, r), (-1, r), ZEBRA))
    for c in align_right:
        st.append(("ALIGN", (c, 0), (c, -1), "RIGHT"))
    t.setStyle(TableStyle(st))
    return t


def _kpis(rep: dict, S: dict, width: float) -> Table:
    s, ab = rep["summary"], rep["autoblock"]
    items = [
        (s["unique_ips"], "IP bị chặn (duy nhất)"),
        (s["manual_ips"], "Chặn thủ công (con người)"),
        (s["auto_ips"], "Tự động chặn (lệnh SOC)"),
        (f"{s['auto_share']}%", "Tỷ lệ tự động"),
        (s["actions"], "Lượt chặn (IP × firewall)"),
        (fmt_dur(ab["latency_avg"]), "SOC gửi → chặn xong (TB)"),
    ]
    cells = [[Paragraph(_esc(v), S["kpi_v"]), Paragraph(_esc(lbl), S["kpi_l"])] for v, lbl in items]
    row = [Table([[c[0]], [c[1]]], colWidths=[width / 6 - 8]) for c in cells]
    t = Table([row], colWidths=[width / 6] * 6, hAlign="LEFT")
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                           ("BACKGROUND", (0, 0), (-1, -1), TINT_BLUE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return t


def _chart(rep: dict, width: float) -> Drawing:
    daily = rep["daily"]
    h = 170
    d = Drawing(width, h)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 34, 26, width - 150, h - 40
    bc.data = [[x["manual"] for x in daily], [x["auto"] for x in daily]]
    bc.categoryAxis.style = "stacked"
    step = max(1, -(-len(daily) // 31))  # kỳ dài: chỉ ghi nhãn mỗi `step` ngày cho đỡ chồng chữ
    bc.categoryAxis.categoryNames = [x["date"].strftime("%d/%m") if i % step == 0 else ""
                                     for i, x in enumerate(daily)]
    bc.categoryAxis.labels.fontName = "Inter"
    bc.categoryAxis.labels.fontSize = 6.5 if len(daily) > 14 else 7.5
    bc.categoryAxis.labels.angle = 45 if len(daily) > 14 else 0
    bc.categoryAxis.labels.boxAnchor = "ne" if len(daily) > 14 else "n"
    bc.valueAxis.valueMin = 0
    top = max([x["total"] for x in daily] + [1])
    bc.valueAxis.valueMax = max(4, top + max(1, top // 5))
    bc.valueAxis.valueStep = max(1, bc.valueAxis.valueMax // 4)
    bc.valueAxis.labels.fontName = "Inter"
    bc.valueAxis.labels.fontSize = 7.5
    bc.valueAxis.gridStrokeColor = LINE
    bc.valueAxis.visibleGrid = True
    bc.bars[0].fillColor, bc.bars[1].fillColor = BLUE, AMBER
    bc.bars.strokeColor = None
    bc.barSpacing = 1
    d.add(bc)
    lg = Legend()
    lg.x, lg.y = width - 100, h - 30
    lg.fontName, lg.fontSize = "Inter", 8
    lg.colorNamePairs = [(BLUE, "Thủ công"), (AMBER, "Tự động")]
    lg.dxTextSpace, lg.deltay = 4, 12
    d.add(lg)
    return d


def _logo_flowable(logo: tuple[bytes, int, int, bool] | None, max_w: float, max_h: float):
    if not logo:
        return Spacer(1, 1)
    png, w, h, _ = logo
    scale = min(max_w / w, max_h / h)
    return Image(io.BytesIO(png), width=w * scale, height=h * scale)


def build_pdf(rep: dict, *, generated_by: str, generated_at: str,
              logo: tuple[bytes, int, int, bool] | None = None) -> bytes:
    _fonts()
    S = _styles()
    buf = io.BytesIO()
    page = landscape(A4)
    doc = SimpleDocTemplate(buf, pagesize=page, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=12 * mm,
                            bottomMargin=16 * mm, title=f"Báo cáo chặn IP {rep['label']}",
                            author="SOC Rapid Block", subject="Báo cáo chặn IP")
    W = page[0] - 28 * mm
    s, ab = rep["summary"], rep["autoblock"]
    ex = executive(rep)
    story = []

    # ===================================================== TÓM TẮT ĐIỀU HÀNH
    # Header: dải màu cover HSC, logo trong ô trắng góc phải (logo tải lên hoặc biểu tượng mặc định)
    LW = 46 * mm
    band = Table([[Paragraph(f"Báo cáo chặn IP — {_esc(rep['label'])}", S["title"]), _logo_flowable(logo, LW - 10 * mm, 14 * mm)],
                  [Paragraph(f"Kỳ báo cáo: <b>{fmt(rep['start'])}</b> → <b>{fmt(rep['end'])}</b> (giờ Việt Nam) · "
                             f"Lập bởi {_esc(generated_by)} lúc {_esc(generated_at)} · SOC Rapid Block · "
                             "SCANPORT GROUP", S["sub"]), ""]], colWidths=[W - LW, LW], hAlign="LEFT")
    band.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), COVER), ("BACKGROUND", (0, 1), (0, 1), NAVY),
                              ("SPAN", (1, 0), (1, 1)), ("BACKGROUND", (1, 0), (1, 1), colors.white),
                              ("BOX", (1, 0), (1, 1), 0.8, NAVY), ("ALIGN", (1, 0), (1, 1), "CENTER"),
                              ("VALIGN", (1, 0), (1, 1), "MIDDLE"), ("VALIGN", (0, 0), (0, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                              ("TOPPADDING", (0, 0), (0, 0), 12), ("BOTTOMPADDING", (0, -1), (0, -1), 10)]))
    story += [
        band,
        Spacer(1, 10),
        Paragraph("Tóm tắt điều hành", S["h1"]),
        Paragraph(_esc(ex["headline"]), S["lead"]),
        Spacer(1, 8),
        _kpis(rep, S, W),
        Spacer(1, 10),
    ]
    hl = [Paragraph("Nhận định nổi bật", S["h2"])] + [Paragraph(_esc(x), S["bullet"], bulletText="•")
                                                       for x in ex["highlights"] or ["Không có dữ liệu trong kỳ."]]
    at = [Paragraph("Cần lưu ý / hành động", S["h2"])] + [Paragraph(_esc(x), S["bullet"], bulletText="•")
                                                           for x in ex["attention"]]
    two = Table([[hl, at]], colWidths=[W * 0.58, W * 0.42], hAlign="LEFT")
    two.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (1, 0), (1, 0), TINT_AMBER),
                             ("BOX", (1, 0), (1, 0), 0.5, AMBER_LINE),
                             ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                             ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [two, PageBreak()]

    # ===================================================== CHI TIẾT
    story.append(Paragraph("Nội dung chi tiết", S["h1"]))
    story.append(Paragraph("1. IP bị chặn theo ngày", S["h2"]))
    rows = [["Ngày", "Thủ công (IP)", "Tự động (IP)", "Tổng IP"]] + [
        [d["date"].strftime("%d/%m/%Y"), d["manual"], d["auto"], d["total"]] for d in rep["daily"]]
    rows.append(["Tổng kỳ (IP duy nhất)", s["manual_ips"], s["auto_ips"], s["unique_ips"]])
    short = len(rep["daily"]) <= 10
    tbl = _grid(rows, [W * f for f in ((0.13, 0.095, 0.095, 0.08) if short else (0.25, 0.25, 0.25, 0.25))],
                align_right=(1, 2, 3))
    tbl.setStyle(TableStyle([("FONT", (0, -1), (-1, -1), "Inter-SemiBold", 8), ("LINEABOVE", (0, -1), (-1, -1), 0.8, NAVY)]))
    if short:  # kỳ ngắn: biểu đồ và bảng cạnh nhau
        side = Table([[_chart(rep, W * 0.56), tbl]], colWidths=[W * 0.58, W * 0.42], hAlign="LEFT")
        side.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(side)
    else:  # kỳ dài: biểu đồ hết chiều ngang, bảng bên dưới (tự sang trang, lặp tiêu đề)
        story += [_chart(rep, W), Spacer(1, 6), tbl]

    story.append(CondPageBreak(55 * mm))  # tiêu đề mục không đứng một mình cuối trang
    story.append(Paragraph("2. Tự động chặn — lệnh SOC qua Teams", S["h2"]))
    ab_rows = [["Chỉ số", "Giá trị", "Chỉ số", "Giá trị"],
               ["Lệnh SOC nhận được", ab["requests"], "Thời gian SOC gửi → chặn xong (trung bình)", fmt_dur(ab["latency_avg"])],
               ["Tự chặn ngay", ab["auto"], "Thời gian SOC gửi → chặn xong (trung vị)", fmt_dur(ab["latency_median"])],
               ["Chờ rồi được duyệt", ab["approved"], "Thời gian SOC gửi → chặn xong (lâu nhất)", fmt_dur(ab["latency_max"])],
               ["Đang chờ duyệt", ab["pending"], "Đề xuất chặn IP thuộc whitelist", ab["whitelist"]],
               ["Bị từ chối", ab["rejected"], "Không hợp lệ / trùng", ab["invalid"] + ab["duplicate"]]]
    story.append(KeepTogether(_grid(ab_rows, [W * 0.3, W * 0.12, W * 0.43, W * 0.15], align_right=(1, 3))))

    story.append(CondPageBreak(55 * mm))  # tiêu đề mục không đứng một mình cuối trang
    story.append(Paragraph("3. Người / tác nhân thực hiện", S["h2"]))
    a_rows = [["Người / tác nhân", "Phương thức", "IP (duy nhất)", "Lượt chặn"]] + [
        [Paragraph(_esc(a["actor"]), S["cell"]), a["method_label"], a["ips"], a["actions"]] for a in rep["actors"]]
    if len(a_rows) == 1:
        a_rows.append(["Không có thao tác chặn trong kỳ", "", "", ""])
    story.append(_grid(a_rows, [W * 0.46, W * 0.24, W * 0.15, W * 0.15], align_right=(2, 3)))

    story.append(CondPageBreak(55 * mm))  # tiêu đề mục không đứng một mình cuối trang
    story.append(Paragraph(f"4. Danh sách IP bị chặn ({len(rep['ips'])} IP)", S["h2"]))
    story.append(Paragraph("Mỗi IP một dòng (gộp các firewall). Chi tiết từng lượt trên từng firewall có trong bản Excel.",
                           S["note"]))
    story.append(Spacer(1, 4))
    ip_rows = [["IP / CIDR", "Thời gian thực hiện", "Phương thức", "Người / nguồn", "Firewall", "Trạng thái", "Lý do"]]
    for i in rep["ips"]:
        status = Paragraph(f'<font color="{"#187A2C" if i["status"] == "Đang chặn" else "#474747"}">{i["status"]}</font>',
                           S["cell"])
        ip_rows.append([Paragraph(_esc(i["ip"]), S["mono"]), Paragraph(fmt(i["first"]), S["cell"]),
                        i["method_label"], Paragraph(_esc(", ".join(i["actors"])) + "<br/>"
                                                     f'<font color="#474747">{_esc(", ".join(i["sources"]))}</font>', S["cell"]),
                        Paragraph(_esc(", ".join(i["firewalls"])), S["cell"]), status,
                        Paragraph(_esc(i["reason"][:300]), S["cell"])])
    if len(ip_rows) == 1:
        ip_rows.append(["—", "", "", "Không có IP nào bị chặn trong kỳ", "", "", ""])
    story.append(_grid(ip_rows, [W * 0.12, W * 0.12, W * 0.09, W * 0.17, W * 0.15, W * 0.08, W * 0.27]))

    _NumberedCanvas.footer = (f"SOC Rapid Block · Báo cáo chặn IP · "
                              f"{fmt(rep['start'])[:10]} – {fmt(rep['end'])[:10]}")
    doc.build(story, canvasmaker=_NumberedCanvas)
    return buf.getvalue()
