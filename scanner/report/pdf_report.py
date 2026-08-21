import html
import io
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.models import Finding, Verdict
from loadtest.runner import LoadTestResult
from smoketest.runner import SmokeTestResult

SEVERITY_HEX = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#6b7280",
}

VERDICT_HEX = {
    "NOT_READY": ("#7f1d1d", "#fee2e2"),
    "READY_WITH_WARNINGS": ("#92400e", "#fef3c7"),
    "READY": ("#065f46", "#d1fae5"),
}

VERDICT_LABELS_TR = {
    "NOT_READY": "PRODUCTION'A HAZIR DEĞİL",
    "READY_WITH_WARNINGS": "UYARILARLA HAZIR",
    "READY": "PRODUCTION'A HAZIR",
}

# Turkish strings lean on i/ı, İ/I, ğ, ş -- glyphs the core PDF fonts (WinAnsi
# encoding) don't have. Prefer a real system TrueType font; fall back to the
# built-in Helvetica/Courier if none is found so PDF generation never hard-fails.
_FONT_CANDIDATES = [
    ("PLSans", r"C:\Windows\Fonts\arial.ttf", "PLSans-Bold", r"C:\Windows\Fonts\arialbd.ttf"),
    ("PLSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "PLSans-Bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("PLSans", "/Library/Fonts/Arial.ttf", "PLSans-Bold", "/Library/Fonts/Arial Bold.ttf"),
]
_MONO_CANDIDATES = [
    ("PLMono", r"C:\Windows\Fonts\consola.ttf"),
    ("PLMono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("PLMono", "/Library/Fonts/Courier New.ttf"),
]

FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"


def _register_fonts() -> None:
    global FONT_REGULAR, FONT_BOLD, FONT_MONO
    for regular_name, regular_path, bold_name, bold_path in _FONT_CANDIDATES:
        if os.path.isfile(regular_path) and os.path.isfile(bold_path):
            try:
                pdfmetrics.registerFont(TTFont(regular_name, regular_path))
                pdfmetrics.registerFont(TTFont(bold_name, bold_path))
                FONT_REGULAR, FONT_BOLD = regular_name, bold_name
                break
            except Exception:
                continue
    for mono_name, mono_path in _MONO_CANDIDATES:
        if os.path.isfile(mono_path):
            try:
                pdfmetrics.registerFont(TTFont(mono_name, mono_path))
                FONT_MONO = mono_name
                break
            except Exception:
                continue


_register_fonts()

PAGE_SIZE = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_SIZE[0] - 2 * MARGIN


def _esc(value) -> str:
    return html.escape(str(value), quote=False)


def _styles():
    return {
        "title": ParagraphStyle("PLTitle", fontName=FONT_BOLD, fontSize=20, leading=24, textColor=colors.HexColor("#111111")),
        "tagline": ParagraphStyle("PLTagline", fontName=FONT_BOLD, fontSize=8, leading=11, textColor=colors.HexColor("#6b7280"), spaceAfter=4),
        "meta": ParagraphStyle("PLMeta", fontName=FONT_REGULAR, fontSize=9, leading=13, textColor=colors.HexColor("#6b7280"), spaceAfter=6),
        "section": ParagraphStyle("PLSection", fontName=FONT_BOLD, fontSize=13, leading=16, textColor=colors.HexColor("#374151"), spaceBefore=12, spaceAfter=6),
        "verdict_label": ParagraphStyle("PLVerdictLabel", fontName=FONT_BOLD, fontSize=15, leading=18, spaceAfter=6),
        "verdict_counts": ParagraphStyle("PLVerdictCounts", fontName=FONT_REGULAR, fontSize=9.5, leading=14),
        "finding_header": ParagraphStyle("PLFindingHeader", fontName=FONT_REGULAR, fontSize=10.5, leading=14, spaceAfter=3),
        "finding_location": ParagraphStyle(
            "PLFindingLocation", fontName=FONT_MONO, fontSize=8.5, leading=12,
            textColor=colors.HexColor("#374151"), backColor=colors.HexColor("#f3f4f6"),
            borderPadding=(3, 5, 3, 5), spaceAfter=5,
        ),
        "finding_body": ParagraphStyle("PLFindingBody", fontName=FONT_REGULAR, fontSize=9.5, leading=13.5, spaceAfter=3),
        "finding_disposition": ParagraphStyle("PLFindingDisposition", fontName=FONT_REGULAR, fontSize=9, leading=13, textColor=colors.HexColor("#4b5563")),
        "no_findings": ParagraphStyle("PLNoFindings", fontName=FONT_BOLD, fontSize=10.5, textColor=colors.HexColor("#059669")),
        "stat_value": ParagraphStyle("PLStatValue", fontName=FONT_BOLD, fontSize=13, leading=16, alignment=1),
        "stat_label": ParagraphStyle("PLStatLabel", fontName=FONT_REGULAR, fontSize=7.5, leading=10, alignment=1, textColor=colors.HexColor("#6b7280")),
        "pill_line": ParagraphStyle("PLPillLine", fontName=FONT_REGULAR, fontSize=9, leading=13),
    }


def _finding_flowable(f: Finding, styles: dict) -> Table:
    color = colors.HexColor(SEVERITY_HEX.get(f.severity.value, "#6b7280"))
    header = Paragraph(
        f'<font color="{SEVERITY_HEX.get(f.severity.value, "#6b7280")}"><b>{_esc(f.severity.value.upper())}</b></font>'
        f'&nbsp;&nbsp;·&nbsp;&nbsp;{_esc(f.category.value)}'
        f'&nbsp;&nbsp;·&nbsp;&nbsp;<b>{_esc(f.title)}</b>'
        f'&nbsp;&nbsp;<font color="#9ca3af" size="7">#{_esc(f.id)}</font>',
        styles["finding_header"],
    )
    cell = [
        header,
        Paragraph(_esc(f.location), styles["finding_location"]),
        Paragraph(f"<b>Açıklama:</b> {_esc(f.description)}", styles["finding_body"]),
        Paragraph(f"<b>Kanıt:</b> {_esc(f.evidence)}", styles["finding_body"]),
        Paragraph(f"<b>Çözüm:</b> {_esc(f.remediation)}", styles["finding_body"]),
    ]
    if not f.is_open:
        cell.append(
            Paragraph(
                f"<b>Durum:</b> {_esc(f.disposition.value)} — {_esc(f.disposition_reason)}",
                styles["finding_disposition"],
            )
        )

    table = Table([[cell]], colWidths=[CONTENT_WIDTH])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffefe") if f.is_open else colors.HexColor("#fafafa")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#e5e7eb")),
                ("LINEBEFORE", (0, 0), (0, -1), 3, color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _verdict_block(verdict: Verdict, styles: dict) -> Table:
    fg_hex, bg_hex = VERDICT_HEX.get(verdict.status, ("#111111", "#eeeeee"))
    label = VERDICT_LABELS_TR.get(verdict.status, verdict.label)
    label_p = Paragraph(f'<font color="{fg_hex}"><b>{_esc(label)}</b></font>', styles["verdict_label"])

    parts = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        parts.append(f'<font color="{SEVERITY_HEX.get(sev)}"><b>{sev}:</b></font> {verdict.counts.get(sev, 0)}')
    if verdict.accepted_count:
        parts.append(f'<font color="#4b5563">İncelenmiş/Kabul Edilmiş: {verdict.accepted_count} (verdict\'e dahil değil)</font>')
    counts_p = Paragraph("&nbsp;&nbsp;&nbsp;".join(parts), styles["verdict_counts"])

    table = Table([[[label_p, counts_p]]], colWidths=[CONTENT_WIDTH])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_hex)),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    return table


def _load_test_block(result: LoadTestResult, styles: dict) -> list:
    if result.aborted_reason:
        warn_style = ParagraphStyle(
            "PLLoadAbort", fontName=FONT_BOLD, fontSize=9.5, leading=14,
            textColor=colors.HexColor("#92400e"), backColor=colors.HexColor("#fef3c7"),
            borderPadding=(8, 10, 8, 10),
        )
        return [
            Paragraph("Yük Testi — Başlatılmadı", styles["section"]),
            Paragraph(_esc(result.aborted_reason), warn_style),
        ]

    error_hex = "#dc2626" if result.error_rate > 0.05 else ("#d97706" if result.error_rate > 0 else "#059669")
    stats = [
        (str(result.concurrency), "eşzamanlı worker"),
        (f"{result.wall_time_s:.1f}s", "süre"),
        (str(result.total_requests), "toplam istek"),
        (f"{result.rps:.1f}", "istek/sn"),
        (f"%{result.error_rate * 100:.1f}", "hata oranı"),
    ]
    value_style = styles["stat_value"]
    error_value_style = ParagraphStyle("PLStatValueErr", parent=value_style, textColor=colors.HexColor(error_hex))
    row_values = []
    row_labels = []
    for i, (value, label) in enumerate(stats):
        style = error_value_style if label == "hata oranı" else value_style
        row_values.append(Paragraph(value, style))
        row_labels.append(Paragraph(label, styles["stat_label"]))

    col_w = CONTENT_WIDTH / len(stats)
    stat_table = Table([row_values, row_labels], colWidths=[col_w] * len(stats))
    stat_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))

    latency = Paragraph(
        f"<b>Gecikme (ms):</b> min {result.latency_min_ms:.0f} · ort {result.latency_avg_ms:.0f} · "
        f"p50 {result.latency_p50_ms:.0f} · p95 {result.latency_p95_ms:.0f} · p99 {result.latency_p99_ms:.0f} · "
        f"max {result.latency_max_ms:.0f}",
        styles["finding_body"],
    )
    codes = ", ".join(f"{code}: {count}" for code, count in sorted(result.status_codes.items()))
    codes_p = Paragraph(f"<b>Durum kodları:</b> {_esc(codes)}", styles["finding_body"])

    body = [
        Paragraph(f"<b>Hedef:</b> {_esc(result.method)} {_esc(result.target)}", styles["finding_body"]),
    ]
    if len(result.stages_ran) > 1:
        stages = " → ".join(f"{s['concurrency']}w/{s['duration_s']:.0f}s" for s in result.stages_ran)
        body.append(Paragraph(f"<b>Aşamalar:</b> {_esc(stages)}", styles["finding_body"]))
    body += [
        Spacer(1, 6),
        stat_table,
        Spacer(1, 6),
        latency,
        codes_p,
    ]
    if result.errors:
        errs = ", ".join(f"{name}: {count}" for name, count in sorted(result.errors.items()))
        body.append(Paragraph(f'<font color="#dc2626"><b>Bağlantı hataları:</b> {_esc(errs)}</font>', styles["finding_body"]))
    if result.passed is not None:
        pass_hex = "#059669" if result.passed else "#dc2626"
        parts = []
        if result.threshold_p95_ms is not None:
            parts.append(f"p95 ≤ {result.threshold_p95_ms:.0f}ms")
        if result.threshold_error_rate_pct is not None:
            parts.append(f"hata ≤ %{result.threshold_error_rate_pct:.1f}")
        body.append(
            Paragraph(
                f'<font color="{pass_hex}"><b>{"GEÇTİ" if result.passed else "KALDI"}</b></font> — Eşik: {_esc(", ".join(parts))}',
                styles["finding_body"],
            )
        )

    card = Table([[body]], colWidths=[CONTENT_WIDTH])
    card.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return [Paragraph("Yük Testi Sonucu", styles["section"]), card]


def _smoke_test_block(result: SmokeTestResult, styles: dict) -> list:
    rows = []
    for c in result.checks:
        ok_hex = "#059669" if c.ok else "#dc2626"
        detail = _esc(c.error) if c.error else str(c.status_code)
        expected = f" (beklenen {c.expected_status})" if c.expected_status is not None else ""
        rows.append(
            Paragraph(
                f'<font color="{ok_hex}"><b>{"OK" if c.ok else "FAIL"}</b></font> '
                f'<font face="{FONT_MONO}">{_esc(c.path)}</font> → {detail}{expected} '
                f'<font color="#6b7280" size="7.5">({c.latency_ms:.0f}ms)</font>',
                styles["finding_body"],
            )
        )

    pass_hex = "#059669" if result.passed else "#dc2626"
    title = Paragraph(
        f'Smoke Test <font color="{pass_hex}" size="10">({result.passed_count}/{len(result.checks)} geçti)</font>',
        styles["section"],
    )
    body = [Paragraph(f"<b>Hedef:</b> {_esc(result.base_url)}", styles["finding_body"]), Spacer(1, 4)] + rows
    card = Table([[body]], colWidths=[CONTENT_WIDTH])
    card.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return [title, card]


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(FONT_REGULAR, 7.5)
    canvas.setFillColor(colors.HexColor("#9ca3af"))
    canvas.drawString(MARGIN, 10 * mm, "VEXYRON — otomatik üretilmiş rapor")
    canvas.drawRightString(PAGE_SIZE[0] - MARGIN, 10 * mm, f"Sayfa {doc.page}")
    canvas.restoreState()


def render_pdf_report(
    findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> bytes:
    styles = _styles()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story = [
        Paragraph("VEXYRON Raporu", styles["title"]),
        Paragraph("SECURITY VALIDATION PLATFORM", styles["tagline"]),
        Paragraph(f"Hedef: {_esc(target)} &middot; Oluşturulma: {_esc(generated_at)}", styles["meta"]),
        _verdict_block(verdict, styles),
        Spacer(1, 10),
    ]

    if smoke_test_result:
        story += _smoke_test_block(smoke_test_result, styles)
        story.append(Spacer(1, 4))

    if load_test_result:
        story += _load_test_block(load_test_result, styles)
        story.append(Spacer(1, 4))

    open_findings = [f for f in findings if f.is_open]
    reviewed_findings = [f for f in findings if not f.is_open]

    if not findings:
        story.append(Paragraph("Hiçbir bulgu yok.", styles["no_findings"]))
    else:
        if open_findings:
            story.append(Paragraph(f"Açık Bulgular ({len(open_findings)})", styles["section"]))
            for f in open_findings:
                story.append(_finding_flowable(f, styles))
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("Açık bulgu yok.", styles["no_findings"]))

        if reviewed_findings:
            story.append(Paragraph(f"İncelenmiş / Kabul Edilmiş ({len(reviewed_findings)})", styles["section"]))
            for f in reviewed_findings:
                story.append(_finding_flowable(f, styles))
                story.append(Spacer(1, 8))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=PAGE_SIZE,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        title=f"VEXYRON Raporu — {target}",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def write_pdf_report(
    path: str, findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> None:
    data = render_pdf_report(
        findings, verdict, target, load_test_result=load_test_result, smoke_test_result=smoke_test_result
    )
    with open(path, "wb") as fh:
        fh.write(data)
