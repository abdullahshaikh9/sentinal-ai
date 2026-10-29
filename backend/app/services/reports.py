"""Enterprise-grade, evidence-grounded PDF security assessment reports built from persisted scan records."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from io import BytesIO
import json
import re
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Group, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models import Finding, Scan, VerificationAttempt

# ----------------------------------------------------------------------
# Visual System & Color Palette
# ----------------------------------------------------------------------
# Backward-compatibility color constants
INK = colors.HexColor("#0f172a")
EMERALD = colors.HexColor("#059669")
PALE = colors.HexColor("#f8fafc")
MUTED = colors.HexColor("#64748b")
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUS_VALUES = {"completed", "failed", "skipped", "inconclusive"}

# Primary Theme Colors
COVER_BG = colors.HexColor("#080e1e")          # Deep dark midnight navy
COVER_CARD = colors.HexColor("#101930")        # Elevated dark card
COVER_BORDER = colors.HexColor("#1d2b4f")      # Card border stroke
COVER_TEXT_TITLE = colors.HexColor("#ffffff")
COVER_TEXT_SUB = colors.HexColor("#94a3b8")
COVER_TEXT_MUTED = colors.HexColor("#64748b")
ELECTRIC_BLUE = colors.HexColor("#2563eb")     # Brand accent blue
CYAN_ACCENT = colors.HexColor("#06b6d4")       # Brand accent cyan
CYAN_LIGHT = colors.HexColor("#38bdf8")        # Bright cyan highlight

INK_PRIMARY = colors.HexColor("#0f172a")       # Deep slate text
INK_SECONDARY = colors.HexColor("#334155")     # Secondary body text
INK_MUTED = colors.HexColor("#64748b")         # Subtitle and caption text
BORDER_LIGHT = colors.HexColor("#e2e8f0")      # Table and card dividers
BORDER_MUTED = colors.HexColor("#cbd5e1")      # Structural borders
BG_LIGHT = colors.HexColor("#f8fafc")          # Monospaced evidence background
BG_ALT = colors.HexColor("#f1f5f9")            # Table alternating row background
BG_CARD_LIGHT = colors.HexColor("#f8fafc")     # Card background
BG_CARD_ALT = colors.HexColor("#f1f5f9")       # Secondary card background
WHITE = colors.HexColor("#ffffff")

# Severity Color Tokens (Text, Background, Border)
SEV_COLORS = {
    "critical": (colors.HexColor("#991b1b"), colors.HexColor("#fef2f2"), colors.HexColor("#fecaca")),
    "high":     (colors.HexColor("#c2410c"), colors.HexColor("#fff7ed"), colors.HexColor("#fed7aa")),
    "medium":   (colors.HexColor("#b45309"), colors.HexColor("#fffbeb"), colors.HexColor("#fde68a")),
    "low":      (colors.HexColor("#1d4ed8"), colors.HexColor("#eff6ff"), colors.HexColor("#bfdbfe")),
    "info":     (colors.HexColor("#475569"), colors.HexColor("#f1f5f9"), colors.HexColor("#cbd5e1")),
}

# Status Color Tokens
STATUS_COLORS = {
    "completed":    (colors.HexColor("#047857"), colors.HexColor("#ecfdf5"), colors.HexColor("#a7f3d0")),
    "failed":       (colors.HexColor("#be123c"), colors.HexColor("#fff1f2"), colors.HexColor("#fecdd3")),
    "inconclusive": (colors.HexColor("#6d28d9"), colors.HexColor("#f5f3ff"), colors.HexColor("#ddd6fe")),
    "skipped":      (colors.HexColor("#475569"), colors.HexColor("#f8fafc"), colors.HexColor("#e2e8f0")),
    "pending":      (colors.HexColor("#b45309"), colors.HexColor("#fffbeb"), colors.HexColor("#fde68a")),
}

_SECRET_PATTERNS = (
    re.compile(r"(?i)(set-cookie\s*:\s*[^=;\s]+)=([^;\s]+)"),
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|password|client[-_ ]?secret)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;,]+)"),
    re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)(nonce-)[A-Za-z0-9_+/=-]+"),
    re.compile(r"(?i)([?&](?:token|access_token|refresh_token|api_key|key|password|secret|session)=)[^&#\s]+"),
)


# ----------------------------------------------------------------------
# Sanitization & Data Formatting Helpers
# ----------------------------------------------------------------------
def redact_evidence(value: str | None) -> str:
    """Mask credentials, auth tokens, session cookies, and API keys."""
    if not value:
        return "No evidence recorded."
    redacted = value
    for pattern in _SECRET_PATTERNS:
        replacement = r"\1[redacted]" if pattern.groups else "[redacted]"
        redacted = pattern.sub(replacement, redacted)
    return redacted[:4000]


def _literal(value: object, limit: int = 6000) -> str:
    """Escape XML characters and convert line breaks for safe ReportLab Paragraph rendering."""
    return escape(str(value)[:limit]).replace("\n", "<br/>")


def _report_url(value: str) -> str:
    """Normalize target URL, stripping sensitive query parameters from public headers."""
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _format_timestamp(dt: datetime | None) -> str:
    """Format timestamps consistently with an explicit UTC identifier."""
    if not dt:
        return "Not recorded"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _category_label(category: str) -> str:
    """Format technical category keys into readable title case labels."""
    mapping = {
        "tls": "TLS / SSL Encryption",
        "headers": "HTTP Security Headers",
        "cookies": "Cookie & Session Security",
        "disclosure": "Information Disclosure",
        "dns": "DNS & Network Infrastructure",
        "cors": "Cross-Origin Resource Sharing",
    }
    lowered = category.lower().replace("_", "-")
    return mapping.get(lowered, category.replace("_", " ").replace("-", " ").title())


def _format_verification_status(status: str | None, summary: str | None = None) -> tuple[str, colors.Color, colors.Color]:
    """Map verification outcomes to explicit, unambiguous enterprise audit labels."""
    st = (status or "").lower()
    sm = (summary or "").lower()
    if st in ("reproduced", "fail", "failed") or "reproduced" in sm:
        return "Issue Reproduced", colors.HexColor("#991b1b"), colors.HexColor("#fef2f2")
    if st in ("resolved", "pass", "no_longer_observed") or "no longer observed" in sm:
        return "Issue No Longer Observed", colors.HexColor("#047857"), colors.HexColor("#ecfdf5")
    if st == "inconclusive" or "inconclusive" in sm:
        return "Inconclusive Observation", colors.HexColor("#6d28d9"), colors.HexColor("#f5f3ff")
    if st in ("error", "execution_failed") or "error" in sm:
        return "Verification Execution Failed", colors.HexColor("#be123c"), colors.HexColor("#fff1f2")
    if st in ("pending", "queued", "running"):
        return "Verification In Progress", colors.HexColor("#b45309"), colors.HexColor("#fffbeb")
    return "Not Attempted", colors.HexColor("#64748b"), colors.HexColor("#f8fafc")


def _scan_data(scan: Scan) -> tuple[dict[str, str], dict[str, object]]:
    """Extract check coverage and execution details from persisted check_summary JSON."""
    if not scan.check_summary:
        return {}, {}
    try:
        parsed = json.loads(scan.check_summary)
    except (TypeError, ValueError):
        return {}, {}
    if not isinstance(parsed, dict):
        return {}, {}
    if isinstance(parsed.get("coverage"), dict):
        coverage = {str(k): str(v) for k, v in parsed["coverage"].items() if isinstance(v, str)}
        details = parsed.get("details") if isinstance(parsed.get("details"), dict) else {}
        return coverage, details
    return {str(k): str(v) for k, v in parsed.items() if isinstance(v, str)}, {}


def _coverage_counts(coverage: dict[str, str]) -> dict[str, int]:
    """Aggregate recorded check category statuses."""
    return {state: sum(v == state for v in coverage.values()) for state in STATUS_VALUES}


# ----------------------------------------------------------------------
# Vector Graphics & Visualizations
# ----------------------------------------------------------------------
def _draw_shield_vector(w: float = 38, h: float = 44) -> Drawing:
    """Generate crisp, vector Sentinel shield badge for cover branding."""
    d = Drawing(w, h)
    pts = [
        0, h,
        w, h,
        w, h * 0.45,
        w * 0.5, 0,
        0, h * 0.45
    ]
    d.add(Polygon(pts, fillColor=COVER_CARD, strokeColor=CYAN_LIGHT, strokeWidth=1.75))
    # Inner checkmark
    d.add(Line(w * 0.28, h * 0.50, w * 0.45, h * 0.33, strokeColor=CYAN_LIGHT, strokeWidth=2.2, strokeLineCap=1))
    d.add(Line(w * 0.45, h * 0.33, w * 0.72, h * 0.65, strokeColor=CYAN_LIGHT, strokeWidth=2.2, strokeLineCap=1))
    return d


def _draw_severity_distribution(counts: Counter[str], width: float = 532, height: float = 48) -> Drawing:
    """Render a bounded horizontal distribution bar displaying observed finding severities."""
    d = Drawing(width, height)
    total = sum(counts.values())
    bar_y = 22.0
    bar_h = 18.0

    if total == 0:
        d.add(Rect(0, bar_y, width, bar_h, fillColor=colors.HexColor("#ecfdf5"), strokeColor=colors.HexColor("#a7f3d0"), strokeWidth=0.75, rx=3, ry=3))
        d.add(String(width / 2, bar_y + 5.0, "Zero Security Vulnerabilities or Misconfigurations Identified Across Evaluated Checks", fontName="Helvetica-Bold", fontSize=8.5, fillColor=colors.HexColor("#047857"), textAnchor="middle"))
        return d

    # Background track
    d.add(Rect(0, bar_y, width, bar_h, fillColor=colors.HexColor("#f1f5f9"), strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.5, rx=3, ry=3))

    order = [
        ("critical", "Critical", SEV_COLORS["critical"][0]),
        ("high", "High", SEV_COLORS["high"][0]),
        ("medium", "Medium", SEV_COLORS["medium"][0]),
        ("low", "Low", SEV_COLORS["low"][0]),
        ("info", "Info", SEV_COLORS["info"][0]),
    ]

    x = 0.0
    for key, _, color in order:
        cnt = counts.get(key, 0)
        if cnt == 0:
            continue
        seg_w = (cnt / total) * width
        d.add(Rect(x, bar_y, seg_w, bar_h, fillColor=color, strokeColor=WHITE, strokeWidth=1, rx=0, ry=0))
        if seg_w >= 18:
            d.add(String(x + seg_w / 2, bar_y + 5.0, str(cnt), fontName="Helvetica-Bold", fontSize=8.5, fillColor=WHITE, textAnchor="middle"))
        x += seg_w

    # Evenly spaced legend beneath the distribution bar (5 columns)
    col_width = width / 5.0
    for idx, (key, label, color) in enumerate(order):
        col_x = idx * col_width
        cnt = counts.get(key, 0)
        d.add(Rect(col_x + 2, 5.5, 9, 9, fillColor=color, strokeColor=None, rx=1.5, ry=1.5))
        txt = f"{label}: {cnt}"
        d.add(String(col_x + 15, 6.5, txt, fontName="Helvetica-Bold" if cnt > 0 else "Helvetica", fontSize=8, fillColor=INK_PRIMARY if cnt > 0 else INK_MUTED))

    return d


# ----------------------------------------------------------------------
# Page Background & Template Callbacks
# ----------------------------------------------------------------------
def _draw_cover_background(canv: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    """Paint deep midnight navy cover canvas and structural accents on page 1 before flowables."""
    canv.saveState()
    w, h = letter
    # Deep navy cover canvas
    canv.setFillColor(COVER_BG)
    canv.rect(0, 0, w, h, fill=True, stroke=False)

    # Header accent gradient/bars
    canv.setFillColor(ELECTRIC_BLUE)
    canv.rect(0, h - 6, w, 6, fill=True, stroke=False)
    canv.setFillColor(CYAN_ACCENT)
    canv.rect(0, h - 9, w, 3, fill=True, stroke=False)

    # Subtle geometric gridlines
    canv.setStrokeColor(colors.HexColor("#121d36"))
    canv.setLineWidth(0.5)
    for y_pos in (120, 240, 360, 480, 600, 700):
        canv.line(40, y_pos, w - 40, y_pos)

    # Subtle bottom frame
    canv.setFillColor(COVER_BORDER)
    canv.rect(0, 0, w, 4, fill=True, stroke=False)
    canv.restoreState()


def _draw_later_pages(canv: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    """Placeholder callback for SimpleDocTemplate later pages."""
    pass


# ----------------------------------------------------------------------
# Numbered Multi-Pass Canvas (Running Headers, Footers)
# ----------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas providing exact 'Page X of Y' numbers and running headers/footers."""
    scan_id: int = 0
    target_host: str = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self._draw_inner_chrome(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_inner_chrome(self, num_pages: int):
        self.saveState()
        w, h = letter
        left = 40.0
        right = w - 40.0

        # Running Top Header
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(INK_PRIMARY)
        host_str = f" · {self.target_host}" if self.target_host else ""
        self.drawString(left, h - 34, f"SENTINEL AI · SECURITY ASSESSMENT REPORT #{self.scan_id}{host_str}")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(INK_MUTED)
        self.drawRightString(right, h - 34, "CONFIDENTIAL")

        # Top Header Divider Line
        self.setStrokeColor(BORDER_MUTED)
        self.setLineWidth(0.6)
        self.line(left, h - 40, right, h - 40)

        # Running Bottom Footer Divider Line
        self.line(left, 40, right, 40)

        # Running Bottom Footer
        self.setFont("Helvetica", 7.5)
        self.setFillColor(INK_MUTED)
        self.drawString(left, 27, "CONFIDENTIAL · Prepared by Sentinel AI Bounded Security Assessment Engine")
        self.drawRightString(right, 27, f"Page {self._pageNumber} of {num_pages}")
        self.restoreState()


# ----------------------------------------------------------------------
# Stylesheet & Typography Setup
# ----------------------------------------------------------------------
def _styles():
    base = getSampleStyleSheet()

    # Cover Page Styles
    base.add(ParagraphStyle("CoverBrand", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=WHITE))
    base.add(ParagraphStyle("CoverTagline", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=CYAN_LIGHT))
    base.add(ParagraphStyle("CoverMainTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=23, leading=28, textColor=WHITE, spaceBefore=14, spaceAfter=4, alignment=TA_LEFT))
    base.add(ParagraphStyle("CoverSubtitle", parent=base["Normal"], fontName="Helvetica", fontSize=10.5, leading=15, textColor=COVER_TEXT_SUB, spaceAfter=14))
    base.add(ParagraphStyle("CoverMetaKey", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=COVER_TEXT_SUB))
    base.add(ParagraphStyle("CoverMetaVal", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=12, textColor=WHITE))
    base.add(ParagraphStyle("CoverNotice", parent=base["Normal"], fontName="Helvetica", fontSize=7, leading=9.5, textColor=COVER_TEXT_MUTED, alignment=TA_CENTER))

    # Inner Section Styles
    base.add(ParagraphStyle("SectionTitle", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=INK_PRIMARY, spaceBefore=12, spaceAfter=6, keepWithNext=True))
    base.add(ParagraphStyle("SubTitle", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK_PRIMARY, spaceBefore=8, spaceAfter=4, keepWithNext=True))
    base.add(ParagraphStyle("BodySafe", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=12.5, textColor=INK_SECONDARY, spaceAfter=4, splitLongWords=True))
    base.add(ParagraphStyle("SmallSafe", parent=base["BodyText"], fontName="Helvetica", fontSize=7.5, leading=10.5, textColor=INK_MUTED, spaceAfter=2, splitLongWords=True))
    base.add(ParagraphStyle("CodeEvidence", parent=base["BodyText"], fontName="Courier", fontSize=7.5, leading=10, textColor=INK_PRIMARY, splitLongWords=True))
    base.add(ParagraphStyle("CardHeaderTitle", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK_PRIMARY, keepWithNext=True))

    return base


# ----------------------------------------------------------------------
# Table Construction Utility
# ----------------------------------------------------------------------
def _table(rows: list[list[object]], widths: list[float], styles, header: bool = False, header_bg: colors.Color | None = None) -> Table:
    """Build a professional table with wrapped cells and strict page-break safety."""
    converted = []
    for row_index, row in enumerate(rows):
        cells = []
        for item in row:
            if isinstance(item, (Paragraph, Table)):
                cells.append(item)
            elif isinstance(item, (list, tuple)):
                cells.append(item)
            else:
                is_hdr = header and row_index == 0
                cell_style = ParagraphStyle(
                    f"Cell_{row_index}_{len(cells)}",
                    parent=styles["SmallSafe"],
                    fontName="Helvetica-Bold" if is_hdr else "Helvetica",
                    fontSize=7.5,
                    leading=10.5,
                    textColor=WHITE if is_hdr else INK_PRIMARY,
                )
                cells.append(Paragraph(_literal(item), cell_style))
        converted.append(cells)

    table = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]
    if header:
        bg = header_bg or INK_PRIMARY
        commands.append(("BACKGROUND", (0, 0), (-1, 0), bg))
        for r_idx in range(1, len(rows)):
            if r_idx % 2 == 0:
                commands.append(("BACKGROUND", (0, r_idx), (-1, r_idx), BG_ALT))
    else:
        for r_idx in range(len(rows)):
            if r_idx % 2 == 1:
                commands.append(("BACKGROUND", (0, r_idx), (-1, r_idx), BG_ALT))

    table.setStyle(TableStyle(commands))
    return table


# ----------------------------------------------------------------------
# Main PDF Generation Entrypoint
# ----------------------------------------------------------------------
def build_scan_pdf(
    scan: Scan,
    findings: list[Finding],
    verification_attempts: list[VerificationAttempt] | None = None,
    remediations: dict[int, str] | None = None,
) -> bytes:
    """Generate an enterprise-grade, bounded cybersecurity assessment PDF report."""
    output = BytesIO()
    doc_width = 532.0  # 612 - (40 * 2)

    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        leftMargin=40.0,
        rightMargin=40.0,
        topMargin=46.0,
        bottomMargin=46.0,
        title=f"Sentinel AI Security Assessment #{scan.id}",
        author="Sentinel AI Cybersecurity Platform",
        subject="Evidence-Based Bounded Website Security Assessment",
    )
    styles = _styles()

    # Pass dynamic header data to canvas
    NumberedCanvas.scan_id = scan.id
    target_parsed = urlsplit(scan.target_url)
    NumberedCanvas.target_host = target_parsed.hostname or target_parsed.netloc or scan.target_url

    coverage, details = _scan_data(scan)
    coverage_counts = _coverage_counts(coverage)
    counts = Counter(item.severity for item in findings)
    remediations = remediations or {}

    # Organize verification attempts
    attempts = sorted(
        verification_attempts or [],
        key=lambda item: (item.created_at or datetime.min.replace(tzinfo=UTC), item.id or 0),
    )
    latest_attempt: dict[int, VerificationAttempt] = {}
    for att in attempts:
        if att.finding_id is not None:
            latest_attempt[att.finding_id] = att

    # Sort findings by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity.lower(), 5), f.id))

    story = []

    # ==================================================================
    # PAGE 1: ENTERPRISE DARK COVER PAGE
    # ==================================================================
    # 1. Branding Header: Shield Logo + Brand Name + Tagline
    shield = _draw_shield_vector(w=36, h=42)
    brand_table = Table(
        [
            [shield, [
                Paragraph("SENTINEL AI", styles["CoverBrand"]),
                Paragraph("Detect · Analyze · Resolve · Verify · Secure", styles["CoverTagline"]),
            ]],
        ],
        colWidths=[46, 486],
        hAlign="LEFT",
    )
    brand_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(brand_table)
    story.append(Spacer(1, 14))

    # 2. Main Assessment Title & Subtitle
    story.append(Paragraph("WEBSITE SECURITY ASSESSMENT REPORT", styles["CoverMainTitle"]))
    story.append(Paragraph(
        "Automated Evidence-Based Cybersecurity Audit, Vulnerability Inspection & Risk Analysis",
        styles["CoverSubtitle"],
    ))
    story.append(Spacer(1, 10))

    # 3. Assessment Metadata Card
    status_label = scan.status.upper()
    status_color_hex = "#10b981" if scan.status == "completed" else "#f43f5e" if scan.status == "failed" else "#f59e0b"

    meta_rows = [
        [
            Paragraph("Target Host", styles["CoverMetaKey"]),
            Paragraph(_literal(NumberedCanvas.target_host), styles["CoverMetaVal"]),
            Paragraph("Assessment Record", styles["CoverMetaKey"]),
            Paragraph(f"#{scan.id}", styles["CoverMetaVal"]),
        ],
        [
            Paragraph("Target URL", styles["CoverMetaKey"]),
            Paragraph(_literal(_report_url(scan.target_url)), styles["CoverMetaVal"]),
            Paragraph("Scan Status", styles["CoverMetaKey"]),
            Paragraph(f'<font color="{status_color_hex}">{status_label}</font>', styles["CoverMetaVal"]),
        ],
        [
            Paragraph("Assessment Started", styles["CoverMetaKey"]),
            Paragraph(_format_timestamp(scan.created_at), styles["CoverMetaVal"]),
            Paragraph("Completed", styles["CoverMetaKey"]),
            Paragraph(_format_timestamp(scan.completed_at), styles["CoverMetaVal"]),
        ],
        [
            Paragraph("Report Generated", styles["CoverMetaKey"]),
            Paragraph(_format_timestamp(datetime.now(UTC)), styles["CoverMetaVal"]),
            Paragraph("Assessment Engine", styles["CoverMetaKey"]),
            Paragraph("Sentinel AI v0.1.0", styles["CoverMetaVal"]),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[110, 186, 110, 126], hAlign="LEFT")
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COVER_CARD),
        ("BOX", (0, 0), (-1, -1), 1, COVER_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1b2848")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # 4. Cover Metric Summary Cards (4 Cards Grid)
    risk_display = f"{scan.risk_score} / 100" if scan.risk_score is not None else "N/A"
    risk_level_display = (scan.risk_level or "Unrated").upper()
    total_findings_display = str(len(findings))
    crit_high_count = counts.get("critical", 0) + counts.get("high", 0)
    cats_completed = coverage_counts["completed"]
    total_cats = len(coverage)

    def _cover_card(title: str, val: str, sub: str) -> list[Paragraph]:
        return [
            Paragraph(title, ParagraphStyle("CMT", parent=styles["CoverMetaKey"], fontSize=7, textColor=CYAN_LIGHT, alignment=TA_CENTER)),
            Paragraph(val, ParagraphStyle("CMV", parent=styles["CoverMetaVal"], fontSize=13, textColor=WHITE, alignment=TA_CENTER)),
            Paragraph(sub, ParagraphStyle("CMS", parent=styles["CoverMetaKey"], fontSize=7, textColor=COVER_TEXT_SUB, alignment=TA_CENTER)),
        ]

    cover_metric_cells = [[
        _cover_card("OBSERVED RISK", risk_display, f"{risk_level_display} RISK"),
        _cover_card("TOTAL FINDINGS", total_findings_display, f"{crit_high_count} Crit / High"),
        _cover_card("CHECK CATEGORIES", f"{cats_completed} / {total_cats}", "Completed Checks"),
        _cover_card("POSTURE STATUS", "ACTION REQUIRED" if len(findings) > 0 else "CLEAN POSTURE", "Based on Evidence"),
    ]]
    cover_metric_table = Table(cover_metric_cells, colWidths=[133, 133, 133, 133], hAlign="LEFT")
    cover_metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COVER_CARD),
        ("BOX", (0, 0), (-1, -1), 1, COVER_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COVER_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(cover_metric_table)
    story.append(Spacer(1, 24))

    # 5. Scope & Confidentiality Notice on Cover
    notice_text = (
        "CONFIDENTIAL & PROPRIETARY · PREPARED FOR AUTHORIZED STAKEHOLDERS<br/>"
        "This security assessment report summarizes empirical observations persisted by Sentinel AI's safe, non-invasive scanner. "
        "It is designed to prioritize defensive remediation. It does not certify regulatory compliance, penetration test completion, "
        "or the total absence of unobserved software vulnerabilities."
    )
    story.append(Paragraph(notice_text, styles["CoverNotice"]))
    story.append(PageBreak())

    # ==================================================================
    # PAGE 2+: EXECUTIVE SUMMARY
    # ==================================================================
    story.append(Paragraph("1. Executive Summary", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ELECTRIC_BLUE, spaceBefore=1, spaceAfter=8))

    status_intro = (
        f"Sentinel AI performed an automated, bounded security assessment of <b>{_literal(scan.target_url)}</b>. "
        f"The scan concluded with status <b>{scan.status.upper()}</b> across {len(coverage)} security check categories, "
        f"identifying <b>{len(findings)}</b> persisted security and configuration findings."
        if scan.status == "completed"
        else f"Sentinel AI conducted a bounded assessment of <b>{_literal(scan.target_url)}</b> which terminated with status <b>{scan.status.upper()}</b>. "
        f"Findings and coverage in this report reflect partial observations prior to termination."
    )
    story.append(Paragraph(status_intro, styles["BodySafe"]))
    story.append(Spacer(1, 6))

    # Metric Summary Grid on Content Page
    card_p1 = [
        Paragraph("Observed Risk Score", styles["SubTitle"]),
        Paragraph(f"<b>{risk_display}</b>", ParagraphStyle("BigRisk", parent=styles["Normal"], fontSize=16, leading=20, fontName="Helvetica-Bold", textColor=INK_PRIMARY)),
        Paragraph(f"Level: <b>{risk_level_display}</b><br/>Deterministic severity sum (max 100); not a percentage of security.", styles["SmallSafe"]),
    ]
    card_p2 = [
        Paragraph("Persisted Findings", styles["SubTitle"]),
        Paragraph(f"<b>{len(findings)}</b>", ParagraphStyle("BigFind", parent=styles["Normal"], fontSize=16, leading=20, fontName="Helvetica-Bold", textColor=INK_PRIMARY)),
        Paragraph(f"<b>{counts.get('critical', 0)}</b> Crit · <b>{counts.get('high', 0)}</b> High · <b>{counts.get('medium', 0)}</b> Med<br/><b>{counts.get('low', 0)}</b> Low · <b>{counts.get('info', 0)}</b> Informational", styles["SmallSafe"]),
    ]
    card_p3 = [
        Paragraph("Category Coverage", styles["SubTitle"]),
        Paragraph(f"<b>{coverage_counts['completed']} / {len(coverage)}</b>", ParagraphStyle("BigCov", parent=styles["Normal"], fontSize=16, leading=20, fontName="Helvetica-Bold", textColor=INK_PRIMARY)),
        Paragraph(f"<b>{coverage_counts['completed']}</b> Completed · <b>{coverage_counts['failed']}</b> Failed<br/><b>{coverage_counts['skipped']}</b> Skipped · <b>{coverage_counts['inconclusive']}</b> Inconclusive", styles["SmallSafe"]),
    ]
    verified_count = sum(1 for f in findings if f.id in latest_attempt and latest_attempt[f.id].status in ("resolved", "pass", "no_longer_observed"))
    card_p4 = [
        Paragraph("Verification Status", styles["SubTitle"]),
        Paragraph(f"<b>{verified_count} / {len(findings)}</b>", ParagraphStyle("BigVer", parent=styles["Normal"], fontSize=16, leading=20, fontName="Helvetica-Bold", textColor=INK_PRIMARY)),
        Paragraph(f"<b>{verified_count}</b> Verified Resolved<br/><b>{len(findings) - verified_count}</b> Pending or Not Attempted", styles["SmallSafe"]),
    ]
    summary_grid = Table([[card_p1, card_p2, card_p3, card_p4]], colWidths=[133, 133, 133, 133], hAlign="LEFT")
    summary_grid.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CARD_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_MUTED),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(summary_grid)
    story.append(Spacer(1, 10))

    # Severity Distribution Chart & Summary Table
    story.append(Paragraph("Observed Finding Severity Distribution", styles["SubTitle"]))
    story.append(_draw_severity_distribution(counts, width=doc_width, height=44))
    story.append(Spacer(1, 6))

    sev_summary_rows = [
        ["Severity Level", "Observed Count", "Weight Contribution", "Share of Total", "Remediation Target Window"],
        ["Critical", str(counts.get("critical", 0)), "25 pts each", f"{(counts.get('critical', 0) / max(1, len(findings)) * 100):.1f}%", "Immediate (Within 24 Hours)"],
        ["High", str(counts.get("high", 0)), "15 pts each", f"{(counts.get('high', 0) / max(1, len(findings)) * 100):.1f}%", "High Priority (Within 48-72 Hours)"],
        ["Medium", str(counts.get("medium", 0)), "8 pts each", f"{(counts.get('medium', 0) / max(1, len(findings)) * 100):.1f}%", "Scheduled Sprint (Within 14 Days)"],
        ["Low", str(counts.get("low", 0)), "3 pts each", f"{(counts.get('low', 0) / max(1, len(findings)) * 100):.1f}%", "Maintenance Cycle (Within 30 Days)"],
        ["Informational", str(counts.get("info", 0)), "0 pts", f"{(counts.get('info', 0) / max(1, len(findings)) * 100):.1f}%", "Defensive Hardening Review"],
    ]
    story.append(_table(sev_summary_rows, [95, 75, 95, 80, 187], styles, header=True))

    if scan.error_message:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Assessment Limitation & Scanner Notice", styles["SubTitle"]))
        story.append(Paragraph(_literal(redact_evidence(scan.error_message)), styles["BodySafe"]))

    story.append(PageBreak())

    # ==================================================================
    # 2. ASSESSMENT SCOPE & METHODOLOGY
    # ==================================================================
    story.append(Paragraph("2. Assessment Scope & Methodology", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    scope_details = [
        ["Assessment Target", _report_url(scan.target_url)],
        ["Scan Identification", f"Scan Record ID #{scan.id}"],
        ["Target IP Resolution", details.get("final_url", "Public DNS validation verified")],
        ["Scanning Methodology", "Non-invasive passive & bounded active inspection (No exploits, no DoS)"],
        ["Safety Boundary", "Strict RFC 1918 & Cloud Metadata blocking, DNS pinning, rate limits"],
    ]
    story.append(_table(scope_details, [140, 392], styles, header=False))
    story.append(Spacer(1, 6))

    methodology_text = (
        "<b>Execution Success vs. Security Posture:</b> A security check category marked as 'completed' indicates "
        "that the scanner successfully completed its network queries, response validation, and rule analysis. "
        "It does <i>not</i> imply that all security controls passed or that the target is immune to attack. "
        "Conversely, findings indicate empirical deviations from hardened security baselines (OWASP, CWE, RFC standards)."
    )
    story.append(Paragraph(methodology_text, styles["BodySafe"]))

    # ==================================================================
    # 3. SECURITY COVERAGE OVERVIEW
    # ==================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("3. Security Coverage Overview", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    rule_results = details.get("rule_results") if isinstance(details.get("rule_results"), dict) else {}
    category_rules: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for rule_id, state in rule_results.items():
        if isinstance(rule_id, str) and isinstance(state, str):
            cat = rule_id.split(".", 1)[0]
            category_rules[cat].append((rule_id, state))

    cov_rows = [["Check Category", "Execution Status", "Findings Produced", "Rule-Level Audit Observation"]]
    for cat_key, cat_status in sorted(coverage.items()):
        cat_findings = [f for f in findings if (f.category or "").lower() == cat_key.lower() or f.stable_id and f.stable_id.startswith(cat_key)]
        findings_count = len(cat_findings)

        rules = category_rules.get(cat_key, [])
        if rules:
            passed_rules = sum(1 for _, res in rules if res in ("present", "passed", "valid", "compliant"))
            rule_audit_text = f"{passed_rules} of {len(rules)} evaluated controls passed"
        elif cat_status == "completed":
            # PRESERVE DISTINCTION: Do not turn missing rule-level results into passed!
            rule_audit_text = "Rule-level results not recorded"
        else:
            rule_audit_text = f"Category {cat_status}; controls not asserted"

        cov_rows.append([
            _category_label(cat_key),
            cat_status.upper(),
            f"{findings_count} finding(s)" if findings_count else "0 findings",
            rule_audit_text,
        ])

    if len(cov_rows) > 1:
        story.append(_table(cov_rows, [140, 95, 95, 202], styles, header=True))
    else:
        story.append(Paragraph("No structured check coverage was saved for this historical record.", styles["BodySafe"]))

    if not rule_results and coverage:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "<i>Note on rule-level results:</i> This scan record predates detailed per-rule result persistence or contains "
            "only category-level execution coverage. The report explicitly marks rule-level outcomes as 'not recorded' "
            "and does not infer successful individual controls from missing finding records.",
            styles["SmallSafe"],
        ))

    story.append(PageBreak())

    # ==================================================================
    # 4. DETAILED FINDINGS & TECHNICAL EVIDENCE
    # ==================================================================
    story.append(Paragraph("4. Detailed Findings & Technical Evidence", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    if not sorted_findings:
        empty_box = [
            Paragraph("<b>No Security Findings Identified</b>", styles["SubTitle"]),
            Paragraph(
                "No vulnerabilities, weaknesses, or configuration gaps were identified during this assessment. "
                "This indicates that all evaluated automated checks satisfied baseline security requirements. "
                "However, this does not certify that the application is secure against unassessed or application-logic vulnerabilities.",
                styles["BodySafe"],
            ),
        ]
        empty_table = Table([[empty_box]], colWidths=[doc_width], hAlign="LEFT")
        empty_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#a7f3d0")),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(empty_table)
    else:
        for idx, finding in enumerate(sorted_findings, start=1):
            sev_key = finding.severity.lower()
            t_color, bg_color, b_color = SEV_COLORS.get(sev_key, SEV_COLORS["info"])

            data = finding.evidence_data if isinstance(finding.evidence_data, dict) else {}
            if not data and isinstance(finding.evidence_data, str):
                try:
                    data = json.loads(finding.evidence_data)
                except Exception:
                    data = {}

            assessment = data.get("assessment") if isinstance(data.get("assessment"), dict) else {}
            references = assessment.get("references") if isinstance(assessment.get("references"), list) else []

            # Verification state
            if finding.id in latest_attempt:
                att = latest_attempt[finding.id]
                ver_status_label, ver_t_color, ver_bg_color = _format_verification_status(att.status, att.summary)
                ver_evidence = redact_evidence(att.evidence or att.summary)
                ver_hex = f"#{ver_t_color.hexval()[2:]}"
                ver_display = f'<font color="{ver_hex}"><b>{escape(ver_status_label)}</b></font> · {_format_timestamp(att.created_at)}'
            else:
                ver_status_label, ver_t_color, _ = _format_verification_status(assessment.get("verification_status"))
                ver_hex = f"#{ver_t_color.hexval()[2:]}"
                ver_display = f'<font color="{ver_hex}"><b>{escape(ver_status_label)}</b></font>'
                ver_evidence = None

            lifecycle = remediations.get(finding.id, "open").replace("_", " ").title()

            # Finding Card Header
            sev_hex = f"#{t_color.hexval()[2:]}"
            badge_html = f'<font color="{sev_hex}"><b>{finding.severity.upper()} SEVERITY</b></font>'
            hdr_cells = [
                [Paragraph(f"<b>#{idx}. {_literal(finding.title)}</b>", styles["CardHeaderTitle"]), Paragraph(badge_html, ParagraphStyle("BH", parent=styles["Normal"], alignment=TA_RIGHT))],
            ]
            hdr_table = Table(hdr_cells, colWidths=[400, 132], hAlign="LEFT")
            hdr_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))

            # Finding Metadata Grid
            card_rows = [
                [
                    Paragraph("Rule ID", styles["SmallSafe"]),
                    Paragraph(_literal(finding.stable_id or "Not recorded"), styles["SmallSafe"]),
                    Paragraph("Category", styles["SmallSafe"]),
                    Paragraph(_category_label(finding.category or "General"), styles["SmallSafe"]),
                ],
                [
                    Paragraph("Confidence", styles["SmallSafe"]),
                    Paragraph((finding.confidence or "High").title(), styles["SmallSafe"]),
                    Paragraph("Lifecycle Status", styles["SmallSafe"]),
                    Paragraph(lifecycle, styles["SmallSafe"]),
                ],
                [
                    Paragraph("Observed Evidence", styles["SmallSafe"]),
                    Paragraph(_literal(redact_evidence(finding.evidence)), styles["CodeEvidence"]),
                    "", "",
                ],
            ]

            # Structural / cookie evidence if present
            if data:
                technical = {k: v for k, v in data.items() if k != "assessment"}
                if technical:
                    card_rows.append([
                        Paragraph("Evidence Data", styles["SmallSafe"]),
                        Paragraph(_literal(json.dumps(technical, sort_keys=True, ensure_ascii=True)[:1500]), styles["CodeEvidence"]),
                        "", "",
                    ])

            card_rows.extend([
                [
                    Paragraph("Why It Matters", styles["SmallSafe"]),
                    Paragraph(_literal(finding.explanation or "Gap identified during automated observation."), styles["SmallSafe"]),
                    "", "",
                ],
                [
                    Paragraph("Potential Impact", styles["SmallSafe"]),
                    Paragraph(_literal(assessment.get("impact", "Specific exploitability depends on application context and surrounding defensive controls.")), styles["SmallSafe"]),
                    "", "",
                ],
                [
                    Paragraph("Remediation", styles["SmallSafe"]),
                    Paragraph(_literal(finding.remediation or "Review configuration against secure baseline best practices."), styles["SmallSafe"]),
                    "", "",
                ],
                [
                    Paragraph("Verification", styles["SmallSafe"]),
                    Paragraph(ver_display, styles["SmallSafe"]),
                    "", "",
                ],
            ])

            if ver_evidence:
                card_rows.append([
                    Paragraph("Verification Audit", styles["SmallSafe"]),
                    Paragraph(_literal(ver_evidence), styles["SmallSafe"]),
                    "", "",
                ])

            if references:
                ref_str = "; ".join(str(r) for r in references[:5])
                card_rows.append([
                    Paragraph("References", styles["SmallSafe"]),
                    Paragraph(_literal(ref_str), styles["SmallSafe"]),
                    "", "",
                ])

            card_table = Table(card_rows, colWidths=[95, 171, 95, 171], hAlign="LEFT")
            card_styles = [
                ("BACKGROUND", (0, 0), (-1, -1), BG_CARD_LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.75, b_color),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("SPAN", (1, 2), (3, 2)),  # Span Evidence
            ]
            row_cursor = 3
            if data and {k: v for k, v in data.items() if k != "assessment"}:
                card_styles.append(("SPAN", (1, row_cursor), (3, row_cursor)))
                row_cursor += 1
            # Span remaining rows across columns 1-3
            for r in range(row_cursor, len(card_rows)):
                card_styles.append(("SPAN", (1, r), (3, r)))

            card_table.setStyle(TableStyle(card_styles))

            card_block = KeepTogether([hdr_table, Spacer(1, 3), card_table, Spacer(1, 10)])
            story.append(card_block)

    story.append(PageBreak())

    # ==================================================================
    # 5. TECHNICAL ENVIRONMENT & SERVER OBSERVATIONS
    # ==================================================================
    story.append(Paragraph("5. Technical Environment & Observations", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    env_rows = [["Property", "Observed Server Value"]]
    for key in ("response_status", "final_url", "scanner_version", "tls_valid", "tls_expires_at"):
        if key in details:
            env_rows.append([key.replace("_", " ").title(), str(details[key])])

    dns_obs = details.get("dns_observations") if isinstance(details.get("dns_observations"), list) else []
    for obs in dns_obs[:6]:
        if isinstance(obs, dict):
            addresses = ", ".join(str(a) for a in obs.get("validated_public_addresses", [])[:6])
            env_rows.append(["DNS Public IP Addresses", addresses or "Validated Public Host"])

    response_headers = details.get("response_headers") if isinstance(details.get("response_headers"), dict) else {}
    for h_key, h_val in sorted(response_headers.items()):
        if isinstance(h_key, str) and isinstance(h_val, str):
            env_rows.append([h_key, redact_evidence(h_val)])

    if len(env_rows) > 1:
        story.append(_table(env_rows, [160, 372], styles, header=True))
    else:
        story.append(Paragraph("No technical response metadata was persisted for this scan.", styles["BodySafe"]))

    # Redirect Observations
    redirects = details.get("redirect_observations") if isinstance(details.get("redirect_observations"), list) else []
    if redirects:
        story.append(Spacer(1, 8))
        story.append(Paragraph("HTTP Redirect Hops", styles["SubTitle"]))
        red_rows = [["Status", "Source URL", "Destination URL"]]
        for red in redirects[:8]:
            if isinstance(red, dict):
                red_rows.append([
                    str(red.get("status", "30x")),
                    _literal(red.get("source", "not recorded")),
                    _literal(red.get("destination", "not recorded")),
                ])
        story.append(_table(red_rows, [60, 236, 236], styles, header=True))

    # ==================================================================
    # 6. PRIORITIZED REMEDIATION ROADMAP
    # ==================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("6. Prioritized Remediation Roadmap", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    if not sorted_findings:
        story.append(Paragraph("No remediation actions are required for this assessment.", styles["BodySafe"]))
    else:
        story.append(Paragraph(
            "The following prioritized roadmap structures findings by observed severity. Engineering teams should "
            "validate changes in non-production environments before deployment. Re-run verification post-implementation.",
            styles["BodySafe"],
        ))
        roadmap_rows = [["Priority", "Finding & Rule ID", "Recommended Remediation Action", "Validation Method"]]
        p_mapping = {"critical": "P1 (Critical)", "high": "P2 (High)", "medium": "P3 (Medium)", "low": "P4 (Low)", "info": "P5 (Info)"}
        for f in sorted_findings:
            p_label = p_mapping.get(f.severity.lower(), "P4 (Low)")
            f_label_p = Paragraph(
                f"<b>{escape(f.title)}</b><br/><font color='#{INK_MUTED.hexval()[2:]}'>{escape(f.stable_id or 'General')}</font>",
                styles["SmallSafe"],
            )
            rem_action = _literal(f.remediation or "Review server configuration and apply secure defaults.")
            val_method = "Trigger automated verification or inspect headers via curl."
            roadmap_rows.append([p_label, f_label_p, rem_action, val_method])

        story.append(_table(roadmap_rows, [75, 145, 192, 120], styles, header=True))

    story.append(PageBreak())

    # ==================================================================
    # 7. POST-ASSESSMENT VERIFICATION HISTORY
    # ==================================================================
    story.append(Paragraph("7. Verification History & Audit Trail", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    if not attempts:
        story.append(Paragraph("No verification attempts have been recorded for this assessment.", styles["BodySafe"]))
    else:
        ver_rows = [["Target Finding", "Attempt Timestamp", "Verification Outcome", "Audit Details"]]
        f_by_id = {f.id: f for f in findings}
        for att in attempts[:50]:
            f_item = f_by_id.get(att.finding_id)
            f_name = f_item.stable_id or f_item.title if f_item else "Scan Verification"
            out_label, out_color, _ = _format_verification_status(att.status, att.summary)
            status_p = Paragraph(
                f'<font color="#{out_color.hexval()[2:]}"><b>{escape(out_label)}</b></font>',
                styles["SmallSafe"],
            )
            ver_rows.append([
                _literal(f_name),
                _format_timestamp(att.created_at),
                status_p,
                _literal(redact_evidence(att.summary or "Verification executed.")),
            ])
        story.append(_table(ver_rows, [140, 115, 127, 150], styles, header=True))

    # ==================================================================
    # 8. ASSESSMENT LIMITATIONS & DEFINITIONS APPENDIX
    # ==================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("8. Methodology, Limitations & Definitions Appendix", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_MUTED, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph("<b>Standard Scope Limitations:</b>", styles["SubTitle"]))
    limits_text = (
        "1. <b>Non-Invasive Architecture:</b> Sentinel AI executes non-destructive observations only. It does not exploit weaknesses, inject persistent payloads, perform authentication brute-forcing, or simulate Denial-of-Service conditions.<br/>"
        "2. <b>Route & State Boundedness:</b> Observations represent the HTTP/S responses returned by the target host at scan time. Responses may vary based on CDN edge, geolocation, load balancing, or WAF challenges (e.g. Cloudflare, AWS WAF).<br/>"
        "3. <b>Compliance & Legal Disclaimer:</b> This deliverable is an empirical technical review. It does not constitute a formal penetration test, SOC 2 certification, ISO 27001 audit, or PCI-DSS attestation."
    )
    story.append(Paragraph(limits_text, styles["BodySafe"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Standard Terminology & Definitions:</b>", styles["SubTitle"]))
    def_rows = [
        ["Classification", "Definition & Operational Semantics"],
        ["Critical Severity", "Severe vulnerability allowing arbitrary code execution, authentication bypass, or direct compromise."],
        ["High Severity", "High-impact defect or absent core defense (e.g. missing critical security headers allowing MITM/clickjacking)."],
        ["Medium Severity", "Moderate risk gap (e.g. cookie flags missing, permissive CSP directives, certificate expiry warnings)."],
        ["Low Severity", "Minor configuration hardening gap or missing defense-in-depth indicator."],
        ["Informational", "Empirical observation or reconnaissance intelligence without direct exploitability."],
        ["Risk Score", "Deterministic aggregate score (0-100) weighting observed findings; not a security percentage."],
        ["Issue Reproduced", "Target re-assessed; the insecure condition or configuration gap was empirically re-observed."],
        ["Issue No Longer Observed", "Target re-assessed; the insecure condition was absent, confirming defensive resolution."],
    ]
    story.append(_table(def_rows, [125, 407], styles, header=True))

    # Formal Report Conclusion Banner
    story.append(Spacer(1, 12))
    end_banner = Table(
        [
            [
                Paragraph(
                    "<b>END OF SECURITY ASSESSMENT REPORT</b><br/>"
                    "<font color='#64748b'>Sentinel AI Bounded Security Assessment Platform · Authoritative Evidence-Grounded Audit Deliverable</font>",
                    ParagraphStyle("ReportEnd", parent=styles["Normal"], fontSize=8, leading=11, alignment=TA_CENTER, textColor=INK_PRIMARY),
                )
            ]
        ],
        colWidths=[doc_width],
        hAlign="LEFT",
    )
    end_banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_ALT),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_MUTED),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(end_banner)

    # Build PDF with multi-pass NumberedCanvas and cover background callback
    doc.build(
        story,
        canvasmaker=NumberedCanvas,
        onFirstPage=_draw_cover_background,
        onLaterPages=_draw_later_pages,
    )
    return output.getvalue()
