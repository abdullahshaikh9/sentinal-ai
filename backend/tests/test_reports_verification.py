import base64
import zlib
from datetime import UTC, datetime
import re
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Finding, Scan, VerificationAttempt
from app.services.reports import build_scan_pdf, redact_evidence
from app.services.scanning.scanner import FindingResult, ScanReport
from app.services import verification


def test_pdf_report_is_generated_from_persisted_values_and_redacts_secrets() -> None:
    scan = Scan(id=7, target_url="https://public.example", status="completed", risk_score=5, risk_level="low", created_at=datetime.now(UTC))
    finding = Finding(id=3, scan_id=7, stable_id="cookie.httponly-missing", title="Cookie is missing HttpOnly", severity="low", category="cookie", evidence="Set-Cookie: session=secret-value; Path=/", explanation="Observed configuration gap.", remediation="Set HttpOnly.", confidence="high")

    assert "secret-value" not in redact_evidence(finding.evidence)
    pdf = build_scan_pdf(scan, [finding])
    assert pdf.startswith(b"%PDF")
    assert b"secret-value" not in pdf


def test_report_evidence_redacts_common_authentication_secrets() -> None:
    evidence = "Authorization: Basic dXNlcjpwYXNz api_key=abc123 password='sensitive value' refresh_token: token456 https://site.test/path?token=url-secret"
    redacted = redact_evidence(evidence)

    for secret in ("dXNlcjpwYXNz", "abc123", "sensitive value", "token456", "url-secret"):
        assert secret not in redacted
    assert redacted.count("[redacted]") == 5


def test_pdf_treats_scan_and_finding_text_as_literal_not_reportlab_markup() -> None:
    external_uri = "https://untrusted.example/phishing"
    scan = Scan(
        id=9,
        target_url="https://public.example/?token=cover-secret&a=1&b=<value>",
        status="partial",
        error_message="Response included <b>untrusted</b> markup & text.",
        created_at=datetime.now(UTC),
    )
    finding = Finding(
        id=4,
        scan_id=9,
        stable_id="headers.content-security-policy",
        title=f'<link href="{external_uri}">Review evidence</link>',
        severity="high",
        category="security & headers",
        evidence="Observed <b>untrusted</b> response & markup.",
        explanation="The evidence contains <script>text</script>.",
        remediation="Review A&B settings.",
        confidence="high",
        dedup_key="headers.content-security-policy",
    )

    pdf = build_scan_pdf(scan, [finding])

    assert pdf.startswith(b"%PDF")
    assert external_uri.encode() not in pdf
    assert b"cover-secret" not in pdf


def test_pdf_includes_persisted_verification_attempts_without_claiming_success() -> None:
    scan = Scan(id=10, target_url="https://verify.example", status="completed", risk_score=10, risk_level="low", created_at=datetime.now(UTC))
    finding = Finding(id=5, scan_id=10, stable_id="headers.hsts-missing", title="HSTS absent", severity="low", evidence="HSTS missing", explanation="Header not observed", remediation="Set policy", confidence="high", dedup_key="headers.hsts-missing")
    attempt = VerificationAttempt(id=7, scan_id=10, finding_id=5, status="inconclusive", summary="Could not confidently reproduce the observation.", evidence="HTTP 403 blocked verification", created_at=datetime.now(UTC))

    pdf = build_scan_pdf(scan, [finding], [attempt])

    assert pdf.startswith(b"%PDF")
    assert len(re.findall(rb"/Type /Page\b", pdf)) >= 5


def test_pdf_report_handles_none_risk_score_and_partial_scan() -> None:
    scan = Scan(id=8, target_url="https://partial.example", status="partial", risk_score=None, risk_level=None, error_message="Network timeout during TLS check", created_at=datetime.now(UTC))
    pdf = build_scan_pdf(scan, [])
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 100


def test_pdf_report_handles_zero_one_and_multiple_findings_with_persisted_coverage() -> None:
    scan = Scan(
        id=88, target_url="https://report.example", status="completed", risk_score=5,
        risk_level="low", created_at=datetime.now(UTC), completed_at=datetime.now(UTC),
        check_summary=json.dumps({
            "coverage": {"dns": "completed", "headers": "completed", "tls": "completed", "cookies": "skipped"},
            "details": {"response_status": 200, "final_url": "https://report.example/", "scanner_version": 2, "response_headers": {"content-security-policy": "default-src 'self'"}, "redirect_observations": [], "rule_results": {"headers.csp": "present", "headers.hsts": "missing"}},
        }),
    )
    zero_pdf = build_scan_pdf(scan, [])
    assert zero_pdf.startswith(b"%PDF")
    assert len(re.findall(rb"/Type /Page\b", zero_pdf)) >= 4

    one = Finding(id=1, scan_id=88, stable_id="headers.hsts-missing", title="HSTS missing", severity="low", category="security-header", evidence="Final HTTPS response had no HSTS header.", explanation="HSTS was not observed.", remediation="Configure HSTS after validating HTTPS coverage.", confidence="high", dedup_key="headers.hsts-missing")
    one_pdf = build_scan_pdf(scan, [one])
    assert one_pdf.startswith(b"%PDF")

    many = [Finding(
        id=index, scan_id=88, stable_id=f"test.rule-{index}", title=f"Persisted observation {index}",
        severity=("high" if index % 2 else "low"), category="test", evidence=f"Observed evidence {index}",
        explanation="Impact requires application-context review.", remediation="Review the saved observation.",
        confidence="medium", dedup_key=f"test.rule-{index}",
    ) for index in range(1, 18)]
    many_pdf = build_scan_pdf(scan, many)
    assert many_pdf.startswith(b"%PDF")
    assert len(re.findall(rb"/Type /Page\b", many_pdf)) > len(re.findall(rb"/Type /Page\b", one_pdf))


def test_verification_marks_missing_observation_inconclusive(monkeypatch) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with test_session() as db:
        scan = Scan(target_url="https://public.example", normalized_url="https://public.example", status="completed")
        db.add(scan)
        db.flush()
        finding = Finding(scan_id=scan.id, stable_id="headers.csp-missing", dedup_key="headers.csp-missing", title="CSP missing", severity="low", category="security-header", evidence="CSP was absent.")
        db.add(finding)
        db.flush()
        attempt = VerificationAttempt(scan_id=scan.id, finding_id=finding.id, status="pending")
        db.add(attempt)
        db.commit()
        attempt_id = attempt.id

    class FakeScanner:
        def scan(self, target_url: str) -> ScanReport:
            return ScanReport(normalized_url=target_url, status="completed", findings=[FindingResult("headers.hsts-missing", "HSTS missing", "low", "security-header", "HSTS absent", "gap", "add HSTS", "high")])

    monkeypatch.setattr(verification, "SessionLocal", test_session)
    monkeypatch.setattr(verification, "WebsiteScanner", FakeScanner)
    verification.execute_verification(attempt_id)

    with test_session() as db:
        saved = db.get(VerificationAttempt, attempt_id)
        assert saved is not None
        assert saved.status == "inconclusive"
        assert saved.summary is not None

    engine.dispose()


def _extract_pdf_streams(pdf_bytes: bytes) -> str:
    chunks = []
    idx = 0
    while True:
        pos = pdf_bytes.find(b"stream\n", idx)
        if pos == -1:
            break
        end_pos = pdf_bytes.find(b"endstream", pos)
        if end_pos == -1:
            break
        raw = pdf_bytes[pos + 7 : end_pos].strip()
        try:
            decomp = zlib.decompress(base64.a85decode(raw, adobe=True))
            chunks.append(decomp.decode("latin1", errors="replace"))
        except Exception:
            try:
                decomp = zlib.decompress(raw)
                chunks.append(decomp.decode("latin1", errors="replace"))
            except Exception:
                chunks.append(raw.decode("latin1", errors="replace"))
        idx = end_pos + 9
    return "\n".join(chunks)


def test_pdf_report_enterprise_cover_and_severity_distribution() -> None:
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
    scan = Scan(
        id=42, target_url="https://audit.example.org/portal", status="completed",
        risk_score=48, risk_level="medium", created_at=now, completed_at=now,
        check_summary=json.dumps({
            "coverage": {"tls": "completed", "headers": "completed", "cookies": "completed"},
            "details": {
                "response_status": 200,
                "final_url": "https://audit.example.org/portal/",
                "scanner_version": 2,
                "response_headers": {"server": "nginx", "x-frame-options": "DENY"},
                "dns_observations": [{"validated_public_addresses": ["93.184.216.34"]}],
            },
        }),
    )
    findings = [
        Finding(
            id=101, scan_id=42, stable_id="headers.csp-missing", title="Content-Security-Policy header is missing",
            severity="low", category="headers", evidence="Response lacked CSP header",
            explanation="Mitigates cross-site scripting attacks.", remediation="Configure Content-Security-Policy header.",
            confidence="high", dedup_key="headers.csp-missing",
        ),
        Finding(
            id=102, scan_id=42, stable_id="cookies.samesite-missing", title="Session cookie missing SameSite flag",
            severity="medium", category="cookies", evidence="Set-Cookie: auth=xyz; Secure; HttpOnly",
            explanation="Mitigates cross-site request forgery.", remediation="Add SameSite=Lax or SameSite=Strict.",
            confidence="high", dedup_key="cookies.samesite-missing",
        ),
    ]

    pdf = build_scan_pdf(scan, findings, remediations={101: "open", 102: "in_progress"})
    assert pdf.startswith(b"%PDF")
    extracted = _extract_pdf_streams(pdf)
    # Verify UTC timestamp is explicitly present
    assert "2026-10-29 12:00:00 UTC" in extracted
    # Verify Sentinel AI branding is present
    assert "SENTINEL AI" in extracted
    # Verify rule level not recorded is preserved for scans without per-rule details
    assert "Rule-level results not recorded" in extracted


def test_pdf_report_verification_unambiguous_labels() -> None:
    now = datetime(2026, 10, 29, 14, 0, 0, tzinfo=UTC)
    scan = Scan(id=55, target_url="https://verify.example.org", status="completed", risk_score=25, risk_level="low", created_at=now)
    f1 = Finding(id=1, scan_id=55, stable_id="headers.hsts", title="HSTS missing", severity="medium", evidence="HSTS missing")
    f2 = Finding(id=2, scan_id=55, stable_id="headers.csp", title="CSP missing", severity="low", evidence="CSP missing")

    attempts = [
        VerificationAttempt(id=1, scan_id=55, finding_id=1, status="reproduced", summary="The insecure configuration was reproduced upon re-observation.", created_at=now),
        VerificationAttempt(id=2, scan_id=55, finding_id=2, status="resolved", summary="The issue was no longer observed upon re-observation.", created_at=now),
    ]

    pdf = build_scan_pdf(scan, [f1, f2], attempts)
    assert pdf.startswith(b"%PDF")
    extracted = _extract_pdf_streams(pdf)
    # Verify unambiguous enterprise labels
    assert "Issue Reproduced" in extracted
    assert "Issue No Longer Observed" in extracted


def test_pdf_report_endpoint_enforces_auth_and_ownership() -> None:
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_db
    from app.models import User

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    user1 = User(id=801, email="u1@example.test", display_name="User One", password_hash="hash")
    user2 = User(id=802, email="u2@example.test", display_name="User Two", password_hash="hash")
    scan1 = Scan(id=901, target_url="https://user1.example", owner_id=801, status="completed", risk_score=10, created_at=datetime.now(UTC))

    with session_factory() as db:
        db.add_all([user1, user2, scan1])
        db.commit()

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        import app.api.routes as routes
        # Unauthenticated request
        with TestClient(app) as client:
            unauth = client.get("/api/v1/scans/901/report.pdf")
            assert unauth.status_code == 401

        # User 2 attempting to access User 1's scan
        app.dependency_overrides[routes.get_current_user] = lambda: user2
        with TestClient(app) as client:
            forbidden = client.get("/api/v1/scans/901/report.pdf")
            assert forbidden.status_code == 404

        # User 1 accessing own scan
        app.dependency_overrides[routes.get_current_user] = lambda: user1
        with TestClient(app) as client:
            success = client.get("/api/v1/scans/901/report.pdf")
            assert success.status_code == 200
            assert success.headers["content-type"] == "application/pdf"
            assert success.content.startswith(b"%PDF")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)


def test_cover_page_is_rendered_above_background_and_not_blank() -> None:
    """Ensure the cover page is painted above the background and visibly renders all branding/metadata."""
    import pypdf
    import io
    try:
        import pypdfium2 as pdfium
    except ImportError:
        pdfium = None

    now = datetime(2026, 10, 29, 15, 30, 0, tzinfo=UTC)
    scan = Scan(
        id=77, target_url="https://app.example.com", status="completed",
        risk_score=55, risk_level="high", created_at=now, completed_at=now,
        check_summary=json.dumps({"coverage": {"headers": "completed", "tls": "completed"}}),
    )
    finding = Finding(id=1, scan_id=77, title="TLS Misconfiguration", severity="high", category="tls", stable_id="tls.weak-cipher")

    pdf = build_scan_pdf(scan, [finding])
    reader = pypdf.PdfReader(io.BytesIO(pdf))

    # Page 1 text validation
    page1_text = reader.pages[0].extract_text()
    assert "SENTINEL AI" in page1_text
    assert "WEBSITE SECURITY ASSESSMENT REPORT" in page1_text
    assert "app.example.com" in page1_text
    assert "#77" in page1_text
    assert "COMPLETED" in page1_text
    assert "55 / 100" in page1_text
    assert "HIGH RISK" in page1_text
    assert "CONFIDENTIAL & PROPRIETARY" in page1_text

    # Visual rendering validation: ensure the cover is not covered by a solid rectangle
    if pdfium is not None:
        doc = pdfium.PdfDocument(pdf)
        img = doc[0].render(scale=1.5).to_pil()
        colors_found = img.getcolors(maxcolors=20000)
        # More than 50 unique colors (due to text anti-aliasing, badges, shield logo)
        assert len(colors_found) > 50
        # Ensure bright white text pixels are present and not buried
        white_px = sum(cnt for cnt, col in colors_found if col[0] > 230 and col[1] > 230 and col[2] > 230)
        assert white_px > 1000


def test_ending_page_renders_methodology_appendix_and_conclusion_without_blank_pages() -> None:
    """Ensure the PDF ends naturally with verification, definitions, and the conclusion banner."""
    import pypdf
    import io

    now = datetime(2026, 10, 29, 16, 0, 0, tzinfo=UTC)
    scan = Scan(
        id=88, target_url="https://portal.example.com", status="completed",
        risk_score=20, risk_level="low", created_at=now, completed_at=now,
        check_summary=json.dumps({"coverage": {"headers": "completed"}}),
    )
    finding = Finding(id=1, scan_id=88, title="Missing Header", severity="low", category="headers", stable_id="headers.missing")
    attempt = VerificationAttempt(id=1, scan_id=88, finding_id=1, status="resolved", summary="Header verified active.", created_at=now)

    pdf = build_scan_pdf(scan, [finding], [attempt], {1: "resolved"})
    reader = pypdf.PdfReader(io.BytesIO(pdf))

    last_page = reader.pages[-1]
    last_text = last_page.extract_text()
    assert len(last_text.strip()) > 100
    assert "8. Methodology, Limitations & Definitions Appendix" in last_text
    assert "END OF SECURITY ASSESSMENT REPORT" in last_text
    assert "Page 6 of 6" in last_text or f"Page {len(reader.pages)} of {len(reader.pages)}" in last_text


def test_no_unparsed_html_or_xml_tags_escape_into_tables() -> None:
    """Verify that table cells never render raw escaped <font color="0x..."> or <b> tags."""
    import pypdf
    import io

    now = datetime(2026, 10, 29, 17, 0, 0, tzinfo=UTC)
    scan = Scan(id=99, target_url="https://tags.example.com", status="completed", risk_score=30, risk_level="low", created_at=now)
    f1 = Finding(id=1, scan_id=99, title="Header Gap", severity="medium", category="headers", stable_id="headers.gap")
    attempt = VerificationAttempt(id=1, scan_id=99, finding_id=1, status="resolved", summary="Verified fixed.", created_at=now)

    pdf = build_scan_pdf(scan, [f1], [attempt], {1: "resolved"})
    reader = pypdf.PdfReader(io.BytesIO(pdf))

    for idx, page in enumerate(reader.pages):
        text = page.extract_text()
        assert "<font" not in text, f"Found unparsed <font tag on page {idx+1}"
        assert "&lt;font" not in text, f"Found escaped &lt;font tag on page {idx+1}"
        assert "0x" not in text or "0x991b1b" not in text, f"Found raw hex color string on page {idx+1}"


def test_severity_distribution_chart_and_zero_findings() -> None:
    """Ensure the distribution chart renders cleanly for both normal and zero-findings scans."""
    import pypdf
    import io

    now = datetime(2026, 10, 29, 18, 0, 0, tzinfo=UTC)
    # Zero findings
    scan_zero = Scan(id=101, target_url="https://clean.example.com", status="completed", risk_score=0, risk_level="clean", created_at=now)
    pdf_zero = build_scan_pdf(scan_zero, [])
    reader_zero = pypdf.PdfReader(io.BytesIO(pdf_zero))
    p2_text = reader_zero.pages[1].extract_text()
    assert "Zero Security Vulnerabilities or Misconfigurations Identified Across Evaluated Checks" in p2_text

    # Multiple findings
    scan_multi = Scan(id=102, target_url="https://multi.example.com", status="completed", risk_score=80, risk_level="critical", created_at=now)
    findings = [
        Finding(id=1, scan_id=102, title="Crit 1", severity="critical"),
        Finding(id=2, scan_id=102, title="High 1", severity="high"),
        Finding(id=3, scan_id=102, title="Med 1", severity="medium"),
        Finding(id=4, scan_id=102, title="Low 1", severity="low"),
        Finding(id=5, scan_id=102, title="Info 1", severity="info"),
    ]
    pdf_multi = build_scan_pdf(scan_multi, findings)
    reader_multi = pypdf.PdfReader(io.BytesIO(pdf_multi))
    multi_p2 = reader_multi.pages[1].extract_text()
    assert "Critical: 1" in multi_p2
    assert "High: 1" in multi_p2
    assert "Medium: 1" in multi_p2
    assert "Low: 1" in multi_p2
    assert "Info: 1" in multi_p2


def test_long_findings_and_evidence_wrap_cleanly() -> None:
    """Ensure very long finding titles, explanations, and evidence wrap without crashing."""
    import pypdf
    import io

    now = datetime(2026, 10, 29, 19, 0, 0, tzinfo=UTC)
    scan = Scan(id=103, target_url="https://long.example.com", status="completed", risk_score=40, risk_level="medium", created_at=now)
    long_evidence = "X" * 3500
    long_finding = Finding(
        id=1,
        scan_id=103,
        title="Excessively Long Finding Title That Should Wrap Properly Across Multiple Lines Without Overflowing",
        severity="medium",
        category="security-headers",
        stable_id="headers.long-stable-id-that-wraps-cleanly",
        evidence=long_evidence,
        explanation="Detailed explanation paragraph " * 10,
        remediation="Lengthy multi-step remediation instructions " * 10,
    )
    pdf = build_scan_pdf(scan, [long_finding])
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) >= 5
    # Verify content didn't disappear
    found_title = any("Excessively Long Finding Title" in p.extract_text() for p in reader.pages)
    assert found_title


