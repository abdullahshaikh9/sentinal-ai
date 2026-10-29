import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Finding, Scan
from app.services.scanning import jobs
from app.services.scanning.scanner import FindingResult, ScanReport


def test_scan_job_persists_report_and_findings(monkeypatch) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    class FakeScanner:
        def scan(self, target_url: str) -> ScanReport:
            return ScanReport(
                normalized_url=target_url,
                status="completed",
                risk_score=999,
                risk_level="critical",
                findings=[
                    FindingResult(
                        "headers.csp-missing",
                        "Content-Security-Policy header is missing",
                        "low",
                        "security-header",
                        "CSP was not present.",
                        "Observed configuration gap.",
                        "Set a policy.",
                        "high",
                    "headers.csp-missing",
                    )
                    , FindingResult(
                        "headers.csp-missing",
                        "Content-Security-Policy header is missing",
                        "low",
                        "security-header",
                        "CSP was not present.",
                        "Observed configuration gap.",
                        "Set a policy.",
                        "high",
                        "headers.csp-missing",
                    )
                ],
                checks={"headers": "completed"},
            )

    with test_session() as db:
        scan = Scan(target_url="https://public.example/", normalized_url="https://public.example/", status="pending")
        db.add(scan)
        db.commit()
        scan_id = scan.id

    monkeypatch.setattr(jobs, "SessionLocal", test_session)
    monkeypatch.setattr(jobs, "WebsiteScanner", FakeScanner)
    jobs.execute_scan(scan_id)

    with test_session() as db:
        saved_scan = db.get(Scan, scan_id)
        saved_finding = db.query(Finding).one()
        assert saved_scan is not None
        assert saved_scan.status == "completed"
        assert saved_scan.risk_score == 5
        assert saved_scan.risk_level == "low"
        assert saved_scan.completed_at is not None
        assert saved_finding.stable_id == "headers.csp-missing"
        saved_summary = json.loads(saved_scan.check_summary)
        assert saved_summary == {"coverage": {"headers": "completed"}, "details": {}}

    jobs.execute_scan(scan_id)

    with test_session() as db:
        assert db.query(Finding).filter(Finding.scan_id == scan_id).count() == 1

    engine.dispose()
