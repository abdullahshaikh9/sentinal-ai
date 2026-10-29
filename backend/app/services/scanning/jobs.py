"""Persistence boundary for background scan execution."""

import json
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError

from app.db import SessionLocal
from app.models import ActivityEvent, Finding, Notification, Scan
from app.services.risk import calculate_risk_score
from app.services.scanning.scanner import WebsiteScanner, deduplicate_findings


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.commit()

        report = WebsiteScanner().scan(scan.normalized_url or scan.target_url)
        findings = deduplicate_findings(report.findings)
        risk_score, risk_level = calculate_risk_score(finding.severity for finding in findings)
        scan.status = report.status
        scan.normalized_url = report.normalized_url
        scan.risk_score = risk_score
        scan.risk_level = risk_level
        scan.error_message = report.error_message
        scan.redirects = json.dumps(report.redirects)
        scan.check_summary = json.dumps({
            "coverage": report.checks,
            "details": report.check_details,
        }, sort_keys=True)
        scan.completed_at = datetime.now(UTC)
        event_type = f"scan.{report.status}"
        db.add(ActivityEvent(event_type=event_type, summary=f"Scan {scan.id} {report.status}.", scan_id=scan.id, owner_id=scan.owner_id))
        important_count = sum(result.severity in {"critical", "high"} for result in findings)
        if scan.owner_id is not None:
            db.add(Notification(user_id=scan.owner_id, event_type=event_type, title="Assessment finished", message=f"Scan {scan.id} finished with status {report.status}.", scan_id=scan.id))
        if important_count and scan.owner_id is not None:
            db.add(Notification(user_id=scan.owner_id, event_type="finding.important", title="High-priority observations recorded", message=f"Scan {scan.id} recorded {important_count} high or critical observation(s). Review the saved evidence.", scan_id=scan.id))
        for result in findings:
            dedup_key = result.dedup_key or result.stable_id
            existing = db.query(Finding).filter_by(scan_id=scan.id, dedup_key=dedup_key).one_or_none()
            values = {
                "stable_id": result.stable_id,
                "title": result.title,
                "severity": result.severity,
                "category": result.category,
                "evidence": result.evidence,
                "explanation": result.explanation,
                "remediation": result.remediation,
                "confidence": result.confidence,
                "evidence_data": json.dumps(result.evidence_data, sort_keys=True) if result.evidence_data else None,
                "dedup_key": dedup_key,
            }
            if existing is None:
                db.add(Finding(scan_id=scan.id, **values))
            else:
                for key, value in values.items():
                    setattr(existing, key, value)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        failed_scan = db.get(Scan, scan_id)
        if failed_scan is not None:
            failed_scan.status = "failed"
            failed_scan.error_message = "The scan result could not be saved. Check database availability and retry."
            failed_scan.completed_at = datetime.now(UTC)
            db.add(ActivityEvent(event_type="scan.failed", summary=f"Scan {scan_id} failed while saving its result.", scan_id=scan_id, owner_id=failed_scan.owner_id))
            db.commit()
    except Exception:
        db.rollback()
        failed_scan = db.get(Scan, scan_id)
        if failed_scan is not None:
            failed_scan.status = "failed"
            failed_scan.error_message = "The scan could not be completed. Retry the authorized assessment."
            failed_scan.completed_at = datetime.now(UTC)
            db.add(ActivityEvent(event_type="scan.failed", summary=f"Scan {scan_id} failed during assessment.", scan_id=scan_id, owner_id=failed_scan.owner_id))
            db.commit()
    finally:
        db.close()
