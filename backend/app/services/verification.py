"""Non-destructive verification using the existing bounded scanner."""

from app.db import SessionLocal
from app.models import ActivityEvent, Finding, Scan, VerificationAttempt
from app.services.scanning.scanner import WebsiteScanner


def execute_verification(attempt_id: int) -> None:
    db = SessionLocal()
    try:
        attempt = db.get(VerificationAttempt, attempt_id)
        if attempt is None:
            return
        finding = db.get(Finding, attempt.finding_id) if attempt.finding_id else None
        scan = db.get(Scan, attempt.scan_id)
        if finding is None or scan is None:
            attempt.status = "inconclusive"
            attempt.summary = "The original finding or scan could not be loaded."
            db.commit()
            return
        attempt.status = "running"
        db.commit()
        if finding.category not in {"cookie", "security-header", "transport"}:
            outcome, summary = "inconclusive", "This finding category is not supported by the safe verification workflow."
            evidence = "No verification request was made."
        else:
            report = WebsiteScanner().scan(scan.normalized_url or scan.target_url)
            matching = [result for result in report.findings if (result.dedup_key or result.stable_id) == (finding.dedup_key or finding.stable_id)]
            if report.status != "completed":
                outcome, summary = "inconclusive", "The verification scan was incomplete; absence or presence cannot establish a fix."
                evidence = report.error_message or "The verification scan did not complete all required checks."
            elif matching:
                outcome, summary = "failed", "The original observation was reproduced by the bounded verification scan."
                evidence = matching[0].evidence
            else:
                outcome, summary = "inconclusive", "The observation was not reproduced, but a later absence is not proof that it was fixed."
                evidence = "The original logical check was not present in the verification result."
        attempt.status = outcome
        attempt.summary = summary
        attempt.evidence = evidence[:4000]
        db.add(ActivityEvent(event_type="verification.completed", summary=f"Verification {outcome} for finding {finding.id}.", scan_id=scan.id, finding_id=finding.id, owner_id=scan.owner_id))
        db.commit()
    except Exception:
        db.rollback()
        attempt = db.get(VerificationAttempt, attempt_id)
        if attempt is not None:
            attempt.status = "inconclusive"
            attempt.summary = "Verification could not be completed safely."
            db.commit()
    finally:
        db.close()
