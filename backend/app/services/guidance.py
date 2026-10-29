"""Evidence-only defensive guidance assembled from persisted scan findings."""

from __future__ import annotations

from app.models import Finding, Scan
from app.services.ai import redact_untrusted


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _bound_guidance(answer: str, max_chars: int) -> str:
    limit = max(1, max_chars)
    marker = "\n\nGuidance was truncated to the configured response limit."
    if len(answer) <= limit:
        return answer
    if limit <= len(marker):
        return marker[-limit:]
    return answer[: limit - len(marker)].rstrip() + marker


def build_defensive_guidance(scan: Scan, findings: list[Finding], *, omitted_findings: int = 0, max_chars: int = 5000) -> str:
    ordered = sorted(findings, key=lambda finding: (_SEVERITY_ORDER.get(finding.severity.lower(), 5), finding.id))
    lines = [
        f"Defensive guidance for scan {scan.id}",
        f"Scan reference: scan:{scan.id}",
        f"Scan status: {scan.status}. Target: {redact_untrusted(scan.target_url, 500)}.",
        "Recommendations below use only findings persisted for this scan. They do not confirm exploitability or overall security.",
    ]
    if omitted_findings:
        lines.append(f"Coverage limitation: the guidance includes the {len(ordered)} highest-priority saved findings; {omitted_findings} additional finding(s) were omitted from the context limit.")
    if scan.status in {"partial", "failed", "pending", "running"}:
        lines.append("Assessment limitation: this scan is not complete; treat the results as partial and review its check coverage before drawing conclusions.")

    if not ordered:
        lines.append("No findings were persisted for this scan, so there are no finding-specific remediation steps to recommend. This does not establish that the target is secure.")
        return _bound_guidance("\n".join(lines), max_chars)

    lines.append("\nPrioritized actions (highest severity first):")
    for index, finding in enumerate(ordered, start=1):
        severity = finding.severity.lower()
        lines.append(f"\n{index}. [{severity.upper()}] {redact_untrusted(finding.title, 255)}")
        lines.append(f"   Finding reference: finding:{finding.id}; category: {redact_untrusted(finding.category, 80)}; confidence: {redact_untrusted(finding.confidence, 50)}.")
        if finding.evidence:
            lines.append(f"   Recorded evidence: {redact_untrusted(finding.evidence, 1000)}")
        if finding.explanation:
            lines.append(f"   Recorded explanation: {redact_untrusted(finding.explanation, 1000)}")
        if finding.remediation:
            lines.append(f"   Stored remediation: {redact_untrusted(finding.remediation, 1200)}")
        else:
            lines.append("   Remediation: no finding-specific remediation was stored. Validate the observation, then consult the relevant framework or vendor documentation for the recorded control before making changes.")

    lines.append("\nBefore changing a system, validate the recorded evidence in an authorized environment, test remediation outside production, and rerun the same bounded checks. No changes or security tests were performed by this guidance.")
    return _bound_guidance("\n".join(lines), max_chars)
