"""Deterministic risk classification for observed scanner findings."""

from collections.abc import Iterable

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 0}


def calculate_risk_score(severities: Iterable[str]) -> tuple[int, str]:
    """Calculate a transparent capped score from confirmed observations only."""
    score = min(100, sum(SEVERITY_WEIGHTS.get(severity, 0) for severity in severities))
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    return score, level

