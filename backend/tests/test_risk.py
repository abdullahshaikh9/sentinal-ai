from app.services.risk import calculate_risk_score


def test_risk_score_is_deterministic_and_capped() -> None:
    assert calculate_risk_score(["medium", "low"]) == (20, "medium")
    assert calculate_risk_score(["critical", "critical", "high"]) == (100, "critical")
    assert calculate_risk_score(["info"]) == (0, "none")
