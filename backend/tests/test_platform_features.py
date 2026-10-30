from datetime import UTC, datetime, timedelta
from itertools import count
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import ActivityEvent, Asset, AuthSession, Finding, FindingRemediation, Notification, OtpSendAttempt, ReportMetadata, Scan, User, VerificationAttempt
from app.config import Settings
from app.services.otp import OtpSendRateLimitError, check_send_rate_limits, record_send_attempts
import app.api.routes as routes


_ids = count(9200)


@pytest.fixture()
def platform_client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    user_id = next(_ids)
    owner = User(id=user_id, email=f"platform-{user_id}@example.test", display_name="Platform User", password_hash="test-hash", phone_number=f"+1555{user_id:07d}", email_verified_at=datetime.now(UTC), phone_verified_at=datetime.now(UTC))
    with factory() as db:
        db.add(owner)
        db.add_all([
            Scan(id=1, target_url="https://owned.example", normalized_url="https://owned.example", status="completed", risk_score=55, risk_level="medium", asset_id=41, owner_id=user_id, created_at=datetime.now(UTC)),
            Scan(id=2, target_url="https://owned.example/", normalized_url="https://owned.example", status="partial", risk_score=35, risk_level="low", owner_id=user_id, created_at=datetime.now(UTC)),
            Scan(id=3, target_url="https://other.example", normalized_url="https://other.example", status="completed", risk_score=10, owner_id=user_id + 1, created_at=datetime.now(UTC)),
        ])
        db.add_all([
            Asset(id=41, target_url="https://owned.example", normalized_url="https://owned.example", authorization_confirmed=True, owner_id=user_id),
            Asset(id=42, target_url="https://private.example", normalized_url="https://private.example", authorization_confirmed=True, owner_id=user_id + 1),
        ])
        db.add_all([
            Finding(id=11, scan_id=1, stable_id="header.hsts", dedup_key="header.hsts", title="HSTS absent", severity="high", evidence="Not observed", remediation="Set a policy."),
            Finding(id=12, scan_id=1, stable_id="cookie.secure", dedup_key="cookie.secure", title="Cookie lacks Secure", severity="medium", evidence="Attribute absent"),
            Finding(id=21, scan_id=2, stable_id="header.hsts", dedup_key="header.hsts", title="HSTS absent", severity="medium", evidence="Not observed"),
            Finding(id=22, scan_id=2, stable_id="tls.protocol", dedup_key="tls.protocol", title="Protocol finding", severity="low", evidence="Observed"),
            Finding(id=31, scan_id=3, stable_id="private", dedup_key="private", title="Other account", severity="critical"),
        ])
        db.add(Notification(id=91, user_id=user_id + 1, event_type="test", title="Private", message="Private notification"))
        db.commit()

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[routes.get_current_user] = lambda: owner
    app.dependency_overrides[routes.require_csrf] = lambda: None
    try:
        with TestClient(app) as client:
            yield client, factory, owner
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)


def test_scan_comparison_reports_observation_changes_and_limits(platform_client):
    client, _, _ = platform_client
    response = client.get("/api/v1/scans/compare", params={"earlier_scan_id": 1, "later_scan_id": 2})
    assert response.status_code == 200
    data = response.json()
    assert [(item["stable_id"], item["severity"]) for item in data["new_findings"]] == [("tls.protocol", "low")]
    assert [item["stable_id"] for item in data["no_longer_observed"]] == ["cookie.secure"]
    assert [item["stable_id"] for item in data["still_present"]] == ["header.hsts"]
    assert data["severity_changes"] == [{"stable_id": "header.hsts", "title": "HSTS absent", "before": "high", "after": "medium"}]
    assert data["risk_score_delta"] == -20
    assert "not proof of remediation" in data["limitation"]


def test_scan_comparison_rejects_different_website_and_unowned_scan(platform_client):
    client, _, _ = platform_client
    different_target = client.get("/api/v1/scans/compare", params={"earlier_scan_id": 1, "later_scan_id": 3})
    unowned = client.get("/api/v1/scans/compare", params={"earlier_scan_id": 1, "later_scan_id": 99})
    assert different_target.status_code == 404
    assert unowned.status_code == 404


def test_scan_comparison_keeps_duplicate_titles_distinct_by_stable_identifier(platform_client):
    client, factory, owner = platform_client
    with factory() as db:
        db.add_all([
            Finding(id=101, scan_id=1, stable_id="finding.first", dedup_key="finding.first", title="Duplicate title", severity="low"),
            Finding(id=102, scan_id=2, stable_id="finding.second", dedup_key="finding.second", title="Duplicate title", severity="low"),
        ])
        db.commit()
    result = client.get("/api/v1/scans/compare", params={"earlier_scan_id": 1, "later_scan_id": 2}).json()
    assert "not proof of remediation" in result["limitation"]
    assert "finding.second" in {item["stable_id"] for item in result["new_findings"]}
    assert "finding.first" in {item["stable_id"] for item in result["no_longer_observed"]}


def test_global_search_returns_only_owned_assets_scans_and_findings(platform_client):
    client, _, _ = platform_client
    response = client.get("/api/v1/search", params={"q": "owned"})
    assert response.status_code == 200
    results = response.json()["results"]
    assert {item["kind"] for item in results} == {"asset", "scan"}
    assert all("other.example" not in item["label"] for item in results)
    finding_response = client.get("/api/v1/search", params={"q": "HSTS absent"})
    assert finding_response.status_code == 200
    assert {item["kind"] for item in finding_response.json()["results"]} == {"finding"}
    assert all(item["href"].startswith("/findings/") for item in finding_response.json()["results"])


def test_global_search_treats_wildcards_as_literal_and_bounds_query_length(platform_client):
    client, _, _ = platform_client
    wildcard = client.get("/api/v1/search", params={"q": "%"})
    too_long = client.get("/api/v1/search", params={"q": "x" * 101})
    assert wildcard.status_code == 200 and wildcard.json()["results"] == []
    assert too_long.status_code == 422


def test_dashboard_overview_uses_account_scoped_persisted_data(platform_client):
    client, factory, owner = platform_client
    with factory() as db:
        db.add(FindingRemediation(finding_id=12, owner_id=owner.id, status="fixed", updated_by=owner.id))
        db.add(VerificationAttempt(scan_id=1, finding_id=11, status="pending", summary="Queued"))
        db.add(VerificationAttempt(scan_id=3, finding_id=31, status="running", summary="Other account"))
        db.commit()

    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["scans_total"] == 2
    assert data["scans_by_status"] == {"pending": 0, "running": 0, "completed": 1, "partial": 1, "failed": 0}
    assert data["findings_by_severity"] == {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 0}
    assert data["open_findings"] == 3 and data["resolved_findings"] == 1
    assert data["high_critical_open"] == 1
    assert data["awaiting_verification"] == 1
    assert data["verification_outcomes"]["pending"] == 1
    assert data["assets_total"] == 1 and data["assets_scanned"] == 1
    assert data["assets"][0]["latest_scan_id"] == 1
    assert data["assets"][0]["open_findings"] == 1
    assert [item["id"] for item in data["recent_scans"]] == [2, 1]
    assert all(item["id"] != 3 for item in data["recent_scans"])


def test_asset_overview_reports_latest_owned_scan_and_finding_summary(platform_client):
    client, factory, owner = platform_client
    with factory() as db:
        db.add(Scan(id=4, target_url="https://owned.example", normalized_url="https://owned.example", status="partial", risk_score=40, risk_level="low", asset_id=41, owner_id=owner.id, created_at=datetime.now(UTC) + timedelta(seconds=1)))
        db.add(Finding(id=41, scan_id=4, stable_id="latest.finding", dedup_key="latest.finding", title="Latest scan observation", severity="medium"))
        db.commit()
    response = client.get("/api/v1/assets/overview", params={"limit": 10, "offset": 0})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    asset = data["items"][0]
    assert asset["id"] == 41
    assert asset["latest_scan_id"] == 4
    assert asset["latest_scan_status"] == "partial"
    assert asset["scan_count"] == 2
    assert asset["latest_findings"] == 1
    assert asset["latest_open_findings"] == 1
    assert client.get("/api/v1/assets/overview", params={"limit": 1, "offset": 1}).json()["items"] == []


def test_scan_history_filters_by_owned_asset_and_date_range(platform_client):
    client, _, _ = platform_client
    today = datetime.now(UTC).date().isoformat()
    matching = client.get("/api/v1/scans", params={"asset_id": 41, "date_from": today, "date_to": today})
    reversed_range = client.get("/api/v1/scans", params={"date_from": "2026-02-02", "date_to": "2026-02-01"})
    private_asset = client.get("/api/v1/scans", params={"asset_id": 999})
    assert matching.status_code == 200 and [item["id"] for item in matching.json()["items"]] == [1]
    assert reversed_range.status_code == 400
    assert private_asset.status_code == 200 and private_asset.json()["items"] == []


def test_remediation_transitions_are_persisted_with_history_and_notifications(platform_client):
    client, factory, owner = platform_client
    rejected = client.patch("/api/v1/findings/11/remediation", json={"status": "fixed"})
    assert rejected.status_code == 409
    active = client.patch("/api/v1/findings/11/remediation", json={"status": "in_progress"})
    assert active.status_code == 200
    assert active.json()["status"] == "in_progress"
    fixed = client.patch("/api/v1/findings/11/remediation", json={"status": "fixed"})
    assert fixed.status_code == 200
    assert fixed.json()["status"] == "fixed"
    history = client.get("/api/v1/findings/11/remediation/history")
    assert [row["to_status"] for row in history.json()] == ["fixed", "in_progress"]
    notifications = client.get("/api/v1/notifications")
    assert len(notifications.json()) == 2
    notification_id = notifications.json()[0]["id"]
    marked = client.patch(f"/api/v1/notifications/{notification_id}/read")
    assert marked.status_code == 200
    assert marked.json()["read_at"] is not None
    with factory() as db:
        assert db.get(Notification, 91).read_at is None
        assert db.query(Notification).filter_by(user_id=owner.id).count() == 2


def test_csv_export_is_owner_scoped_and_neutralizes_spreadsheet_formulas(platform_client):
    client, factory, _ = platform_client
    with factory() as db:
        finding = db.get(Finding, 11)
        finding.title = '=HYPERLINK("https://bad.example")'
        db.commit()
    response = client.get("/api/v1/scans/1/findings.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK" in response.text
    assert client.get("/api/v1/scans/3/findings.csv").status_code == 404
    history = client.get("/api/v1/reports")
    assert history.status_code == 200
    assert [(row["scan_id"], row["report_type"]) for row in history.json()] == [(1, "csv")]


def test_otp_send_limits_are_keyed_per_recipient_and_ip(platform_client):
    _, factory, _ = platform_client
    settings = Settings(_env_file=None, otp_pepper="unit-test-secret", otp_max_sends_per_recipient_per_hour=3, otp_max_sends_per_ip_per_hour=10)
    with factory() as db:
        for _ in range(3):
            record_send_attempts(db, ["+923001234567"], "203.0.113.7", settings)
            db.commit()
        with pytest.raises(OtpSendRateLimitError):
            check_send_rate_limits(db, ["+923001234567"], "203.0.113.7", settings)
        for index in range(9):
            record_send_attempts(db, [f"person-{index}@example.test"], "203.0.113.8", settings)
            db.commit()
        with pytest.raises(OtpSendRateLimitError):
            check_send_rate_limits(db, ["new@example.test", "new-phone"], "203.0.113.8", settings)
        rows = db.query(OtpSendAttempt).all()
        assert all("923001234567" not in row.recipient_hash and "203.0.113." not in row.ip_hash for row in rows)


def test_get_finding_detail_is_owner_scoped_and_includes_scan_target(platform_client):
    client, _, _ = platform_client
    response = client.get("/api/v1/findings/11")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 11
    assert data["scan_id"] == 1
    assert data["target_url"] == "https://owned.example"
    assert data["title"] == "HSTS absent"
    assert data["remediation_status"] == "open"

    # Cross-user access returns 404
    assert client.get("/api/v1/findings/31").status_code == 404
    # Non-existent finding returns 404
    assert client.get("/api/v1/findings/99999").status_code == 404


def test_scan_details_serialize_structured_coverage_and_pdf_uses_persisted_observations(platform_client):
    client, factory, _ = platform_client
    with factory() as db:
        scan = db.get(Scan, 1)
        assert scan is not None
        scan.check_summary = json.dumps({
            "coverage": {"headers": "completed", "cookies": "inconclusive"},
            "details": {"response_status": 200, "final_url": "https://owned.example/", "scanner_version": 2, "rule_results": {"headers.csp": "present"}},
        })
        db.commit()

    detail = client.get("/api/v1/scans/1")
    assert detail.status_code == 200
    assert detail.json()["checks"] == {"headers": "completed", "cookies": "inconclusive"}
    assert detail.json()["check_details"]["response_status"] == 200
    assert detail.json()["check_details"]["rule_results"]["headers.csp"] == "present"

    report = client.get("/api/v1/scans/1/report.pdf")
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert report.content.startswith(b"%PDF")


def test_scan_comparison_handles_duplicate_rule_ids_with_distinct_dedup_keys(platform_client):
    client, factory, _ = platform_client
    with factory() as db:
        db.add_all([
            Finding(id=201, scan_id=1, stable_id="cookie.secure", dedup_key="cookie.secure:session_id", title="Cookie session_id lacks Secure", severity="medium"),
            Finding(id=202, scan_id=1, stable_id="cookie.secure", dedup_key="cookie.secure:auth_token", title="Cookie auth_token lacks Secure", severity="medium"),
            Finding(id=203, scan_id=2, stable_id="cookie.secure", dedup_key="cookie.secure:session_id", title="Cookie session_id lacks Secure", severity="medium"),
        ])
        db.commit()
    result = client.get("/api/v1/scans/compare", params={"earlier_scan_id": 1, "later_scan_id": 2}).json()
    still_present_ids = {item["stable_id"] for item in result["still_present"]}
    no_longer_observed_ids = {item["stable_id"] for item in result["no_longer_observed"]}
    assert "cookie.secure:session_id" in still_present_ids
    assert "cookie.secure:auth_token" in no_longer_observed_ids


def test_dashboard_asset_query_count_does_not_grow_with_asset_count(platform_client):
    client, factory, owner = platform_client
    engine = factory.kw["bind"]
    statements: list[str] = []
    listener = lambda _connection, _cursor, statement, _parameters, _context, _executemany: statements.append(statement)
    event.listen(engine, "before_cursor_execute", listener)
    try:
        baseline = client.get("/api/v1/dashboard/overview")
        baseline_count = len(statements)
        assert baseline.status_code == 200

        with factory() as db:
            created_at = datetime.now(UTC) + timedelta(minutes=1)
            for index in range(8):
                asset_id = 7000 + index
                db.add(Asset(id=asset_id, target_url=f"https://dashboard-{index}.example", normalized_url=f"https://dashboard-{index}.example", authorization_confirmed=True, owner_id=owner.id, created_at=created_at + timedelta(seconds=index)))
                db.add(Scan(id=8000 + index, target_url=f"https://dashboard-{index}.example", normalized_url=f"https://dashboard-{index}.example", status="completed", risk_score=1, risk_level="low", asset_id=asset_id, owner_id=owner.id, created_at=created_at + timedelta(seconds=index)))
            db.commit()

        statements.clear()
        expanded = client.get("/api/v1/dashboard/overview")
        expanded_count = len(statements)
        assert expanded.status_code == 200
        assert len(expanded.json()["assets"]) == 6
        assert expanded_count == baseline_count
    finally:
        event.remove(engine, "before_cursor_execute", listener)


def test_findings_and_verification_overviews_are_batched_and_owner_scoped(platform_client):
    client, factory, owner = platform_client
    with factory() as db:
        db.add_all([
            VerificationAttempt(id=801, scan_id=1, finding_id=11, status="completed", summary="Verified", evidence="Observed", created_at=datetime.now(UTC)),
            VerificationAttempt(id=802, scan_id=3, finding_id=31, status="failed", summary="Private attempt", created_at=datetime.now(UTC)),
            FindingRemediation(finding_id=11, owner_id=owner.id, status="fixed", updated_by=owner.id),
        ])
        db.commit()

    findings = client.get("/api/v1/findings/overview")
    assert findings.status_code == 200
    assert {item["id"] for item in findings.json()} == {11, 12, 21, 22}
    assert next(item for item in findings.json() if item["id"] == 11)["remediation_status"] == "fixed"

    verification = client.get("/api/v1/verification/overview")
    assert verification.status_code == 200
    items = {item["finding_id"]: item for item in verification.json()}
    assert set(items) == {11, 12, 21, 22}
    assert items[11]["attempts"][0]["summary"] == "Verified"
    assert all(attempt["summary"] != "Private attempt" for item in items.values() for attempt in item["attempts"])


def test_admin_access_is_explicitly_allowlisted_and_overview_uses_saved_records(platform_client, monkeypatch):
    from app.config import Settings

    client, _, owner = platform_client
    assert client.get("/api/v1/admin/overview").status_code == 403

    original_user_override = app.dependency_overrides.pop(routes.get_current_user)
    try:
        assert client.get("/api/v1/admin/overview").status_code == 401
    finally:
        app.dependency_overrides[routes.get_current_user] = original_user_override

    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(owner.id)))
    response = client.get("/api/v1/admin/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["users_total"] == 1
    assert data["users_active"] == 1
    assert data["assets_total"] == 2
    assert data["assets_with_scans"] == 1
    assert data["scans_total"] == 3
    assert data["scans_by_status"] == {"pending": 0, "running": 0, "completed": 2, "partial": 1, "failed": 0}
    assert data["findings_by_severity"] == {"critical": 1, "high": 1, "medium": 2, "low": 1, "info": 0}
    assert data["recent_activity"] == []
    assert data["failed_login_counters_active"] == 0


def test_admin_database_diagnostics_is_read_only_and_reports_required_tables(platform_client, monkeypatch):
    from app.config import Settings

    client, _, admin = platform_client
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(admin.id)))

    response = client.get("/api/v1/admin/database-diagnostics")

    assert response.status_code == 200
    data = response.json()
    assert data["database"] == "healthy"
    assert data["required_tables"]["password_reset_challenges"] is True
    assert data["required_tables"]["users"] is True
    assert data["expected_head"] == "20261030_0010"
    assert data["revision_state"] == "missing_revision_table"


def test_all_admin_routes_deny_authenticated_non_allowlisted_accounts(platform_client, monkeypatch):
    from app.config import Settings

    client, factory, user = platform_client
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=""))
    read_paths = [
        "/api/v1/admin/overview",
        "/api/v1/admin/health",
        "/api/v1/admin/database-diagnostics",
        "/api/v1/admin/users",
        "/api/v1/admin/assets",
        "/api/v1/admin/findings",
        "/api/v1/admin/audit",
    ]

    assert [client.get(path).status_code for path in read_paths] == [403] * len(read_paths)
    assert client.patch(
        f"/api/v1/admin/users/{user.id}/status",
        json={"is_active": False, "current_password": "not-checked-without-admin"},
    ).status_code == 403
    assert client.post(
        f"/api/v1/admin/users/{user.id}/sessions/revoke",
        json={"current_password": "not-checked-without-admin"},
    ).status_code == 403
    with factory() as db:
        assert db.get(User, user.id).is_active is True


def test_admin_asset_and_finding_inventory_is_paginated_and_uses_persisted_records(platform_client, monkeypatch):
    from app.config import Settings

    client, factory, admin = platform_client
    with factory() as db:
        db.add(VerificationAttempt(scan_id=1, finding_id=11, status="failed", summary="Could not verify"))
        db.add(FindingRemediation(finding_id=11, owner_id=admin.id, status="in_progress", updated_by=admin.id))
        db.commit()
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(admin.id)))

    assets = client.get("/api/v1/admin/assets", params={"q": "owned", "limit": 1})
    assert assets.status_code == 200
    assert assets.json()["total"] == 1
    assert assets.json()["items"][0]["owner_email"] == admin.email
    assert assets.json()["items"][0]["scan_count"] == 1
    assert assets.json()["items"][0]["latest_scan_status"] == "completed"
    assert client.get("/api/v1/admin/assets", params={"q": "private.example"}).json()["total"] == 1

    findings = client.get("/api/v1/admin/findings", params={"q": "Not observed", "severity": "high"})
    assert findings.status_code == 200
    assert findings.json()["total"] == 1
    item = findings.json()["items"][0]
    assert item["id"] == 11
    assert item["owner_email"] == admin.email
    assert item["target_url"] == "https://owned.example"
    assert item["evidence"] == "Not observed"
    assert item["remediation_status"] == "in_progress"
    assert item["verification_count"] == 1
    assert item["latest_verification_status"] == "failed"

    private_findings = client.get("/api/v1/admin/findings", params={"q": "Other account"})
    assert private_findings.status_code == 200
    assert private_findings.json()["items"][0]["owner_id"] == admin.id + 1


def test_admin_user_search_and_status_mutation_reauthenticate_revoke_and_audit(platform_client, monkeypatch):
    from app.config import Settings

    client, factory, admin = platform_client
    target = User(id=admin.id + 1, email="governed@example.test", display_name="Governed User", password_hash="target-hash", is_active=True)
    with factory() as db:
        db.add(target)
        db.add(AuthSession(id=911, user_id=target.id, token_hash="a" * 64, csrf_token_hash="b" * 64, expires_at=datetime.now(UTC) + timedelta(hours=1)))
        db.commit()
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(admin.id)))
    monkeypatch.setattr(routes, "verify_password", lambda password, _encoded: password == "correct-current-password")

    listing = client.get("/api/v1/admin/users", params={"q": "governed", "status": "active", "limit": 1})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["email"] == target.email
    assert listing.json()["items"][0]["is_admin"] is False

    bad_reauth = client.patch(f"/api/v1/admin/users/{target.id}/status", json={"is_active": False, "current_password": "wrong"})
    assert bad_reauth.status_code == 403
    assert client.get("/api/v1/admin/users", params={"status": "active"}).json()["total"] == 2

    disabled = client.patch(f"/api/v1/admin/users/{target.id}/status", json={"is_active": False, "current_password": "correct-current-password"})
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False
    with factory() as db:
        session = db.get(AuthSession, 911)
        assert session is not None and session.revoked_at is not None
        event = db.query(ActivityEvent).filter_by(event_type="admin.user_disabled", owner_id=admin.id).one()
        assert "revoked 1 active session(s)" in event.summary


def test_admin_account_mutation_requires_csrf_even_for_allowlisted_reauthenticated_admin(platform_client, monkeypatch):
    import hashlib

    from app.config import Settings

    client, factory, admin = platform_client
    target = User(id=admin.id + 3, email="csrf-target@example.test", display_name="CSRF Target", password_hash="target-hash", is_active=True)
    raw_session = "isolated-admin-session-token"
    raw_csrf = "isolated-admin-csrf-token"
    with factory() as db:
        db.add(target)
        db.add(AuthSession(
            id=931,
            user_id=admin.id,
            token_hash=hashlib.sha256(raw_session.encode()).hexdigest(),
            csrf_token_hash=hashlib.sha256(raw_csrf.encode()).hexdigest(),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ))
        db.commit()
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(admin.id)))
    monkeypatch.setattr(routes, "verify_password", lambda *_: True)
    app.dependency_overrides.pop(routes.require_csrf, None)
    client.cookies.set("sentinel_session", raw_session)
    client.cookies.set("sentinel_csrf", raw_csrf)

    endpoint = f"/api/v1/admin/users/{target.id}/status"
    payload = {"is_active": False, "current_password": "valid-re-auth"}
    rejected = client.patch(endpoint, json=payload)
    assert rejected.status_code == 403
    with factory() as db:
        assert db.get(User, target.id).is_active is True

    accepted = client.patch(endpoint, json=payload, headers={"X-CSRF-Token": raw_csrf})
    assert accepted.status_code == 200
    assert accepted.json()["is_active"] is False


def test_admin_cannot_disable_self_or_another_configured_administrator(platform_client, monkeypatch):
    from app.config import Settings

    client, factory, admin = platform_client
    peer = User(id=admin.id + 1, email="peer-admin@example.test", display_name="Peer Admin", password_hash="peer-hash", is_active=True)
    with factory() as db:
        db.add(peer)
        db.commit()
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=f"{admin.id},{peer.id}"))
    monkeypatch.setattr(routes, "verify_password", lambda *_: True)

    self_disable = client.patch(f"/api/v1/admin/users/{admin.id}/status", json={"is_active": False, "current_password": "reauth"})
    peer_disable = client.patch(f"/api/v1/admin/users/{peer.id}/status", json={"is_active": False, "current_password": "reauth"})
    assert self_disable.status_code == 409
    assert peer_disable.status_code == 409
    with factory() as db:
        assert db.get(User, admin.id).is_active is True
        assert db.get(User, peer.id).is_active is True


def test_admin_session_revocation_is_reauthenticated_and_audited(platform_client, monkeypatch):
    from app.config import Settings

    client, factory, admin = platform_client
    target = User(id=admin.id + 2, email="session-target@example.test", display_name="Session Target", password_hash="target-hash", is_active=True)
    with factory() as db:
        db.add(target)
        db.add_all([
            AuthSession(id=921, user_id=target.id, token_hash="c" * 64, csrf_token_hash="d" * 64, expires_at=datetime.now(UTC) + timedelta(hours=1)),
            AuthSession(id=922, user_id=target.id, token_hash="e" * 64, csrf_token_hash="f" * 64, expires_at=datetime.now(UTC) + timedelta(hours=1)),
        ])
        db.commit()
    monkeypatch.setattr(routes, "get_settings", lambda: Settings(_env_file=None, admin_user_ids=str(admin.id)))
    monkeypatch.setattr(routes, "verify_password", lambda *_: True)

    response = client.post(f"/api/v1/admin/users/{target.id}/sessions/revoke", json={"current_password": "reauth"})
    assert response.status_code == 200
    assert response.json()["revoked_sessions"] == 2
    audit = client.get("/api/v1/admin/audit", params={"q": "admin.sessions_revoked"})
    assert audit.status_code == 200
    assert audit.json()[0]["actor_email"] == admin.email
    with factory() as db:
        sessions = db.query(AuthSession).filter(AuthSession.user_id == target.id).all()
        assert all(session.revoked_at is not None for session in sessions)
