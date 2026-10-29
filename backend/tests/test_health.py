from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.main import app
from app.config import get_settings
from app.schemas import ScanCreate


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "Sentinel AI"}


def test_scan_api_rejects_invalid_target_before_creating_scan() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ScanCreate(target_url="http://127.0.0.1/admin")
    assert "unsafe" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()


def test_development_cors_allows_vite_origins() -> None:
    client = TestClient(app)
    for origin in ("http://localhost:5173", "http://localhost:5174", "http://localhost:5175"):
        response = client.options(
            "/api/v1/health",
            headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin


def test_configured_frontend_can_preflight_patch_requests() -> None:
    client = TestClient(app)
    origin = "http://localhost:5175"
    assert origin in get_settings().cors_origins
    response = client.options(
        "/api/v1/findings/1/remediation",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "PATCH" in response.headers["access-control-allow-methods"]
    assert "x-csrf-token" in response.headers["access-control-allow-headers"].lower()

