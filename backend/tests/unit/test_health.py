"""Health endpoint tests."""

from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_local_database_and_optional_services() -> None:
    """The simple setup reports unavailable optional services honestly."""
    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["database"] == "up"
    assert body["redis"] == "unavailable"
    assert body["worker"] == "unavailable"
    assert body["status"] == "degraded"
    assert "X-Content-Type-Options" in response.headers
