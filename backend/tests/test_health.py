from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_summary_starts_empty() -> None:
    response = client.get("/api/v1/summary")

    assert response.status_code == 200
    assert response.json()["repositories"] == 0

