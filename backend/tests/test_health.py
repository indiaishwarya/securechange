import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-request-id"]


def test_metrics_endpoint_reports_requests() -> None:
    response = client.get("/metrics")

    assert response.status_code == 200
    data = response.json()
    assert data["requests_total"] >= 1
    assert "status_codes" in data


def test_validation_errors_are_json() -> None:
    response = client.post("/api/v1/repositories/inspect", json={})

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"
    assert response.json()["request_id"]


def test_summary_starts_empty() -> None:
    response = client.get("/api/v1/summary")

    assert response.status_code == 200
    assert response.json()["repositories"] == 0


def test_inspect_repository_rejects_missing_path() -> None:
    response = client.post(
        "/api/v1/repositories/inspect",
        json={"root_path": "/path/that/does/not/exist"},
    )

    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"]


def test_compare_repository_detects_modified_file(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test User"], check=True)
    source_file = tmp_path / "service.py"
    source_file.write_text("def greet():\n    return 'hello'\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "initial"], check=True, capture_output=True)
    base_sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()

    source_file.write_text("def greet():\n    return 'hello world'\n")
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-am", "update greeting"], check=True, capture_output=True)
    target_sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()

    response = client.post(
        "/api/v1/repositories/compare",
        json={"root_path": str(tmp_path), "base_ref": base_sha, "target_ref": target_sha},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["files_changed"] == 1
    assert data["modified_files"] == 1
    assert data["changed_files"][0]["path"] == "service.py"
    assert data["additions"] == 1
    assert data["deletions"] == 1

    analysis_response = client.post(
        "/api/v1/repositories/analyze",
        json={"root_path": str(tmp_path), "base_ref": base_sha, "target_ref": target_sha},
    )

    assert analysis_response.status_code == 200
    analysis = analysis_response.json()
    assert analysis["changed_files"][0]["path"] == "service.py"
    assert analysis["breaking_findings"] == []


def test_impact_analysis_builds_graph_and_schema_findings(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test User"], check=True)
    (tmp_path / "backend").mkdir()
    (tmp_path / "infra" / "db").mkdir(parents=True)
    (tmp_path / "backend" / "service.py").write_text("def serve():\n    return True\n")
    schema = tmp_path / "infra" / "db" / "schema.sql"
    schema.write_text("CREATE TABLE users (id INT);\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "initial"], check=True, capture_output=True)
    base_sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()

    schema.write_text("CREATE TABLE accounts (id INT);\n")
    (tmp_path / "backend" / "service.py").write_text("def serve():\n    return False\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "change service and schema"], check=True, capture_output=True)
    target_sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()

    response = client.post(
        "/api/v1/repositories/impact",
        json={"root_path": str(tmp_path), "base_ref": base_sha, "target_ref": target_sha},
    )

    assert response.status_code == 200
    data = response.json()
    assert "service:backend" in {node["id"] for node in data["nodes"]}
    assert "database:primary" in {node["id"] for node in data["nodes"]}
    assert data["affected_services"] == ["backend", "infra"]
    assert any(finding["object"] == "users" and finding["breaking"] for finding in data["database_findings"])

