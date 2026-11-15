from app.github import parse_github_url
from app.evaluation import evaluate_benchmark
from app.parsers import parse_openapi_document, parse_source_file
from app.retrieval import EMBEDDING_DIMENSIONS, classify_with_llm, embed_text, rerank
from app.security import scan_builtin


def test_parse_python_symbols() -> None:
    symbols = parse_source_file("service.py", "class Service:\n    def run(self):\n        return True\n")

    assert {symbol["name"] for symbol in symbols} == {"Service", "run"}


def test_parse_openapi_endpoints() -> None:
    endpoints = parse_openapi_document(
        "openapi.yaml",
        """
openapi: 3.0.0
paths:
  /users:
    get:
      operationId: listUsers
      summary: List users
""",
    )

    assert endpoints == [
        {
            "source_file": "openapi.yaml",
            "path": "/users",
            "method": "GET",
            "operation_id": "listUsers",
            "summary": "List users",
        }
    ]


def test_parse_github_url() -> None:
    assert parse_github_url("https://github.com/openai/securechange.git") == ("openai", "securechange")


def test_retrieval_embedding_and_reranking() -> None:
    vector = embed_text("database migration users table")
    assert len(vector) == EMBEDDING_DIMENSIONS
    results = rerank(
        "database migration",
        [
            {"path": "infra/schema.sql", "content": "CREATE TABLE users", "embedding": embed_text("database migration users table")},
            {"path": "README.md", "content": "This dashboard renders commits", "embedding": embed_text("dashboard commits")},
        ],
        1,
    )
    assert results[0]["path"] == "infra/schema.sql"
    assert results[0]["score"] > 0


def test_finding_explanation_has_evidence() -> None:
    result = classify_with_llm(
        "A response code was removed from an API",
        [{"path": "openapi.yaml", "content": "responses", "embedding": embed_text("responses")}],
    )
    assert result["category"] == "breaking_change"
    assert result["evidence"][0]["path"] == "openapi.yaml"


def test_security_scan_detects_missing_auth_and_secret(tmp_path) -> None:
    source = tmp_path / "routes.py"
    source.write_text(
        '@app.get("/admin")\n'
        "def admin():\n"
        "    return 'ok'\n"
        'API_KEY = "hardcoded-secret-value"\n'
    )
    findings = scan_builtin(tmp_path, ["routes.py"])
    rules = {item["rule"] for item in findings}
    assert "missing-authorization" in rules
    assert "hardcoded-credential" in rules


def test_benchmark_reports_detection_metrics() -> None:
    result = evaluate_benchmark()
    assert result["benchmark"] == "securechange-intentional-bugs-v1"
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["f1"] == 1.0
