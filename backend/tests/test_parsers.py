from app.github import parse_github_url
from app.parsers import parse_openapi_document, parse_source_file


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
