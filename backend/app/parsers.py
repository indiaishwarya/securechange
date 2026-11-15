import ast
import json
import re
from pathlib import Path

import yaml


SUPPORTED_SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}
OPENAPI_NAMES = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}


def parse_source_file(path: str, content: str) -> list[dict]:
    extension = Path(path).suffix.lower()
    if extension == ".py":
        return parse_python_symbols(path, content)
    if extension in {".js", ".jsx", ".ts", ".tsx"}:
        return parse_javascript_symbols(path, content)
    return parse_generic_symbols(path, content)


def parse_python_symbols(path: str, content: str) -> list[dict]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    symbols = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append({
                "path": path,
                "name": node.name,
                "kind": "class" if isinstance(node, ast.ClassDef) else "function",
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno),
            })
    return symbols


def parse_javascript_symbols(path: str, content: str) -> list[dict]:
    patterns = [
        ("function", re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")),
        ("function", re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(")),
        ("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")),
        ("method", re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{")),
    ]
    symbols = []
    lines = content.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for kind, pattern in patterns:
            for match in pattern.finditer(line):
                symbols.append({"path": path, "name": match.group(1), "kind": kind, "line_start": line_number, "line_end": line_number})
    return symbols


def parse_generic_symbols(path: str, content: str) -> list[dict]:
    symbols = []
    pattern = re.compile(r"^\s*(?:func|class|public\s+\w+\s+\w+)\s+([A-Za-z_][\w]*)")
    for line_number, line in enumerate(content.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            symbols.append({"path": path, "name": match.group(1), "kind": "symbol", "line_start": line_number, "line_end": line_number})
    return symbols


def parse_openapi_document(source_file: str, content: str) -> list[dict]:
    return [
        {
            "source_file": endpoint["source_file"],
            "path": endpoint["path"],
            "method": endpoint["method"],
            "operation_id": endpoint.get("operation_id"),
            "summary": endpoint.get("summary"),
        }
        for endpoint in parse_openapi_contract(source_file, content)
    ]


def parse_openapi_contract(source_file: str, content: str) -> list[dict]:
    try:
        document = json.loads(content) if source_file.endswith(".json") else yaml.safe_load(content)
    except (json.JSONDecodeError, yaml.YAMLError):
        return []
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return []
    endpoints = []
    for path, operations in document["paths"].items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            parameters = []
            for parameter in operation.get("parameters", []) or []:
                if isinstance(parameter, dict):
                    parameters.append({
                        "name": parameter.get("name"),
                        "in": parameter.get("in"),
                        "required": bool(parameter.get("required", False)),
                    })
            request_body = operation.get("requestBody") or {}
            endpoints.append({
                "source_file": source_file,
                "path": str(path),
                "method": method.upper(),
                "operation_id": operation.get("operationId"),
                "summary": operation.get("summary") or operation.get("description"),
                "parameters": parameters,
                "request_body_required": bool(request_body.get("required", False)) if isinstance(request_body, dict) else False,
                "responses": sorted(str(code) for code in (operation.get("responses") or {}).keys()),
            })
    return endpoints


def ingest_repository_files(repository_root: Path, files: list[str]) -> tuple[list[dict], list[dict]]:
    symbols: list[dict] = []
    endpoints: list[dict] = []
    for relative_path in files:
        source_path = repository_root / relative_path
        if not source_path.is_file():
            continue
        if source_path.suffix.lower() in SUPPORTED_SOURCE_EXTENSIONS:
            try:
                symbols.extend(parse_source_file(relative_path, source_path.read_text(errors="ignore")))
            except OSError:
                continue
        if source_path.name.lower() in OPENAPI_NAMES:
            try:
                endpoints.extend(parse_openapi_document(relative_path, source_path.read_text(errors="ignore")))
            except OSError:
                continue
    return symbols, endpoints

