import re
from pathlib import Path

from .parsers import OPENAPI_NAMES, parse_openapi_contract


SCHEMA_MARKERS = {"schema.sql", "schema.yaml", "schema.yml", "schema.json", "migration.sql"}
SCHEMA_EXTENSIONS = {".sql"}
IGNORED_TOP_LEVEL = {".github", ".git", "docs", "tests", "test", "scripts"}


def service_for_path(path: str) -> str:
    parts = Path(path).parts
    if len(parts) > 1 and parts[0] not in {"infra", "docker"}:
        return parts[0]
    if parts and parts[0] == "infra":
        return "infra"
    return "root"


def is_schema_file(path: str) -> bool:
    lower = path.lower()
    name = Path(path).name.lower()
    return (
        Path(path).suffix.lower() in SCHEMA_EXTENSIONS
        or name in SCHEMA_MARKERS
        or "migration" in lower
        or "/migrations/" in f"/{lower}/"
        or "/alembic/" in f"/{lower}/"
        or "/prisma/" in f"/{lower}/"
    )


def tracked_files_at_ref(run_git, repository_root: Path, ref: str) -> list[str]:
    return run_git(repository_root, "ls-tree", "-r", "--name-only", ref).splitlines()


def file_at_ref(run_git, repository_root: Path, ref: str, path: str) -> str:
    try:
        return run_git(repository_root, "show", f"{ref}:{path}")
    except Exception:
        return ""


def openapi_at_ref(run_git, repository_root: Path, ref: str) -> list[dict]:
    endpoints: list[dict] = []
    for path in tracked_files_at_ref(run_git, repository_root, ref):
        if Path(path).name.lower() in OPENAPI_NAMES:
            endpoints.extend(parse_openapi_contract(path, file_at_ref(run_git, repository_root, ref, path)))
    return endpoints


def imports_for_content(path: str, content: str) -> list[str]:
    if Path(path).suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}:
        return []
    patterns = [
        r"^\s*from\s+([A-Za-z0-9_./-]+)\s+import\s+",
        r"^\s*import\s+(?:[^'\"]+from\s+)?['\"]([^'\"]+)['\"]",
        r"^\s*import\s+([A-Za-z0-9_./-]+)",
    ]
    values = []
    for line in content.splitlines():
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                values.append(match.group(1))
                break
    return values


def schema_objects(content: str) -> dict[str, set[str]]:
    result = {"tables": set(), "columns": set(), "indexes": set()}
    table_pattern = r"\b(?:CREATE|ALTER|DROP)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[\"']?([A-Za-z_][\w.]*)"
    column_pattern = r"\b(?:ADD|DROP|ALTER)\s+COLUMN\s+[\"']?([A-Za-z_][\w]*)"
    index_pattern = r"\b(?:CREATE|DROP)\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[\"']?([A-Za-z_][\w]*)"
    result["tables"].update(match.lower() for match in re.findall(table_pattern, content, re.IGNORECASE))
    result["columns"].update(match.lower() for match in re.findall(column_pattern, content, re.IGNORECASE))
    result["indexes"].update(match.lower() for match in re.findall(index_pattern, content, re.IGNORECASE))
    return result


def database_impact(run_git, repository_root: Path, base_ref: str, target_ref: str, changed_files: list[dict]) -> list[dict]:
    schema_paths = {file["path"] for file in changed_files if is_schema_file(file["path"])}
    findings = []
    for path in sorted(schema_paths):
        before = schema_objects(file_at_ref(run_git, repository_root, base_ref, path))
        after = schema_objects(file_at_ref(run_git, repository_root, target_ref, path))
        path_findings = []
        for object_type in before:
            for name in sorted(before[object_type] - after[object_type]):
                path_findings.append({"change_type": "removed", "object_type": object_type[:-1], "object": name, "source_file": path, "details": f"{object_type[:-1].title()} {name} is no longer present.", "breaking": object_type in {"tables", "columns"}})
            for name in sorted(after[object_type] - before[object_type]):
                path_findings.append({"change_type": "added", "object_type": object_type[:-1], "object": name, "source_file": path, "details": f"{object_type[:-1].title()} {name} was added.", "breaking": False})
        if not path_findings:
            path_findings.append({"change_type": "modified", "object_type": "schema", "object": path, "source_file": path, "details": "Schema or migration file changed; review downstream queries and migrations.", "breaking": False})
        findings.extend(path_findings)
    return findings


def build_impact_graph(run_git, repository_root: Path, base_ref: str, target_ref: str, changed_files: list[dict], api_changes: list[dict]) -> dict:
    files = tracked_files_at_ref(run_git, repository_root, target_ref)
    services = {service_for_path(path) for path in files if service_for_path(path) not in IGNORED_TOP_LEVEL}
    nodes = [{"id": f"service:{service}", "label": service, "type": "service", "affected": any(service_for_path(item["path"]) == service for item in changed_files)} for service in sorted(services)]
    edges = []
    seen_edges = set()
    for path in files:
        service = service_for_path(path)
        if path.startswith(".env") or Path(path).suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}:
            continue
        for imported in imports_for_content(path, file_at_ref(run_git, repository_root, target_ref, path)):
            imported_top = imported.replace("\\", "/").lstrip("./").split("/")[0]
            if imported_top in services and imported_top != service:
                edge = (f"service:{service}", f"service:{imported_top}", "imports")
                if edge not in seen_edges:
                    edges.append({"source": edge[0], "target": edge[1], "label": edge[2]})
                    seen_edges.add(edge)

    for endpoint in openapi_at_ref(run_git, repository_root, target_ref):
        service = service_for_path(endpoint["source_file"])
        node_id = f"api:{endpoint['method']}:{endpoint['path']}"
        affected = any(item["method"] == endpoint["method"] and item["path"] == endpoint["path"] for item in api_changes)
        nodes.append({"id": node_id, "label": f"{endpoint['method']} {endpoint['path']}", "type": "api", "affected": affected})
        edges.append({"source": f"service:{service}", "target": node_id, "label": "exposes"})

    schema_paths = [path for path in files if is_schema_file(path)]
    schema_findings = database_impact(run_git, repository_root, base_ref, target_ref, changed_files)
    if schema_paths:
        nodes.append({"id": "database:primary", "label": "database schema", "type": "database", "affected": bool(schema_findings)})
        for path in schema_paths:
            edges.append({"source": f"service:{service_for_path(path)}", "target": "database:primary", "label": "updates schema"})

    changed_services = sorted({service_for_path(item["path"]) for item in changed_files})
    changed_ids = {f"service:{service}" for service in changed_services}
    affected_clients = sorted({edge["source"].split(":", 1)[1] for edge in edges if edge["target"] in changed_ids and edge["source"].startswith("service:") and edge["source"] not in changed_ids})
    return {"nodes": nodes, "edges": edges, "affected_services": changed_services, "affected_clients": affected_clients, "database_findings": schema_findings}
