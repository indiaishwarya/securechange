import subprocess
import re
import time
from uuid import uuid4
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import get_settings
from .database import (
    database_summary,
    fetch_knowledge_chunks,
    fetch_scan_history,
    persist_ingestion,
    persist_knowledge_chunks,
    persist_scan_history,
    persist_security_findings,
)
from .evaluation import evaluate_benchmark
from .github import inspect_github_repository, post_pull_request_comment
from .impact import build_impact_graph, database_impact
from .monitoring import metrics
from .parsers import ingest_repository_files, parse_openapi_contract
from .retrieval import build_repository_chunks, classify_with_llm, rerank
from .security import scan_repository

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="API for detecting software, API, and security change impact.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        started = time.perf_counter()
        metrics.begin()
        try:
            response = await call_next(request)
        except Exception:
            metrics.finish(request.url.path, 500)
            raise
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(round((time.perf_counter() - started) * 1000, 2))
        metrics.finish(request.url.path, response.status_code)
        return response


app.add_middleware(RequestMetricsMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "detail": exc.errors(), "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    print(f"Unhandled request error request_id={request_id} error={type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": "An unexpected server error occurred.", "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: datetime


class RepositoryInspectRequest(BaseModel):
    root_path: str


class CommitSummary(BaseModel):
    sha: str
    short_sha: str
    subject: str
    author: str
    authored_at: str


class RepositoryInspectResponse(BaseModel):
    name: str
    root_path: str
    current_branch: str
    branches: list[str]
    files: list[str]
    commits: list[CommitSummary]
    symbol_count: int = 0
    api_endpoint_count: int = 0
    persisted: bool = False
    persistence_error: str | None = None


class GitHubInspectRequest(BaseModel):
    repository_url: str


class GitHubInspectResponse(BaseModel):
    name: str
    url: str
    default_branch: str
    description: str | None
    stars: int
    commits: list[CommitSummary]
    pull_requests: list[dict]
    persisted: bool = False
    persistence_error: str | None = None


class RepositoryCompareRequest(BaseModel):
    root_path: str
    base_ref: str
    target_ref: str


class DiffHunk(BaseModel):
    header: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context: str
    symbols: list[str]


class ChangedFile(BaseModel):
    status: str
    path: str
    old_path: str | None = None
    new_path: str | None = None
    additions: int
    deletions: int
    hunks: list[DiffHunk]


class RepositoryCompareResponse(BaseModel):
    name: str
    base_ref: str
    target_ref: str
    files_changed: int
    additions: int
    deletions: int
    added_files: int
    modified_files: int
    deleted_files: int
    renamed_files: int
    changed_files: list[ChangedFile]


class ApiChange(BaseModel):
    change_type: str
    method: str
    path: str
    source_file: str | None = None
    details: list[str]
    breaking: bool = False


class BreakingFinding(BaseModel):
    severity: str
    rule: str
    method: str
    path: str
    details: str


class RepositoryAnalysisResponse(BaseModel):
    name: str
    base_ref: str
    target_ref: str
    files_changed: int
    additions: int
    deletions: int
    added_files: int
    modified_files: int
    deleted_files: int
    renamed_files: int
    changed_files: list[ChangedFile]
    changed_functions: list[str]
    api_changes: list[ApiChange]
    breaking_findings: list[BreakingFinding]
    openapi_files: list[str]


class ImpactResponse(BaseModel):
    name: str
    base_ref: str
    target_ref: str
    nodes: list[dict]
    edges: list[dict]
    affected_services: list[str]
    affected_clients: list[str]
    database_findings: list[dict]


class RetrievalIndexRequest(BaseModel):
    root_path: str


class RetrievalSearchRequest(BaseModel):
    root_path: str
    query: str
    top_k: int = 5


class FindingExplanationRequest(BaseModel):
    root_path: str
    finding: str
    top_k: int = 5


class SecurityScanRequest(BaseModel):
    root_path: str


class PullRequestCommentRequest(BaseModel):
    repository_url: str
    pull_number: int
    body: str


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        timestamp=datetime.now(UTC),
    )


@app.get("/ready", tags=["system"])
def readiness() -> dict[str, str]:
    """Readiness probe: the process is ready only when the database is reachable."""
    try:
        from .database import connection

        with connection() as conn:
            conn.execute("SELECT 1")
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Database is not ready: {type(error).__name__}") from error
    return {"status": "ready", "service": settings.app_name}


@app.get("/metrics", tags=["system"])
def application_metrics() -> dict:
    return metrics.snapshot()


@app.get("/api/v1/summary", tags=["dashboard"])
def summary() -> dict[str, int]:
    try:
        return database_summary()
    except Exception:
        return {"repositories": 0, "scans": 0, "critical_findings": 0, "pending_reviews": 0}


def run_git(root_path: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root_path), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError as error:
        raise HTTPException(status_code=500, detail="Git is not installed on the backend host.") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or "Git command failed."
        raise HTTPException(status_code=400, detail=detail) from error
    except subprocess.TimeoutExpired as error:
        raise HTTPException(status_code=408, detail="Git command timed out.") from error
    return result.stdout.strip()


def resolve_repository(root_path: str) -> Path:
    requested_path = Path(root_path).expanduser().resolve()
    if not requested_path.exists() or not requested_path.is_dir():
        raise HTTPException(status_code=400, detail="Repository path does not exist or is not a directory.")

    try:
        return Path(run_git(requested_path, "rev-parse", "--show-toplevel"))
    except HTTPException as error:
        if error.status_code == 400:
            raise HTTPException(status_code=400, detail="The selected directory is not a Git repository.") from error
        raise


def verify_commit(repository_root: Path, ref: str) -> str:
    if not ref.strip():
        raise HTTPException(status_code=400, detail="A base and target commit are required.")
    return run_git(repository_root, "rev-parse", "--verify", f"{ref}^{{commit}}")


def parse_hunks(repository_root: Path, base_ref: str, target_ref: str, path: str) -> tuple[int, int, list[DiffHunk]]:
    diff = run_git(
        repository_root,
        "diff",
        "--no-ext-diff",
        "--unified=0",
        "--function-context",
        base_ref,
        target_ref,
        "--",
        path,
    )
    additions = 0
    deletions = 0
    hunks: list[DiffHunk] = []
    current_hunk: DiffHunk | None = None
    hunk_pattern = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: (.*))?$")

    for line in diff.splitlines():
        if line.startswith("@@ "):
            match = hunk_pattern.match(line)
            if not match:
                continue
            old_start, old_count, new_start, new_count, context = match.groups()
            current_hunk = DiffHunk(
                header=line,
                old_start=int(old_start),
                old_count=int(old_count or 1),
                new_start=int(new_start),
                new_count=int(new_count or 1),
                context=(context or "").strip(),
                symbols=[],
            )
            hunks.append(current_hunk)
            continue

        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1

        if current_hunk and line[:1] in {"+", "-", " "}:
            current_hunk.symbols.extend(extract_symbols(line[1:]))

    for hunk in hunks:
        hunk.symbols = sorted(set(hunk.symbols))
        if hunk.context:
            hunk.symbols = sorted(set(hunk.symbols + extract_symbols(hunk.context)))

    return additions, deletions, hunks


def extract_symbols(text: str) -> list[str]:
    patterns = [
        r"\b(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\b(?:public|private|protected|static|async|final|virtual|override|inline|const)\s+(?:[A-Za-z_][\w:<>,\[\]]*\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    ]
    symbols = []
    for pattern in patterns:
        symbols.extend(re.findall(pattern, text))
    return symbols


@app.post("/api/v1/repositories/inspect", response_model=RepositoryInspectResponse, tags=["repositories"])
def inspect_repository(request: RepositoryInspectRequest) -> RepositoryInspectResponse:
    repository_root = resolve_repository(request.root_path)

    branch_output = run_git(repository_root, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
    current_branch = run_git(repository_root, "branch", "--show-current") or "detached HEAD"
    file_output = run_git(repository_root, "ls-files")
    commit_output = run_git(
        repository_root,
        "log",
        "-n",
        "20",
        "--date=iso-strict",
        "--pretty=format:%H%x09%h%x09%s%x09%an%x09%aI",
    )

    commits = []
    for line in commit_output.splitlines():
        sha, short_sha, subject, author, authored_at = line.split("\t", maxsplit=4)
        commits.append(
            CommitSummary(
                sha=sha,
                short_sha=short_sha,
                subject=subject,
                author=author,
                authored_at=authored_at,
            )
        )

    symbols, endpoints = ingest_repository_files(repository_root, file_output.splitlines())
    persisted = False
    persistence_error = None
    try:
        persist_ingestion(
            name=repository_root.name,
            provider="local",
            url=f"file://{repository_root}",
            commits=[commit.model_dump() for commit in commits],
            files=file_output.splitlines(),
            symbols=symbols,
            endpoints=endpoints,
        )
        persisted = True
    except Exception as error:
        persistence_error = f"{type(error).__name__}: {error}"
        print(f"Repository persistence failed: {persistence_error}")
        persisted = False

    return RepositoryInspectResponse(
        name=repository_root.name,
        root_path=str(repository_root),
        current_branch=current_branch,
        branches=branch_output.splitlines(),
        files=file_output.splitlines(),
        commits=commits,
        symbol_count=len(symbols),
        api_endpoint_count=len(endpoints),
        persisted=persisted,
        persistence_error=persistence_error,
    )


@app.post("/api/v1/github/inspect", response_model=GitHubInspectResponse, tags=["github"])
def inspect_github(request: GitHubInspectRequest) -> GitHubInspectResponse:
    data = inspect_github_repository(request.repository_url)
    commits = [CommitSummary(**commit) for commit in data["commits"]]
    persisted = False
    persistence_error = None
    try:
        persist_ingestion(
            name=data["name"].split("/")[-1],
            provider="github",
            url=data["url"],
            commits=data["commits"],
            files=[],
            symbols=[],
            endpoints=[],
            pull_requests=data["pull_requests"],
        )
        persisted = True
    except Exception as error:
        persistence_error = f"{type(error).__name__}: {error}"
        print(f"GitHub persistence failed: {persistence_error}")
        persisted = False
    return GitHubInspectResponse(
        name=data["name"],
        url=data["url"],
        default_branch=data["default_branch"],
        description=data["description"],
        stars=data["stars"],
        commits=commits,
        pull_requests=data["pull_requests"],
        persisted=persisted,
        persistence_error=persistence_error,
    )


@app.post("/api/v1/repositories/compare", response_model=RepositoryCompareResponse, tags=["repositories"])
def compare_repository(request: RepositoryCompareRequest) -> RepositoryCompareResponse:
    repository_root = resolve_repository(request.root_path)
    base_sha = verify_commit(repository_root, request.base_ref)
    target_sha = verify_commit(repository_root, request.target_ref)

    name_status = run_git(
        repository_root,
        "diff",
        "--name-status",
        "--find-renames",
        base_sha,
        target_sha,
        "--",
    )
    changed_files: list[ChangedFile] = []
    status_counts = {"A": 0, "M": 0, "D": 0, "R": 0}

    for line in name_status.splitlines():
        columns = line.split("\t")
        status_code = columns[0][0]
        status_counts[status_code] = status_counts.get(status_code, 0) + 1
        if status_code == "R" and len(columns) >= 3:
            old_path, new_path = columns[1], columns[2]
            additions, deletions, hunks = parse_hunks(repository_root, base_sha, target_sha, new_path)
            changed_files.append(
                ChangedFile(
                    status="R",
                    path=new_path,
                    old_path=old_path,
                    new_path=new_path,
                    additions=additions,
                    deletions=deletions,
                    hunks=hunks,
                )
            )
            continue

        path = columns[-1]
        additions, deletions, hunks = parse_hunks(repository_root, base_sha, target_sha, path)
        changed_files.append(
            ChangedFile(
                status=status_code,
                path=path,
                new_path=path if status_code != "D" else None,
                additions=additions,
                deletions=deletions,
                hunks=hunks,
            )
        )

    return RepositoryCompareResponse(
        name=repository_root.name,
        base_ref=base_sha,
        target_ref=target_sha,
        files_changed=len(changed_files),
        additions=sum(file.additions for file in changed_files),
        deletions=sum(file.deletions for file in changed_files),
        added_files=status_counts.get("A", 0),
        modified_files=status_counts.get("M", 0),
        deleted_files=status_counts.get("D", 0),
        renamed_files=status_counts.get("R", 0),
        changed_files=changed_files,
    )


def openapi_files_at_ref(repository_root: Path, ref: str) -> list[str]:
    files = run_git(repository_root, "ls-tree", "-r", "--name-only", ref).splitlines()
    return [
        path for path in files
        if Path(path).name.lower() in {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}
    ]


def openapi_contract_at_ref(repository_root: Path, ref: str) -> tuple[list[str], dict[tuple[str, str], dict]]:
    file_paths = openapi_files_at_ref(repository_root, ref)
    contract: dict[tuple[str, str], dict] = {}
    for path in file_paths:
        try:
            content = run_git(repository_root, "show", f"{ref}:{path}")
        except HTTPException:
            continue
        for endpoint in parse_openapi_contract(path, content):
            contract[(endpoint["method"], endpoint["path"])] = endpoint
    return file_paths, contract


def compare_openapi_contracts(repository_root: Path, base_ref: str, target_ref: str) -> tuple[list[ApiChange], list[BreakingFinding], list[str]]:
    base_files, base_contract = openapi_contract_at_ref(repository_root, base_ref)
    target_files, target_contract = openapi_contract_at_ref(repository_root, target_ref)
    api_changes: list[ApiChange] = []
    breaking_findings: list[BreakingFinding] = []
    keys = sorted(set(base_contract) | set(target_contract))

    for key in keys:
        method, path = key
        before = base_contract.get(key)
        after = target_contract.get(key)
        source_file = (after or before).get("source_file")
        if before is None:
            api_changes.append(ApiChange(change_type="added", method=method, path=path, source_file=source_file, details=["Endpoint was added."], breaking=False))
            continue
        if after is None:
            details = ["Endpoint was removed from the target contract."]
            api_changes.append(ApiChange(change_type="removed", method=method, path=path, source_file=source_file, details=details, breaking=True))
            breaking_findings.append(BreakingFinding(severity="critical", rule="endpoint_removed", method=method, path=path, details=details[0]))
            continue

        details: list[str] = []
        before_parameters = {(item.get("name"), item.get("in")): item for item in before.get("parameters", [])}
        after_parameters = {(item.get("name"), item.get("in")): item for item in after.get("parameters", [])}
        for parameter_key, parameter in after_parameters.items():
            if parameter.get("required") and not before_parameters.get(parameter_key, {}).get("required"):
                details.append(f"Parameter {parameter_key[0]} became required.")
                breaking_findings.append(BreakingFinding(severity="high", rule="required_parameter_added", method=method, path=path, details=details[-1]))
        before_responses = set(before.get("responses", []))
        after_responses = set(after.get("responses", []))
        removed_responses = sorted(before_responses - after_responses)
        if removed_responses:
            details.append(f"Response status codes removed: {', '.join(removed_responses)}.")
            breaking_findings.append(BreakingFinding(severity="high", rule="response_removed", method=method, path=path, details=details[-1]))
        if after.get("request_body_required") and not before.get("request_body_required"):
            details.append("Request body became required.")
            breaking_findings.append(BreakingFinding(severity="high", rule="required_request_body", method=method, path=path, details=details[-1]))
        if before.get("operation_id") != after.get("operation_id"):
            details.append("Operation ID changed.")
        if before.get("summary") != after.get("summary"):
            details.append("Summary or description changed.")
        if details:
            api_changes.append(ApiChange(change_type="modified", method=method, path=path, source_file=source_file, details=details, breaking=any(f.path == path and f.method == method for f in breaking_findings)))

    return api_changes, breaking_findings, sorted(set(base_files + target_files))


@app.post("/api/v1/repositories/analyze", response_model=RepositoryAnalysisResponse, tags=["repositories"])
def analyze_repository(request: RepositoryCompareRequest) -> RepositoryAnalysisResponse:
    comparison = compare_repository(request)
    base_sha = verify_commit(resolve_repository(request.root_path), request.base_ref)
    target_sha = verify_commit(resolve_repository(request.root_path), request.target_ref)
    repository_root = resolve_repository(request.root_path)
    api_changes, breaking_findings, openapi_files = compare_openapi_contracts(repository_root, base_sha, target_sha)
    changed_functions = sorted({symbol for file in comparison.changed_files for hunk in file.hunks for symbol in hunk.symbols})
    return RepositoryAnalysisResponse(
        name=repository_root.name,
        base_ref=base_sha,
        target_ref=target_sha,
        files_changed=comparison.files_changed,
        additions=comparison.additions,
        deletions=comparison.deletions,
        added_files=comparison.added_files,
        modified_files=comparison.modified_files,
        deleted_files=comparison.deleted_files,
        renamed_files=comparison.renamed_files,
        changed_files=comparison.changed_files,
        changed_functions=changed_functions,
        api_changes=api_changes,
        breaking_findings=breaking_findings,
        openapi_files=openapi_files,
    )


@app.post("/api/v1/repositories/impact", response_model=ImpactResponse, tags=["repositories"])
def repository_impact(request: RepositoryCompareRequest) -> ImpactResponse:
    repository_root = resolve_repository(request.root_path)
    comparison = compare_repository(request)
    base_sha = verify_commit(repository_root, request.base_ref)
    target_sha = verify_commit(repository_root, request.target_ref)
    api_changes, _, _ = compare_openapi_contracts(repository_root, base_sha, target_sha)
    graph = build_impact_graph(
        run_git,
        repository_root,
        base_sha,
        target_sha,
        [file.model_dump() for file in comparison.changed_files],
        [change.model_dump() for change in api_changes],
    )
    return ImpactResponse(
        name=repository_root.name,
        base_ref=base_sha,
        target_ref=target_sha,
        **graph,
    )


@app.post("/api/v1/repositories/retrieval/index", tags=["retrieval"])
def index_repository(request: RetrievalIndexRequest) -> dict:
    repository_root = resolve_repository(request.root_path)
    files = run_git(repository_root, "ls-files").splitlines()
    chunks = build_repository_chunks(repository_root, files)
    repository_url = f"file://{repository_root}"
    count = persist_knowledge_chunks(repository_url, chunks)
    return {"repository": repository_root.name, "chunks_indexed": count, "embedding_dimensions": 384, "provider": "offline-feature-hash"}


@app.post("/api/v1/repositories/retrieval/search", tags=["retrieval"])
def search_repository(request: RetrievalSearchRequest) -> dict:
    repository_root = resolve_repository(request.root_path)
    repository_url = f"file://{repository_root}"
    rows = fetch_knowledge_chunks(repository_url)
    if not rows:
        files = run_git(repository_root, "ls-files").splitlines()
        rows = build_repository_chunks(repository_root, files)
        persist_knowledge_chunks(repository_url, rows)
    results = rerank(request.query, rows, max(1, min(request.top_k, 20)))
    return {"query": request.query, "results": results, "retrieval": ["bm25", "vector", "score-fusion-reranker"]}


@app.post("/api/v1/repositories/retrieval/explain", tags=["retrieval"])
def explain_finding(request: FindingExplanationRequest) -> dict:
    repository_root = resolve_repository(request.root_path)
    repository_url = f"file://{repository_root}"
    rows = fetch_knowledge_chunks(repository_url)
    if not rows:
        files = run_git(repository_root, "ls-files").splitlines()
        rows = build_repository_chunks(repository_root, files)
        persist_knowledge_chunks(repository_url, rows)
    context = rerank(request.finding, rows, max(1, min(request.top_k, 10)))
    return classify_with_llm(request.finding, context)


@app.post("/api/v1/repositories/security/scan", tags=["security"])
def security_scan(request: SecurityScanRequest) -> dict:
    repository_root = resolve_repository(request.root_path)
    files = run_git(repository_root, "ls-files").splitlines()
    findings, analyzer_status = scan_repository(repository_root, files)
    repository_url = f"file://{repository_root}"
    rows = fetch_knowledge_chunks(repository_url)
    if not rows:
        rows = build_repository_chunks(repository_root, files)
    for item in findings:
        context = rerank(item["message"] + " " + item["rule"], rows, 3)
        item["explanation"] = classify_with_llm(item["message"], context)
    persistence_error = None
    try:
        persist_security_findings(repository_url, findings)
    except Exception as error:
        persistence_error = f"{type(error).__name__}: {error}"
    try:
        persist_scan_history(
            repository_url,
            "security",
            "completed",
            {
                "finding_count": len(findings),
                "critical_count": sum(item["severity"] == "critical" for item in findings),
                "high_count": sum(item["severity"] == "high" for item in findings),
            },
        )
    except Exception as error:
        persistence_error = persistence_error or f"{type(error).__name__}: {error}"
    return {
        "repository": repository_root.name,
        "analyzer_status": analyzer_status,
        "findings": findings,
        "finding_count": len(findings),
        "critical_count": sum(item["severity"] == "critical" for item in findings),
        "high_count": sum(item["severity"] == "high" for item in findings),
        "persistence_error": persistence_error,
    }


@app.post("/api/v1/evaluation/benchmark", tags=["evaluation"])
def benchmark() -> dict:
    return evaluate_benchmark()


@app.post("/api/v1/repositories/history", tags=["history"])
def repository_history(request: RepositoryInspectRequest) -> dict:
    repository_root = resolve_repository(request.root_path)
    return {"repository": repository_root.name, "history": fetch_scan_history(f"file://{repository_root}")}


@app.post("/api/v1/github/pull-requests/comment", tags=["github"])
def comment_on_pull_request(request: PullRequestCommentRequest) -> dict:
    return post_pull_request_comment(request.repository_url, request.pull_number, request.body)

