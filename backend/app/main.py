import subprocess
import re
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import get_settings

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


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        timestamp=datetime.now(UTC),
    )


@app.get("/api/v1/summary", tags=["dashboard"])
def summary() -> dict[str, int]:
    return {
        "repositories": 0,
        "scans": 0,
        "critical_findings": 0,
        "pending_reviews": 0,
    }


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

    return RepositoryInspectResponse(
        name=repository_root.name,
        root_path=str(repository_root),
        current_branch=current_branch,
        branches=branch_output.splitlines(),
        files=file_output.splitlines(),
        commits=commits,
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

