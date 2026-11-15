from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
from typing import Iterator
from uuid import UUID, uuid4

import psycopg

from .config import get_settings


def database_dsn() -> str:
    return get_settings().database_url.replace("postgresql+psycopg://", "postgresql://", 1)


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with psycopg.connect(database_dsn()) as conn:
        yield conn


def ensure_schema() -> None:
    with connection() as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'local',
                url TEXT UNIQUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_ingested_at TIMESTAMPTZ
            )
            """
        )
        conn.execute("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_ingested_at TIMESTAMPTZ")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS repositories_url_unique ON repositories (url)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id UUID PRIMARY KEY,
                repository_id UUID REFERENCES repositories(id),
                base_ref TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repository_commits (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                sha TEXT NOT NULL,
                short_sha TEXT NOT NULL,
                subject TEXT NOT NULL,
                author TEXT NOT NULL,
                authored_at TIMESTAMPTZ,
                UNIQUE(repository_id, sha)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repository_files (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                UNIQUE(repository_id, path)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS source_symbols (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                line_start INT NOT NULL,
                line_end INT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_endpoints (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                source_file TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                operation_id TEXT,
                summary TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pull_requests (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                number INT NOT NULL,
                title TEXT NOT NULL,
                state TEXT NOT NULL,
                author TEXT,
                head_sha TEXT,
                base_ref TEXT,
                url TEXT,
                updated_at TIMESTAMPTZ,
                UNIQUE(repository_id, number)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                chunk_index INT NOT NULL,
                source_type TEXT NOT NULL,
                content TEXT NOT NULL,
                embedding vector(384) NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(repository_id, path, chunk_index)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_findings (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                analyzer TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                path TEXT NOT NULL,
                line INT,
                message TEXT NOT NULL,
                explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id UUID PRIMARY KEY,
                repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                finding_count INT NOT NULL DEFAULT 0,
                critical_count INT NOT NULL DEFAULT 0,
                high_count INT NOT NULL DEFAULT 0,
                summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )


def persist_ingestion(
    *,
    name: str,
    provider: str,
    url: str,
    commits: list[dict],
    files: list[str],
    symbols: list[dict],
    endpoints: list[dict],
    pull_requests: list[dict] | None = None,
) -> UUID:
    ensure_schema()
    repository_id = uuid4()
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO repositories (id, name, provider, url, last_ingested_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (url) DO UPDATE SET
                name = EXCLUDED.name,
                provider = EXCLUDED.provider,
                last_ingested_at = NOW()
            RETURNING id
            """,
            (repository_id, name, provider, url),
        ).fetchone()
        repository_id = row[0]

        conn.execute("DELETE FROM repository_commits WHERE repository_id = %s", (repository_id,))
        conn.execute("DELETE FROM repository_files WHERE repository_id = %s", (repository_id,))
        conn.execute("DELETE FROM source_symbols WHERE repository_id = %s", (repository_id,))
        conn.execute("DELETE FROM api_endpoints WHERE repository_id = %s", (repository_id,))
        conn.execute("DELETE FROM pull_requests WHERE repository_id = %s", (repository_id,))

        for commit in commits:
            conn.execute(
                "INSERT INTO repository_commits (id, repository_id, sha, short_sha, subject, author, authored_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uuid4(), repository_id, commit["sha"], commit["short_sha"], commit["subject"], commit["author"], commit.get("authored_at")),
            )
        for path in files:
            conn.execute("INSERT INTO repository_files (id, repository_id, path) VALUES (%s, %s, %s)", (uuid4(), repository_id, path))
        for symbol in symbols:
            conn.execute(
                "INSERT INTO source_symbols (id, repository_id, path, name, kind, line_start, line_end) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uuid4(), repository_id, symbol["path"], symbol["name"], symbol["kind"], symbol["line_start"], symbol["line_end"]),
            )
        for endpoint in endpoints:
            conn.execute(
                "INSERT INTO api_endpoints (id, repository_id, source_file, path, method, operation_id, summary) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uuid4(), repository_id, endpoint["source_file"], endpoint["path"], endpoint["method"], endpoint.get("operation_id"), endpoint.get("summary")),
            )
        for pull_request in pull_requests or []:
            conn.execute(
                "INSERT INTO pull_requests (id, repository_id, number, title, state, author, head_sha, base_ref, url, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (uuid4(), repository_id, pull_request["number"], pull_request["title"], pull_request["state"], pull_request.get("author"), pull_request.get("head_sha"), pull_request.get("base_ref"), pull_request.get("url"), pull_request.get("updated_at")),
            )
    return repository_id


def database_summary() -> dict[str, int]:
    ensure_schema()
    with connection() as conn:
        repositories = conn.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
        scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        pending_reviews = conn.execute("SELECT COUNT(*) FROM pull_requests WHERE state = 'open'").fetchone()[0]
    return {"repositories": repositories, "scans": scans, "critical_findings": 0, "pending_reviews": pending_reviews}


def persist_knowledge_chunks(repository_url: str, chunks: list[dict]) -> int:
    from .retrieval import vector_literal

    ensure_schema()
    with connection() as conn:
        row = conn.execute("SELECT id FROM repositories WHERE url = %s", (repository_url,)).fetchone()
        if row is None:
            raise ValueError("Inspect the repository before building its retrieval index.")
        repository_id = row[0]
        conn.execute("DELETE FROM knowledge_chunks WHERE repository_id = %s", (repository_id,))
        for chunk in chunks:
            conn.execute(
                """
                INSERT INTO knowledge_chunks
                    (id, repository_id, path, chunk_index, source_type, content, embedding, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s::vector, %s::jsonb)
                """,
                (
                    uuid4(),
                    repository_id,
                    chunk["path"],
                    chunk["chunk_index"],
                    chunk["source_type"],
                    chunk["content"],
                    vector_literal(chunk["embedding"]),
                    json.dumps({"indexed_by": "securechange-week5"}),
                ),
            )
    return len(chunks)


def fetch_knowledge_chunks(repository_url: str) -> list[dict]:
    ensure_schema()
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT kc.path, kc.chunk_index, kc.source_type, kc.content,
                   kc.embedding::text
            FROM knowledge_chunks kc
            JOIN repositories r ON r.id = kc.repository_id
            WHERE r.url = %s
            ORDER BY kc.path, kc.chunk_index
            """,
            (repository_url,),
        ).fetchall()
    chunks = []
    for path, chunk_index, source_type, content, embedding in rows:
        values = [float(value) for value in embedding.strip("[]").split(",") if value]
        chunks.append({"path": path, "chunk_index": chunk_index, "source_type": source_type, "content": content, "embedding": values})
    return chunks


def persist_security_findings(repository_url: str, findings: list[dict]) -> int:
    ensure_schema()
    with connection() as conn:
        row = conn.execute("SELECT id FROM repositories WHERE url = %s", (repository_url,)).fetchone()
        if row is None:
            raise ValueError("Inspect the repository before running a security scan.")
        repository_id = row[0]
        conn.execute("DELETE FROM security_findings WHERE repository_id = %s", (repository_id,))
        for item in findings:
            conn.execute(
                """
                INSERT INTO security_findings
                    (id, repository_id, analyzer, rule, severity, path, line, message, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    uuid4(),
                    repository_id,
                    item["analyzer"],
                    item["rule"],
                    item["severity"],
                    item["path"],
                    item.get("line"),
                    item["message"],
                    json.dumps(item.get("explanation", {})),
                ),
            )
    return len(findings)


def persist_scan_history(repository_url: str, scan_type: str, status: str, summary: dict) -> None:
    ensure_schema()
    with connection() as conn:
        row = conn.execute("SELECT id FROM repositories WHERE url = %s", (repository_url,)).fetchone()
        if row is None:
            raise ValueError("Inspect the repository before recording scan history.")
        conn.execute(
            """
            INSERT INTO scan_history
                (id, repository_id, scan_type, status, finding_count, critical_count, high_count, summary)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                uuid4(),
                row[0],
                scan_type,
                status,
                summary.get("finding_count", 0),
                summary.get("critical_count", 0),
                summary.get("high_count", 0),
                json.dumps(summary),
            ),
        )


def fetch_scan_history(repository_url: str, limit: int = 20) -> list[dict]:
    ensure_schema()
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT sh.scan_type, sh.status, sh.finding_count, sh.critical_count,
                   sh.high_count, sh.created_at
            FROM scan_history sh
            JOIN repositories r ON r.id = sh.repository_id
            WHERE r.url = %s
            ORDER BY sh.created_at DESC
            LIMIT %s
            """,
            (repository_url, limit),
        ).fetchall()
    return [
        {
            "scan_type": row[0],
            "status": row[1],
            "finding_count": row[2],
            "critical_count": row[3],
            "high_count": row[4],
            "created_at": row[5].isoformat(),
        }
        for row in rows
    ]

