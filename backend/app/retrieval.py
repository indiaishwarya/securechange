import hashlib
import math
import re
from collections import Counter
from pathlib import Path

import httpx

from .config import get_settings


EMBEDDING_DIMENSIONS = 384
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_./:-]+")
INDEXABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".sql",
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml",
}
POLICY_MARKERS = ("policy", "security", "compliance", "adr", "readme", "runbook")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_PATTERN.findall(text)]


def embed_text(text: str) -> list[float]:
    vector = [0.0] * EMBEDDING_DIMENSIONS
    for token in tokenize(text):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % EMBEDDING_DIMENSIONS
        sign = 1.0 if digest[4] % 2 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [round(value / norm, 8) for value in vector]


def vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(str(value) for value in vector) + "]"


def source_type(path: str) -> str:
    lower = path.lower()
    if any(marker in lower for marker in POLICY_MARKERS):
        return "policy_or_documentation"
    if lower.endswith((".yaml", ".yml", ".json")) and "openapi" in lower:
        return "api_contract"
    if lower.endswith(".sql") or "migration" in lower:
        return "database_schema"
    return "source_code"


def chunk_text(path: str, content: str, chunk_size: int = 1200) -> list[dict]:
    if not content.strip():
        return []
    chunks = []
    for index, start in enumerate(range(0, len(content), chunk_size)):
        text = content[start : start + chunk_size].strip()
        if text:
            chunks.append({
                "path": path,
                "chunk_index": index,
                "content": text,
                "source_type": source_type(path),
                "embedding": embed_text(path + "\n" + text),
            })
    return chunks


def build_repository_chunks(repository_root: Path, files: list[str]) -> list[dict]:
    chunks = []
    for relative_path in files:
        path = repository_root / relative_path
        if path.suffix.lower() not in INDEXABLE_EXTENSIONS or not path.is_file():
            continue
        try:
            chunks.extend(chunk_text(relative_path, path.read_text(errors="ignore")))
        except OSError:
            continue
    return chunks


def bm25_scores(query: str, documents: list[str]) -> list[float]:
    query_tokens = set(tokenize(query))
    tokenized = [tokenize(document) for document in documents]
    document_frequency = Counter(token for tokens in tokenized for token in set(tokens))
    average_length = sum(len(tokens) for tokens in tokenized) / max(len(tokenized), 1)
    scores = []
    for tokens in tokenized:
        counts = Counter(tokens)
        score = 0.0
        for token in query_tokens:
            if token not in counts:
                continue
            idf = math.log(1 + (len(documents) - document_frequency[token] + 0.5) / (document_frequency[token] + 0.5))
            denominator = counts[token] + 1.5 * (0.25 + 0.75 * len(tokens) / max(average_length, 1))
            score += idf * counts[token] * 2.5 / denominator
        scores.append(score)
    return scores


def cosine_scores(query_vector: list[float], document_vectors: list[list[float]]) -> list[float]:
    return [sum(left * right for left, right in zip(query_vector, vector)) for vector in document_vectors]


def rerank(query: str, rows: list[dict], top_k: int) -> list[dict]:
    if not rows:
        return []
    bm25 = bm25_scores(query, [row["content"] for row in rows])
    vector = cosine_scores(embed_text(query), [row["embedding"] for row in rows])
    max_bm25 = max(bm25) or 1.0
    max_vector = max(vector) or 1.0
    query_tokens = set(tokenize(query))
    for row, lexical, semantic in zip(rows, bm25, vector):
        path_tokens = set(tokenize(row["path"]))
        path_boost = 0.1 if query_tokens & path_tokens else 0.0
        row["bm25_score"] = round(lexical, 4)
        row["vector_score"] = round(semantic, 4)
        row["score"] = round(0.45 * lexical / max_bm25 + 0.55 * semantic / max_vector + path_boost, 4)
    return sorted(rows, key=lambda row: row["score"], reverse=True)[:top_k]


def heuristic_explanation(finding: str, context: list[dict]) -> dict:
    lower = finding.lower()
    if any(word in lower for word in ("secret", "token", "credential", "injection")):
        category, severity = "security", "high"
        recommendation = "Block deployment until the secret or injection risk is removed and add a regression test."
    elif any(word in lower for word in ("removed", "breaking", "required parameter", "response")):
        category, severity = "breaking_change", "high"
        recommendation = "Review downstream consumers, update the contract version, and add compatibility tests."
    elif any(word in lower for word in ("table", "column", "schema", "migration")):
        category, severity = "database_impact", "medium"
        recommendation = "Review migrations, query compatibility, rollout order, and rollback behavior."
    else:
        category, severity = "change_impact", "medium"
        recommendation = "Review the affected callers and add a targeted test before deployment."
    return {
        "category": category,
        "severity": severity,
        "explanation": f"{finding} This may affect behavior in dependent components.",
        "recommendation": recommendation,
        "evidence": [{"path": row["path"], "score": row.get("score", 0.0)} for row in context[:3]],
        "provider": "offline-heuristic",
    }


def classify_with_llm(finding: str, context: list[dict]) -> dict:
    settings = get_settings()
    if not settings.openai_api_key:
        return heuristic_explanation(finding, context)
    evidence = "\n\n".join(f"{row['path']}:\n{row['content']}" for row in context[:5])
    prompt = (
        "Classify this engineering finding. Return JSON with category, severity, explanation, "
        "and recommendation. Use only the supplied evidence.\n\n"
        f"Finding: {finding}\n\nEvidence:\n{evidence}"
    )
    try:
        response = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            json={
                "model": settings.llm_model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are a precise senior software-change reviewer."},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        result = data["choices"][0]["message"]["content"]
        import json
        parsed = json.loads(result)
        parsed["evidence"] = [{"path": row["path"], "score": row.get("score", 0.0)} for row in context[:5]]
        parsed["provider"] = settings.llm_model
        return parsed
    except Exception:
        return heuristic_explanation(finding, context)
