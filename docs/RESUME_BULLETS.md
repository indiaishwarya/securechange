# SecureChange resume bullets

## Software engineering

- Built and containerized a FastAPI + React/TypeScript platform that compares Git commits, parses source and OpenAPI contracts, detects breaking changes, and persists repository evidence in PostgreSQL/pgvector.
- Implemented dependency-graph and database-schema impact analysis with affected-service/client reporting and interactive dashboard visualization.
- Added production-oriented reliability features including request IDs, readiness and metrics endpoints, structured JSON errors, bounded subprocess execution, scan history, automated tests, and GitHub Actions CI.

## AI/ML and security

- Implemented evidence retrieval using BM25, deterministic vector embeddings, cosine similarity, and score-fusion reranking over code, policies, documentation, API contracts, and schemas.
- Built retrieval-grounded finding classification and explanation with an offline fallback plus optional LLM integration, and combined built-in security checks with Bandit and Semgrep results.
- Created an intentional-bug benchmark reporting precision, recall, F1, Recall@3, and false-positive rate; integrated benchmark execution, analyzer artifacts, and pull-request comments into CI.
