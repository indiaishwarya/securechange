# SecureChange

SecureChange is an AI-assisted engineering analysis platform for detecting breaking API changes, service impact, and security risks before deployment.

## Week 1 foundation

- FastAPI backend with health and dashboard-summary endpoints
- React + TypeScript dashboard shell
- PostgreSQL database with pgvector support
- Docker Compose database setup
- Backend tests for the initial API contract
- Local Git repository inspection endpoint for branches, files, and recent commits
- Base-versus-target commit comparison with changed-file and diff-context results
- PostgreSQL persistence for repositories, commits, files, symbols, API endpoints, scans, and pull requests
- Python/JavaScript/TypeScript source-symbol parsing
- OpenAPI and Swagger endpoint extraction
- GitHub repository, commit, and pull-request inspection
- Commit analysis with API-change classification and obvious breaking-change detection
- Service/API dependency graph generation from repository structure, imports, and OpenAPI contracts
- Affected-service and affected-client reporting for changed commits
- Database-schema and migration impact detection for changed SQL/schema files
- Dashboard graph visualization with affected-node highlighting
- Retrieval index with offline embeddings, BM25 search, vector scoring, and score-fusion reranking
- Retrieval-grounded finding classification and explanation with optional LLM support
- Authentication and authorization checks, credential detection, and insecure-URL detection
- Optional Bandit and Semgrep integration with analyzer status reporting
- Security findings combined with retrieval-grounded explanations and persisted in PostgreSQL
- Intentional-bug benchmark with precision, recall, F1, Recall@K, and false-positive rate
- GitHub Actions validation, security-report artifacts, and pull-request comments
- Persisted scan history for reviewing previous security runs

## Local setup

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev
```

### Database

Docker must be installed and running before starting the database:

```bash
cp .env.example .env
docker compose up -d db
```

The dashboard is available at http://localhost:5173 and the API at http://localhost:8000.

## Week 2 repository inspection

With the backend and dashboard running, enter a local Git repository path in the dashboard, such as:

```text
/Users/your-name/Projects/your-repository
```

The backend reads the repository using Git's read-only commands and returns its current branch, local branches, tracked files, and 20 recent commits.

After inspection, select two commits in the dashboard and choose **Compare commits**. SecureChange reports added, modified, deleted, and renamed files, line counts, and Git-provided function context for the changed hunks.

To connect a public GitHub repository, use the GitHub connector in the dashboard. For private repositories, set `GITHUB_TOKEN` in `.env` before starting the backend.

After selecting a base and target commit, choose **Compare commits** to run the Week 3 analysis. The result includes changed files, changed symbols, OpenAPI additions/removals/modifications, and breaking rules such as removed endpoints, newly required parameters, removed response codes, and newly required request bodies.

## Week 4 dependency and impact analysis

The same comparison action also calls the impact-analysis endpoint. It builds service nodes from repository components, connects import relationships, attaches OpenAPI endpoints to their owning service, and connects schema or migration files to the database node. Changed services are highlighted in the graph. SQL, migration, Alembic, and Prisma changes are inspected for added or removed tables, columns, and indexes.

## Week 5 retrieval and AI analysis

Use the Build retrieval index button in the dashboard to chunk source code, policies, documentation, API contracts, and schema files. Search combines a lexical BM25 score with 384-dimensional offline feature-hash vectors and a score-fusion reranker. Classify and explain retrieves evidence first, then uses a configured LLM when OPENAI_API_KEY is present; otherwise it uses a transparent offline heuristic so local development remains functional.

## Week 6 security analysis

Use Run security scan to detect possible missing authorization on web routes, hardcoded credentials, and plain HTTP URLs. If Bandit or Semgrep is installed on the backend host, their JSON findings are included automatically; otherwise the dashboard reports not-installed and continues with the built-in checks. Each finding is enriched with retrieved repository evidence and an offline or LLM-generated explanation.

## Week 7 evaluation and integration

The benchmark endpoint evaluates the intentionally vulnerable and secure fixtures under benchmark/fixtures. It reports precision, recall, F1, Recall@3, and false-positive rate. The GitHub Actions workflow runs tests, the benchmark, Bandit, and Semgrep on pushes and pull requests, uploads analyzer reports, and comments a CI summary on pull requests. Security scans are persisted in scan_history and displayed in the dashboard.

