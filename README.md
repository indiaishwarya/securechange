# SecureChange

SecureChange is an AI-assisted engineering risk platform that analyzes repository changes before deployment. It combines Git diff analysis, API contract comparison, dependency and database impact analysis, retrieval-grounded explanations, security scanning, and evaluation metrics in a single dashboard.

It helps engineering teams answer:

- What changed between two commits?
- Which APIs, services, clients, and database objects may be affected?
- Is the change likely to break an API contract?
- Are there authentication, authorization, credential, or insecure-transport risks?
- What code, documentation, policies, and schema context supports the finding?

## Features

### Repository and change analysis

- Inspect local Git repositories and public GitHub repositories
- Read branches, tracked files, commits, and pull requests
- Parse Python, JavaScript, and TypeScript source symbols
- Parse OpenAPI and Swagger contracts
- Compare two commits and report added, modified, deleted, and renamed files
- Identify changed functions and classes using Git function context
- Detect obvious breaking API changes, including removed endpoints, newly required parameters, removed response status codes, and newly required request bodies

### Dependency and impact analysis

- Build service and API dependency graphs from repository structure and imports
- Identify affected services and clients
- Detect changes to SQL, schema, migration, Alembic, and Prisma files
- Report added and removed tables, columns, and indexes
- Visualize affected nodes in the dashboard

### Retrieval and AI analysis

- Chunk source code, API contracts, documentation, policies, and database schemas
- Generate deterministic 384-dimensional feature-hash embeddings
- Store embeddings in PostgreSQL with pgvector
- Combine BM25 lexical search with vector similarity
- Rerank results using score fusion
- Retrieve evidence before generating an explanation
- Use an optional LLM for classification and explanations
- Provide an offline heuristic fallback when no LLM API key is configured

### Security analysis

- Detect routes that may lack authentication or authorization
- Detect hardcoded credentials and secrets
- Detect insecure HTTP URLs
- Integrate optional Bandit and Semgrep analysis
- Apply bounded analyzer timeouts
- Combine static-analysis findings with retrieved evidence and explanations
- Persist security findings and scan history

### Evaluation and integration

- Benchmark intentionally vulnerable and secure fixtures
- Measure precision, recall, F1, Recall@3, and false-positive rate
- Run tests and security analysis through GitHub Actions
- Upload Bandit and Semgrep reports as CI artifacts
- Post automated summaries to pull requests
- Review previous security scans through the dashboard

### Reliability and operations

- Request IDs through the `X-Request-ID` header
- Consistent JSON validation and internal-error responses
- Liveness endpoint: `/health`
- Database readiness endpoint: `/ready`
- Lightweight request metrics endpoint: `/metrics`
- Production-oriented Dockerfiles and Docker Compose configuration
- Architecture documentation and operations runbook

## Architecture

```text
React + TypeScript dashboard
              |
              v
       FastAPI application
       /       |       \
      /        |        \
    Git   Analysis   Security tools
              |
              v
      PostgreSQL + pgvector
```

The dashboard communicates with the FastAPI backend over HTTP. The backend reads Git repositories using bounded, argument-based subprocess calls. PostgreSQL stores repository metadata, commits, files, symbols, API endpoints, embeddings, security findings, and scan history. Bandit and Semgrep are optional analyzers that supplement SecureChange's built-in checks.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details and [docs/RUNBOOK.md](docs/RUNBOOK.md) for operations and troubleshooting.

## Technology stack

| Area | Technologies |
| --- | --- |
| Backend | Python, FastAPI, Pydantic, Uvicorn |
| Dashboard | React, TypeScript, Vite, CSS |
| Database | PostgreSQL, pgvector, psycopg |
| Repository analysis | Git, Python AST, JavaScript/TypeScript parsing, OpenAPI |
| Retrieval | BM25, feature-hash embeddings, vector similarity, reranking |
| AI | Optional LLM integration with offline fallback |
| Security | Built-in checks, Bandit, Semgrep |
| Infrastructure | Docker, Docker Compose, Nginx |
| CI/CD | GitHub Actions |
| Testing | Pytest, TypeScript compiler, Vite production build |

## Project structure

```text
securechange/
├── backend/
│   ├── app/
│   │   ├── database.py       # PostgreSQL and pgvector persistence
│   │   ├── evaluation.py     # Intentional-bug benchmark
│   │   ├── github.py         # GitHub API integration
│   │   ├── impact.py         # Dependency and schema impact analysis
│   │   ├── main.py           # FastAPI application and routes
│   │   ├── monitoring.py     # Request metrics
│   │   ├── parsers.py        # Source and OpenAPI parsers
│   │   ├── retrieval.py      # Embeddings, BM25, vector search, reranking
│   │   └── security.py       # Built-in, Bandit, and Semgrep checks
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── benchmark/fixtures/       # Secure and vulnerable services
├── dashboard/
│   ├── src/
│   ├── Dockerfile
│   └── nginx.conf
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RESUME_BULLETS.md
│   └── RUNBOOK.md
├── infra/db/init.sql
├── docker-compose.yml
└── docker-compose.production.yml
```

## Local development

### Prerequisites

- Python 3.12
- Node.js and npm
- Docker Desktop
- Git

### Configure environment variables

From the project root:

```bash
cp .env.example .env
```

For the local Docker database setup:

```dotenv
DATABASE_URL=postgresql+psycopg://securechange:securechange_dev@127.0.0.1:55432/securechange
FRONTEND_ORIGIN=http://localhost:5173
```

Optional integrations:

```dotenv
GITHUB_TOKEN=your-github-token
OPENAI_API_KEY=your-api-key
LLM_MODEL=gpt-4o-mini
```

Never commit `.env`, access tokens, or API keys.

### Start PostgreSQL and pgvector

```bash
docker compose up -d db
docker compose ps
```

### Start the backend

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

The API is available at [http://localhost:8000](http://localhost:8000). Interactive documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Start the dashboard

In a second terminal:

```bash
cd dashboard
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Enter a local Git repository path such as:

```text
/Users/your-name/Projects/your-repository
```

## API endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Process liveness check |
| `GET /ready` | Database readiness check |
| `GET /metrics` | Request and status metrics |
| `GET /api/v1/summary` | Dashboard summary metrics |
| `POST /api/v1/repositories/inspect` | Inspect and persist a local repository |
| `POST /api/v1/github/inspect` | Inspect a GitHub repository |
| `POST /api/v1/repositories/analyze` | Compare commits and analyze API changes |
| `POST /api/v1/repositories/impact` | Build dependency and schema impact analysis |
| `POST /api/v1/repositories/retrieval/index` | Build the repository retrieval index |
| `POST /api/v1/repositories/retrieval/search` | Search repository evidence |
| `POST /api/v1/repositories/retrieval/explain` | Classify and explain a finding |
| `POST /api/v1/repositories/security/scan` | Run security analysis |
| `POST /api/v1/repositories/history` | Retrieve scan history |
| `POST /api/v1/evaluation/benchmark` | Run the evaluation benchmark |
| `POST /api/v1/github/pull-requests/comment` | Post a GitHub pull-request comment |

## Testing and verification

Run backend tests:

```bash
cd backend
source .venv/bin/activate
pytest -q
```

Compile backend modules:

```bash
python -m py_compile app/*.py
```

Build the dashboard:

```bash
cd dashboard
npm run build
```

GitHub Actions also runs tests, the benchmark, Bandit, and Semgrep on pushes and pull requests.

## Production-shaped deployment

The repository includes a containerized deployment configuration:

```bash
docker compose -f docker-compose.production.yml config
docker compose -f docker-compose.production.yml up --build -d
```

The dashboard is served through Nginx on port 80, and Nginx proxies API, health, readiness, and metrics requests to the backend.

Before using this outside local development:

- Set a strong `POSTGRES_PASSWORD`
- Configure TLS through a reverse proxy or managed platform
- Restrict database network access
- Configure `GITHUB_TOKEN` and `OPENAI_API_KEY` only when required
- Add persistent backups and centralized logs
- Configure a cloud provider, domain, and production secrets

## Current limitations

- Dependency and client impact detection is heuristic and depends on repository structure and import relationships.
- OpenAPI analysis only identifies changes represented in recognized OpenAPI or Swagger files.
- The default embedding model is deterministic feature hashing rather than a pretrained semantic model.
- Bandit and Semgrep may time out on very large repositories and should use repository-specific exclusions.
- The production Compose configuration is deployment-ready but has not been deployed to a public cloud environment.

## Resume summary

SecureChange demonstrates full-stack software engineering, repository analysis, information retrieval, security automation, evaluation, observability, and CI/CD. Resume-ready bullets are available in [docs/RESUME_BULLETS.md](docs/RESUME_BULLETS.md).

## License

This project is intended as a portfolio and educational engineering project.

