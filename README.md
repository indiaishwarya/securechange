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

