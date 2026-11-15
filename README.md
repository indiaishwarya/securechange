# SecureChange

SecureChange is an AI-assisted engineering analysis platform for detecting breaking API changes, service impact, and security risks before deployment.

## Week 1 foundation

- FastAPI backend with health and dashboard-summary endpoints
- React + TypeScript dashboard shell
- PostgreSQL database with pgvector support
- Docker Compose database setup
- Backend tests for the initial API contract

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

