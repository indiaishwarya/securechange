# SecureChange runbook

## Local startup

```bash
cp .env.example .env
docker compose up -d db
cd backend
source .venv/bin/activate
python -m uvicorn app.main:app --reload --port 8000
```

In another terminal:

```bash
cd dashboard
npm install
npm run dev
```

Use `GET /health` for liveness, `GET /ready` for database readiness, and `GET /metrics` for request counters.

## Production-shaped Docker run

```bash
docker compose -f docker-compose.production.yml up --build -d
docker compose -f docker-compose.production.yml ps
curl http://localhost/ready
```

Set a strong `POSTGRES_PASSWORD` before using this outside a local machine. Put TLS, authentication, and network access controls in front of the services.

## Common failures

- Database role or port errors: check `DATABASE_URL`, `docker compose ps`, and the host port mapping.
- `Bandit: timed-out` or `Semgrep: timed-out`: run each analyzer on the intended source directory, exclude virtual environments and build artifacts, and keep the built-in checks enabled.
- Dashboard cannot reach API: verify the API URL and CORS origin in `.env`; production Docker uses the Nginx same-origin proxy.
- `502` from Nginx: check `docker compose logs backend` and confirm the database health check passed.

## Verification

```bash
cd backend
pytest -q
python -m py_compile app/*.py
cd ../dashboard
npm run build
```
