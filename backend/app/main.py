from datetime import UTC, datetime

from fastapi import FastAPI
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

