from fastapi import APIRouter

router = APIRouter()
API_KEY = "benchmark-secret-value"


@router.get("/admin")
def admin():
    return {"status": "ok"}


SERVICE_URL = "http://internal-service.example.com"
