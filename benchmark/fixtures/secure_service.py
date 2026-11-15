from fastapi import APIRouter, Depends

router = APIRouter()


def require_auth():
    return True


@router.get("/profile", dependencies=[Depends(require_auth)])
def profile():
    return {"status": "ok"}
