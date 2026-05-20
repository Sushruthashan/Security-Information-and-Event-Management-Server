from fastapi import APIRouter
import psutil

router = APIRouter()

@router.get("/health")
def health():

    return {
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "active_endpoints": 2
    }
