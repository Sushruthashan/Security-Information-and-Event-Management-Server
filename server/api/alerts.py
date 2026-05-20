from fastapi import APIRouter

router = APIRouter()

@router.get("/alerts")
def get_alerts():

    return [
        {
            "type":"Suspicious Process",
            "endpoint":"endpoint-vm-01",
            "process":"unknown_process",
            "severity":"High"
        }
    ]
