from fastapi import APIRouter
from shared.event_schema import Event
from server.core.ingestor import ingest

router = APIRouter()

@router.post("/logs")
async def receive_log(event: Event):
    """
    Endpoint agents send telemetry here.
    """

    # Send event to SIEM pipeline
    ingest(event)

    return {"status": "received"}
