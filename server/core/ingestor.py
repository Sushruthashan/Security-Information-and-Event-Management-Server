from shared.event_schema import SecurityEvent
from server.database.repository import save_event
from server.detection.engine import run_detection

def ingest_event(raw_event):
    event = SecurityEvent(**raw_event)
    save_event(event)
    run_detection(event)
