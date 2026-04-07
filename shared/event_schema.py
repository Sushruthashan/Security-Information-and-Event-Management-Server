from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class SecurityEvent(BaseModel):
    timestamp: datetime
    hostname: str
    agent_id: str
    event_type: str

    # authentication
    username: Optional[str] = None
    source_ip: Optional[str] = None
    success: Optional[bool] = None

    # process
    process_name: Optional[str] = None
    pid: Optional[int] = None
    parent_process: Optional[str] = None

    # file
    file_path: Optional[str] = None
    action: Optional[str] = None

    severity: Optional[str] = "info"
