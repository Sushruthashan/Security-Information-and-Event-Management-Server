from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from server.core.security import validate_agent
from server.detection.engine import run_detection # Import your new engine

app = FastAPI(title="Lightweight SIEM-EDR")

@app.post("/ingest")
async def ingest(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint for EDR agents to report telemetry.
    Uses BackgroundTasks to ensure high availability and low latency.
    """
    
    # 1. Security Check: Ensure the request is from a legitimate agent
    if not validate_agent(request.headers):
        raise HTTPException(status_code=401, detail="Unauthorized Agent")

    # 2. Get the JSON telemetry data
    data = await request.json()

    # 3. Offload detection to a background task
    # This prevents the agent from waiting while the server runs complex rules
    background_tasks.add_task(run_detection, data)

    # 4. Return immediately to the agent
    return {
        "status": "success", 
        "message": "Telemetry queued for analysis"
    }

@app.get("/health")
async def health_check():
    return {"status": "online"}
