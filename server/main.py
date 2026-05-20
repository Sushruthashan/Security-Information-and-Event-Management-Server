from server.core.utils import logs_storage, alerts_storage
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import psutil

from server.core.security import validate_agent
from server.detection.engine import run_detection

app = FastAPI(title="Lightweight SIEM-EDR")

templates = Jinja2Templates(directory="dashboard/templates")

app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")

# =========================================================
# CORS CONFIGURATION
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# INGEST ENDPOINT
# =========================================================

@app.post("/ingest")
async def ingest(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint for EDR agents to report telemetry.
    """

    # 1. Validate agent
    if not validate_agent(request.headers):
        raise HTTPException(status_code=401, detail="Unauthorized Agent")

    # 2. Read telemetry JSON
    data = await request.json()
    
    print(f"[EVENT RECEIVED] {data}")

    # 3. Store log temporarily for dashboard
    logs_storage.append(data)

    # 4. Run detection in background
    background_tasks.add_task(run_detection, data)

    # 5. Return immediately
    return {
        "status": "success",
        "message": "Telemetry queued for analysis"
    }

# =========================================================
# HEALTH API
# =========================================================

@app.get("/health")
async def health_check():

    return {
        "status": "online",
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "active_endpoints": 2
    }
    
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):

   return templates.TemplateResponse(
    request=request,
    name="index.html",
    context={}
)   

# =========================================================
# LOGS API
# =========================================================

@app.get("/logs")
async def get_logs():

    return logs_storage[-20:]

# =========================================================
# ALERTS API
# =========================================================

@app.get("/alerts")
async def get_alerts():

    return alerts_storage
