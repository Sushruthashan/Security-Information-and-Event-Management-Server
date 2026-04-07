import requests
from config import SERVER_URL, API_KEY, AGENT_ID

def send_event(event):
    headers = {
        "X-Agent-ID": AGENT_ID,
        "X-API-KEY": API_KEY,
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(
            f"{SERVER_URL}/ingest",
            json=event,
            headers=headers,
            timeout=5
        )
        print("Server response:", r.status_code)
    except Exception as e:
        print("Connection error:", e)
