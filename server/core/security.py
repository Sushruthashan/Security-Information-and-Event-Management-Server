API_KEYS = {
    "agent-001": "supersecretkey123"
}

def validate_agent(headers):
    agent_id = headers.get("X-Agent-ID")
    api_key = headers.get("X-API-KEY")

    if agent_id in API_KEYS and API_KEYS[agent_id] == api_key:
        return True
    return False
