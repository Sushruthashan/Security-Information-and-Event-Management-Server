import time

# State tracking for behavioral rules
FAILED_LOGINS = {} # Structure: {ip: {"count": 0, "last_seen": timestamp}}

def detect_bruteforce(event):
    """
    Detects 5+ failed logins from the same IP within a 5-minute window.
    """
    if event.get("event_type") != "auth" or event.get("success") is True:
        return None

    source_ip = event.get("source_ip")
    current_time = time.time()
    
    # Initialize or reset if the window (300s) has passed
    record = FAILED_LOGINS.get(source_ip, {"count": 0, "last_seen": current_time})
    
    if current_time - record["last_seen"] > 300:
        record["count"] = 1
    else:
        record["count"] += 1
    
    record["last_seen"] = current_time
    FAILED_LOGINS[source_ip] = record

    if record["count"] >= 5:
        # Reset after firing to prevent alert fatigue
        FAILED_LOGINS[source_ip]["count"] = 0 
        return {
            "rule_id": "SIEM-AUTH-01",
            "title": "Brute Force Attempt Detected",
            "severity": "HIGH",
            "mitre_tactic": "Credential Access (T1110)",
            "description": f"IP {source_ip} failed login 5 times within 5 minutes."
        }
    return None


def detect_suspicious_process(event):
    """
    Identifies the execution of known offensive security tools.
    """
    if event.get("event_type") != "process":
        return None

    # Expanded list of suspicious tools
    suspicious_tools = ["nc", "netcat", "nmap", "hydra", "mimikatz", "metasploit", "whoami"]
    proc_name = (event.get("process_name") or "").lower()

    if any(tool in proc_name for tool in suspicious_tools):
        return {
            "rule_id": "EDR-PROC-01",
            "title": "Offensive Tool Execution",
            "severity": "CRITICAL",
            "mitre_tactic": "Execution (T1059)",
            "description": f"Suspicious binary '{proc_name}' was executed on host {event.get('hostname')}."
        }

    return None
