import time
from threading import Lock

# State tracking with a Lock for thread safety in a multi-threaded Uvicorn environment
FAILED_LOGINS = {} 
login_lock = Lock()

PROCESS_COUNTER = {}
process_lock = Lock()

# ===============
#   BRUTEFORCE
# ===============

def detect_bruteforce(event):
    """
    Detects 5+ failed logins from the same IP within a 5-minute window.
    """
    # Defensive check: ensure it is an auth event and it was a failure
    if event.get("event_type") != "auth" or event.get("success") is not False:
        return None

    source_ip = event.get("source_ip", "unknown_ip")
    current_time = time.time()
    
    with login_lock:
        record = FAILED_LOGINS.get(source_ip, {"count": 0, "last_seen": current_time})
        
        # Reset counter if the window (300s) has passed since the last attempt
        if current_time - record["last_seen"] > 300:
            record["count"] = 1
        else:
            record["count"] += 1
        
        record["last_seen"] = current_time
        FAILED_LOGINS[source_ip] = record

        if record["count"] >= 5:
            # Reset after firing to prevent alert flooding
            record["count"] = 0 
            return {
                "rule_id": "SIEM-AUTH-01",
                "title": "Brute Force Attempt Detected",
                "severity": "HIGH",
                "mitre_tactic": "Credential Access (T1110)",
                "description": f"IP {source_ip} failed login 5 times within 5 minutes."
            }
    return None
    
# ============================
# SUSPICIOUS PROCESS DETECTION
# ============================

def detect_suspicious_process(event):
    """
    Identifies offensive tools using exact matching to prevent false positives.
    """
    if event.get("event_type") != "process":
        return None

    # Tuned List: Using a SET for O(1) exact match lookups
    # This prevents 'im-launch' from triggering 'nc' alerts.
    suspicious_tools = {"nc", "netcat", "nmap", "hydra", "mimikatz", "metasploit", "whoami", "ncat"}
    
    # Extract filename from path (e.g., /usr/bin/nc -> nc)
    raw_proc = event.get("process_name") or ""
    proc_name = raw_proc.split('/')[-1].split('\\')[-1].lower()

    # EXACT MATCH check
    if proc_name in suspicious_tools:
        return {
            "rule_id": "EDR-PROC-01",
            "title": "Offensive Tool Execution",
            "severity": "CRITICAL",
            "mitre_tactic": "Execution (T1059)",
            "description": f"Suspicious binary '{proc_name}' was executed on host {event.get('hostname')}."
        }

    return None

# ========================
# REVERSE SHELL DETECTION
# ========================

def detect_reverse_shell(event):

    if event.get("event_type") != "process":
        return None

    cmdline = (event.get("cmdline") or "").lower()

    suspicious_patterns = [
        "nc -e",
        "/dev/tcp/",
        "bash -i",
        "python -c",
        "perl -e"
    ]

    for pattern in suspicious_patterns:

        if pattern in cmdline:

            return {
                "rule_id": "EDR-SHELL-01",
                "title": "Possible Reverse Shell",
                "severity": "CRITICAL",
                "mitre_tactic": "Command and Control (T1071)",
                "description": f"Reverse shell behavior detected: {cmdline}"
            }

    return None
# ==========================
# PRIVILEGE ESCALATION
# ==========================

def detect_privilege_escalation(event):

    if event.get("event_type") != "process":
        return None

    proc = (event.get("process_name") or "").lower()

    suspicious = {
        "sudo",
        "su",
        "pkexec"
    }

    if proc in suspicious:

        return {
            "rule_id": "EDR-PRIV-01",
            "title": "Privilege Escalation Attempt",
            "severity": "HIGH",
            "mitre_tactic": "Privilege Escalation (T1548)",
            "description": f"Privilege escalation tool executed: {proc}"
        }

    return None
    
# ==========================
# SENSITIVE FILE ACCESS
# ==========================

def detect_sensitive_file_access(event):

    if event.get("event_type") != "file":
        return None

    file_path = (event.get("file_path") or "").lower()

    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh"
    ]

    for sensitive in sensitive_files:

        if sensitive in file_path:

            return {
                "rule_id": "EDR-FILE-01",
                "title": "Sensitive File Access",
                "severity": "HIGH",
                "mitre_tactic": "Credential Access (T1003)",
                "description": f"Sensitive file accessed: {file_path}"
            }

    return None

# ==========================
# PROCESS FLOOD DETECTION
# ==========================

def detect_process_flood(event):

    if event.get("event_type") != "process":
        return None

    hostname = event.get("hostname", "unknown")
    current_time = time.time()

    with process_lock:

        record = PROCESS_COUNTER.get(
            hostname,
            {"count": 0, "last_seen": current_time}
        )

        if current_time - record["last_seen"] > 60:
            record["count"] = 1
        else:
            record["count"] += 1

        record["last_seen"] = current_time

        PROCESS_COUNTER[hostname] = record

        if record["count"] > 20:

            record["count"] = 0

            return {
                "rule_id": "EDR-FLOOD-01",
                "title": "Abnormal Process Spawn Rate",
                "severity": "MEDIUM",
                "mitre_tactic": "Impact (T1499)",
                "description": f"Host {hostname} spawned excessive processes."
            }

    return None

# ==========================
# PERSISTENCE DETECTION
# ==========================

def detect_persistence(event):

    if event.get("event_type") != "process":
        return None

    proc = (event.get("process_name") or "").lower()

    suspicious = {
        "crontab",
        "systemctl",
        "service"
    }

    if proc in suspicious:

        return {
            "rule_id": "EDR-PERSIST-01",
            "title": "Persistence Mechanism Activity",
            "severity": "MEDIUM",
            "mitre_tactic": "Persistence (T1053)",
            "description": f"Potential persistence-related command executed: {proc}"
        }

    return None

