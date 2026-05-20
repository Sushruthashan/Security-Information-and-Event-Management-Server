import datetime
from server.detection.rules import (
    detect_bruteforce,
    detect_suspicious_process,
    detect_reverse_shell,
    detect_privilege_escalation,
    detect_sensitive_file_access,
    detect_process_flood,
    detect_persistence
)
# Registry of rules as a tuple (immutable)
RULES_REGISTRY = (
    detect_bruteforce,
    detect_suspicious_process,
    detect_reverse_shell,
    detect_privilege_escalation,
    detect_sensitive_file_access,
    detect_process_flood,
    detect_persistence
)

def detect(event):
    """
    Central detection dispatcher. 
    Handles data normalization and error isolation.
    """
    alerts = []

    # 1. Normalize input (Handle dict or object)
    if hasattr(event, "__dict__"):
        event_data = event.__dict__
    elif isinstance(event, dict):
        event_data = event
    else:
        return None

    # 2. Iterate through rules
    for rule in RULES_REGISTRY:
        try:
            alert = rule(event_data)
            
            if alert:
                # 3. Enrich Alert with metadata
                # Use current server time if event timestamp is missing
                alert["timestamp"] = event_data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                alert["hostname"] = event_data.get("hostname", "Unknown_Host")
                alerts.append(alert)
                
        except Exception as e:
            # Fault tolerance: one bad rule won't stop the whole SIEM
            print(f"[!] Error in rule '{rule.__name__}': {e}")
            continue

    return alerts if alerts else None

if __name__ == "__main__":
    # Test for the fix: This should NO LONGER trigger an alert
    test_event = {
        "event_type": "process",
        "process_name": "at-spi-bus-launcher",
        "hostname": "endpoint-vm",
        "timestamp": "2026-04-09 16:37:47"
    }
    
    results = detect(test_event)
    if results:
        print(f"Alerts Triggered: {results}")
    else:
        print("Success: No false positives detected.")
