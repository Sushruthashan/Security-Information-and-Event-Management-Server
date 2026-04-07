from server.detection.rules import detect_bruteforce, detect_suspicious_process

# Registry of detection functions. 
# As you create new rules in rules.py, add them here.
RULES_REGISTRY = [
    detect_bruteforce,
    detect_suspicious_process
]

def detect(event):
    """
    Central detection dispatcher.
    
    Processes an event through all registered rules and collects any 
    triggered alerts. This allows for multi-stage detection where 
    one event might trigger multiple rules.
    """
    alerts = []

    # Ensure event is in a format we can work with (dictionary)
    # If your events are objects, you might need: event_dict = event.__dict__
    if not isinstance(event, dict):
        # Fallback for attribute-based objects if necessary
        try:
            event_data = event.__dict__
        except AttributeError:
            event_data = event
    else:
        event_data = event

    for rule in RULES_REGISTRY:
        try:
            # Each rule now returns a dict (alert) or None
            alert = rule(event_data)
            
            if alert:
                # Add metadata to the alert for the SIEM dashboard
                alert["timestamp"] = event_data.get("timestamp", "N/A")
                alert["hostname"] = event_data.get("hostname", "Unknown")
                alerts.append(alert)
                
        except Exception as e:
            # Prevents a single faulty rule from crashing the entire pipeline
            print(f"[!] Error executing rule '{rule.__name__}': {e}")
            continue

    # Return the list of alerts found, or None if the event is benign
    return alerts if alerts else None

if __name__ == "__main__":
    # Example test case for local debugging
    test_event = {
        "event_type": "process",
        "process_name": "nmap",
        "hostname": "PROD-DB-01",
        "timestamp": "2026-04-06 22:00:00"
    }
    
    results = detect(test_event)
    if results:
        print(f"Alerts Triggered: {results}")
    else:
        print("No threats detected.")
