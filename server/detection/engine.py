from server.detection.detector import detect
from server.models.alert import create_alert

def run_detection(event):
    """
    Main entry point for event processing.
    Passes events to the detector and saves any generated alerts.
    """
    # 1. Run the event through the detection pipeline
    # This now returns a list of alert dictionaries or None
    triggered_alerts = detect(event)

    if not triggered_alerts:
        return

    # 2. Iterate through found alerts and save them to the database
    for alert_data in triggered_alerts:
        try:
            # We pass the structured data from the rule to your model
            create_alert(
                title=alert_data.get("title", "Unknown Alert"),
                severity=alert_data.get("severity", "medium"),
                # We pass the original event and the rule description 
                # to provide full context in the DB/Dashboard
                description=alert_data.get("description", ""),
                event_data=event 
            )
            
            # Optional: Log the detection to the console for real-time monitoring
            print(f"[*] ALERT PERSISTED: {alert_data['title']} | Severity: {alert_data['severity']}")
            
        except Exception as e:
            print(f"[!] Database Error: Failed to save alert: {e}")
