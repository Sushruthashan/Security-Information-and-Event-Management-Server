from datetime import datetime

def create_alert(title, severity, event_data, description=""):
    """
    Prints and handles a triggered detection alert.
    
    Args:
        title (str): The name/type of the alert.
        severity (str): Priority level (Low, Medium, High, Critical).
        event_data (dict): The raw telemetry data that triggered the alert.
        description (str): Detailed context about the specific match.
    """
    # Extract hostname safely, providing a fallback if not found
    hostname = event_data.get("hostname", "Unknown Host")
    
    print("\n" + "="*30)
    print("      🚨 SIEM ALERT 🚨      ")
    print("="*30)
    print(f"Time:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Alert:       {title}")
    print(f"Severity:    {severity.upper()}")
    print(f"Host:        {hostname}")
    print(f"Description: {description}")
    
    # Optional: Print specific offending data (e.g., the process name)
    if "process_name" in event_data:
        print(f"Process:     {event_data['process_name']}")
    elif "source_ip" in event_data:
        print(f"Source IP:   {event_data['source_ip']}")
        
    print("="*30 + "\n")

    # In a real system, you would also save this to a database here:
    # db.save_alert(title, severity, event_data, description)
