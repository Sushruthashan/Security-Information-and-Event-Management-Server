from server.database.db import get_db

def save_event(event):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    INSERT INTO events(timestamp, hostname, agent_id, event_type, username, process_name, file_path, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(event.timestamp),
        event.hostname,
        event.agent_id,
        event.event_type,
        event.username,
        event.process_name,
        event.file_path,
        event.severity
    ))

    db.commit()
