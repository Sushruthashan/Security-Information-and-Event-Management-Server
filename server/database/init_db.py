from server.database.db import get_db

def init():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        hostname TEXT,
        agent_id TEXT,
        event_type TEXT,
        username TEXT,
        process_name TEXT,
        file_path TEXT,
        severity TEXT
    )
    """)

    db.commit()

if __name__ == "__main__":
    init()
