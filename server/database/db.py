import sqlite3

def get_db():
    conn = sqlite3.connect("server/database/logs.db")
    conn.row_factory = sqlite3.Row
    return conn
