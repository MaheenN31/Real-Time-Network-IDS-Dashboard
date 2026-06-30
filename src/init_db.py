import sqlite3

DB_FILE = "ids_live.db"

conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src TEXT,
    dst TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    size INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    rule TEXT,
    classification TEXT,
    priority INTEGER,
    protocol TEXT,
    src TEXT,
    dst TEXT
)
""")

conn.commit()
conn.close()

print("Database initialized successfully.")
