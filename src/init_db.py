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
    size INTEGER,
    info TEXT,
    tcp_flags TEXT
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
    dst TEXT,

    snort_rule TEXT,
    iface TEXT,
    service TEXT,
    src_addr TEXT,
    src_port INTEGER,
    dst_addr TEXT,
    dst_port INTEGER,
    direction TEXT,
    pkt_len INTEGER,
    action TEXT,
    msg TEXT,
    gid INTEGER,
    sid INTEGER,
    rev INTEGER,
    ttl INTEGER,
    tos INTEGER,
    tcp_flags TEXT,
    icmp_type INTEGER,
    icmp_code INTEGER,
    client_pkts INTEGER,
    client_bytes INTEGER,
    server_pkts INTEGER,
    server_bytes INTEGER,
    raw_json TEXT
)
""")


def add_column_if_missing(table_name, column_name, column_definition):
    cur.execute(f"PRAGMA table_info({table_name})")
    existing_columns = [row[1] for row in cur.fetchall()]

    if column_name not in existing_columns:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


alert_columns = {
    "snort_rule": "TEXT",
    "iface": "TEXT",
    "service": "TEXT",
    "src_addr": "TEXT",
    "src_port": "INTEGER",
    "dst_addr": "TEXT",
    "dst_port": "INTEGER",
    "direction": "TEXT",
    "pkt_len": "INTEGER",
    "action": "TEXT",
    "msg": "TEXT",
    "gid": "INTEGER",
    "sid": "INTEGER",
    "rev": "INTEGER",
    "ttl": "INTEGER",
    "tos": "INTEGER",
    "tcp_flags": "TEXT",
    "icmp_type": "INTEGER",
    "icmp_code": "INTEGER",
    "client_pkts": "INTEGER",
    "client_bytes": "INTEGER",
    "server_pkts": "INTEGER",
    "server_bytes": "INTEGER",
    "raw_json": "TEXT",
}

for column_name, column_definition in alert_columns.items():
    add_column_if_missing("alerts", column_name, column_definition)

conn.commit()
conn.close()

print("Database initialized successfully.")
print("Alerts table is ready for Snort JSON fields.")
