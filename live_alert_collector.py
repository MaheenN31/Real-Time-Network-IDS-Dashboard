import time
import re
import sqlite3
from datetime import datetime
from pathlib import Path

DB_FILE = "ids_live.db"
ALERT_FILE = Path.home() / "snort_logs" / "snort_alerts.txt"

alert_pattern = re.compile(
    r'\[\*\*\]\s+\[(.*?)\]\s+"?(.*?)"?\s+\[\*\*\].*?'
    r'\[Classification:\s*(.*?)\]\s+'
    r'\[Priority:\s*(\d+)\]\s+'
    r'\{(.*?)\}\s+'
    r'(.*?)\s+->\s+(.*)'
)

def save_alert(line):
    match = alert_pattern.search(line)
    if not match:
        return

    sid = match.group(1).strip()
    rule = match.group(2).strip()
    classification = match.group(3).strip()
    priority = int(match.group(4).strip())
    protocol = match.group(5).strip()
    src = match.group(6).strip()
    dst = match.group(7).strip()

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO alerts
        (timestamp, rule, classification, priority, protocol, src, dst)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        rule,
        classification,
        priority,
        protocol,
        src,
        dst
    ))
    cur.execute("""
        DELETE FROM alerts
        WHERE id < (
         SELECT COALESCE(MAX(id) - 1000, 0)
         FROM alerts)
        """)

    conn.commit()
    conn.close()

print(f"Watching Snort alert file: {ALERT_FILE}")

ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
ALERT_FILE.touch(exist_ok=True)

with open(ALERT_FILE, "r") as f:
    f.seek(0, 2)

    while True:
        line = f.readline()

        if line:
            save_alert(line)
        else:
            time.sleep(0.5)
