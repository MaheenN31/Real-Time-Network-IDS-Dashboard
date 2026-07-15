import re
import json
import sqlite3
import hashlib
import subprocess
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

DB_FILE = Path("ids_live.db")

st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st_autorefresh(interval=30000, key="dashboard_refresh")

st.markdown("""
<style>
.main {
    background-color: #0e1117;
}
.metric-card {
    background-color: #161b22;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #30363d;
}
h1, h2, h3 {
    color: #f0f6fc;
}
</style>
""", unsafe_allow_html=True)


def get_connection():
    return sqlite3.connect(DB_FILE)


def load_table(table_name):
    conn = get_connection()
    try:
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def load_query(query):
    conn = get_connection()
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def load_rule_doc(gid, sid):
    if sid is None or pd.isna(sid):
        return {}

    try:
        sid = int(float(sid))
    except Exception:
        return {}

    try:
        gid = int(float(gid)) if gid is not None and not pd.isna(gid) else 1
    except Exception:
        gid = 1

    df = load_query(f"""
        SELECT *
        FROM rule_docs
        WHERE gid = {gid}
          AND sid = {sid}
        LIMIT 1
    """)

    if df.empty:
        return {}

    return df.iloc[0].to_dict()


def show_doc_field(label, value):
    if value is not None and str(value).strip() not in ["", "nan", "None"]:
        st.markdown(f"**{label}:**")
        st.write(value)

RULES_FILE = Path("/usr/local/etc/snort/rules/snort3-community.rules")

@st.cache_data(ttl=60)
def get_snort_version():
    try:
        result = subprocess.run(
            ["snort", "-V"],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout + result.stderr

        # Prefer lines like: Snort++ 3.12.2.0
        version_match = re.search(r"Snort\+\+\s+([0-9]+(?:\.[0-9]+)+)", output)
        if version_match:
            return f"Snort++ {version_match.group(1)}"

        # Fallback for lines like: Version 3.12.2.0
        version_match = re.search(r"Version\s+([0-9]+(?:\.[0-9]+)+)", output, re.IGNORECASE)
        if version_match:
            return f"Snort++ {version_match.group(1)}"

        return "Unable to parse Snort version"

    except Exception as e:
        return f"Unable to read Snort version: {e}"

@st.cache_data(ttl=60)
def get_ruleset_status():
    status = {
        "rules_file": str(RULES_FILE),
        "exists": RULES_FILE.exists(),
        "file_size": "N/A",
        "last_modified": "N/A",
        "sha256": "N/A",
        "enabled_alert_rules": 0,
        "disabled_alert_rules": 0,
        "total_alert_rules": 0,
    }

    if not RULES_FILE.exists():
        return status

    try:
        file_stat = RULES_FILE.stat()
        status["file_size"] = f"{file_stat.st_size / (1024 * 1024):.2f} MB"
        status["last_modified"] = datetime.fromtimestamp(
            file_stat.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")

        sha256_hash = hashlib.sha256()

        with RULES_FILE.open("rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                sha256_hash.update(chunk)

        status["sha256"] = sha256_hash.hexdigest()

        enabled_alert_rules = 0
        disabled_alert_rules = 0

        with RULES_FILE.open("r", errors="ignore") as file:
            for line in file:
                stripped = line.strip()

                if stripped.startswith("alert "):
                    enabled_alert_rules += 1

                elif stripped.startswith("#") and "alert " in stripped:
                    disabled_alert_rules += 1

        status["enabled_alert_rules"] = enabled_alert_rules
        status["disabled_alert_rules"] = disabled_alert_rules
        status["total_alert_rules"] = enabled_alert_rules + disabled_alert_rules

    except Exception:
        pass

    return status

@st.cache_data(ttl=60)
def load_snort_rules_file():
    """
    Load the local Snort Community rules file.
    This does not use the internet. It reads the rules that Snort is already using.
    """
    if not RULES_FILE.exists():
        return ""

    try:
        return RULES_FILE.read_text(errors="ignore")
    except Exception:
        return ""


def find_rule_by_sid(sid):
    """
    Find the original Snort rule from snort3-community.rules using the SID.
    """
    if sid is None or pd.isna(sid):
        return None

    rules_text = load_snort_rules_file()

    if not rules_text:
        return None

    sid_text = str(int(sid)) if str(sid).replace(".0", "").isdigit() else str(sid)

    for line in rules_text.splitlines():
        clean_line = line.strip()

        if not clean_line or clean_line.startswith("#"):
            continue

        if f"sid:{sid_text};" in clean_line:
            return clean_line

    return None


def extract_rule_option(rule_text, option_name):
    """
    Extract a simple option value from a Snort rule.
    Example: msg:"PROTOCOL-ICMP Echo Reply";
    """
    if not rule_text:
        return None

    pattern = rf'{option_name}\s*:\s*"([^"]+)"'
    match = re.search(pattern, rule_text)

    if match:
        return match.group(1)

    pattern = rf'{option_name}\s*:\s*([^;]+);'
    match = re.search(pattern, rule_text)

    if match:
        return match.group(1).strip()

    return None


def priority_meaning(priority):
    try:
        priority = int(priority)
    except Exception:
        return "Unknown priority"

    meanings = {
        1: "High severity. This usually means serious or high-confidence suspicious activity.",
        2: "Medium severity. This usually means suspicious activity, probing, or possible information gathering.",
        3: "Low severity. This is usually informational, miscellaneous, or lower-risk activity.",
        4: "Very low/informational severity."
    }

    return meanings.get(priority, "Unknown priority level.")


def classification_meaning(classification):
    if not classification:
        return "No classification was provided for this alert."

    c = str(classification).lower()

    if "information leak" in c:
        return "This alert suggests that traffic may be trying to discover or expose system/service information."
    if "recon" in c:
        return "This alert suggests reconnaissance activity, such as scanning or probing."
    if "misc" in c:
        return "This is miscellaneous network activity. It may not be malicious by itself, but it is useful for visibility."
    if "web" in c:
        return "This alert is related to suspicious web or HTTP activity."
    if "attempted-dos" in c or "denial" in c:
        return "This alert may indicate traffic related to denial-of-service behavior."
    if "bad-unknown" in c:
        return "This alert indicates suspicious or unusual traffic that does not fit a more specific category."
    if "policy" in c:
        return "This alert indicates traffic that may violate a policy rather than a confirmed exploit."

    return "This classification groups the alert into a general Snort activity category."


def protocol_meaning(row):
    proto = str(row.get("Protocol", row.get("protocol", ""))).upper()
    service = row.get("Service", row.get("service", ""))
    tcp_flags = row.get("TCP Flags", row.get("tcp_flags", ""))
    icmp_type = row.get("ICMP Type", row.get("icmp_type", None))
    icmp_code = row.get("ICMP Code", row.get("icmp_code", None))

    if proto == "ICMP":
        if icmp_type == 0 or str(icmp_type) == "0":
            return "This is ICMP Echo Reply traffic. It usually means the target responded to a ping request."
        if icmp_type == 8 or str(icmp_type) == "8":
            return "This is ICMP Echo Request traffic. It usually means a host is being pinged or probed."
        return f"This is ICMP traffic. ICMP type={icmp_type}, code={icmp_code}."

    if proto == "TCP":
        if tcp_flags and str(tcp_flags).lower() not in ["none", "nan"]:
            return f"This is TCP traffic. TCP flags are `{tcp_flags}`, which can help identify scans or connection behavior."
        return "This is TCP traffic. TCP is used by services such as HTTP, SSH, FTP, and many application protocols."

    if proto == "UDP":
        return "This is UDP traffic. UDP is connectionless and is often used by DNS, SNMP, DHCP, and scanning activity."

    if service and str(service).lower() != "unknown":
        return f"Snort identified the service as `{service}`."

    return "This protocol/service combination does not have a specific explanation available."


def signature_plain_english(row):
    """
    Build a human-readable description using alert fields.
    """
    msg = row.get("Alert Message", row.get("msg", row.get("rule", "Unknown alert")))
    classification = row.get("Classification", row.get("classification", None))
    priority = row.get("Priority", row.get("priority", None))
    protocol = row.get("Protocol", row.get("protocol", None))
    service = row.get("Service", row.get("service", None))
    src_ip = row.get("Source IP", row.get("src_addr", row.get("src", None)))
    src_port = row.get("Source Port", row.get("src_port", None))
    dst_ip = row.get("Destination IP", row.get("dst_addr", row.get("dst", None)))
    dst_port = row.get("Destination Port", row.get("dst_port", None))
    direction = row.get("Direction", row.get("direction", None))

    parts = []

    parts.append(f"**Alert meaning:** `{msg}` was triggered because the observed traffic matched a Snort Community rule/signature.")

    if src_ip and dst_ip:
        src_text = f"{src_ip}"
        dst_text = f"{dst_ip}"

        if src_port and str(src_port) != "nan":
            src_text += f":{src_port}"

        if dst_port and str(dst_port) != "nan":
            dst_text += f":{dst_port}"

        parts.append(f"**Traffic path:** `{src_text}` → `{dst_text}`.")

    if protocol:
        parts.append(f"**Protocol:** `{protocol}`.")

    if service and str(service).lower() not in ["unknown", "nan", "none", ""]:
        parts.append(f"**Detected service:** `{service}`.")

    if direction and str(direction).lower() not in ["nan", "none", ""]:
        if direction == "C2S":
            parts.append("**Direction:** Client-to-server traffic.")
        elif direction == "S2C":
            parts.append("**Direction:** Server-to-client traffic.")
        else:
            parts.append(f"**Direction:** `{direction}`.")

    if classification:
        parts.append(f"**Classification:** `{classification}`. {classification_meaning(classification)}")

    if priority:
        parts.append(f"**Priority:** `{priority}`. {priority_meaning(priority)}")

    return "\n\n".join(parts)

st.title("🛡️ Network Intrusion Detection Dashboard")
st.caption("Live packet monitoring and Snort alert visualization")

if not DB_FILE.exists():
    st.error("Database not found. Please run init_db.py first.")
    st.stop()

packets = load_table("packets")
alerts = load_table("alerts")

# =========================
# Top Metrics
# =========================

total_packets = len(packets)
total_alerts = len(alerts)

active_hosts = 0

if not packets.empty:

    hosts = set()

    for ip in packets["src"].dropna():
        if str(ip).startswith("192.168.56."):
            hosts.add(ip)

    for ip in packets["dst"].dropna():
        if str(ip).startswith("192.168.56."):
            hosts.add(ip)

    active_hosts = len(hosts)

tcp_count = 0
icmp_count = 0
udp_count = 0
http_count = 0
ssh_count = 0

if not packets.empty:
    http_count = len(packets[packets["protocol"] == "HTTP"])
    ssh_count = len(packets[packets["protocol"] == "SSH"])
    tcp_count = len(packets[packets["protocol"] == "TCP"])
    icmp_count = len(packets[packets["protocol"] == "ICMP"])
    udp_count = len(packets[packets["protocol"] == "UDP"])

col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

col1.metric("Total Packets", total_packets)
col2.metric("Snort Alerts", total_alerts)
col3.metric("Active Hosts", active_hosts)
col4.metric("TCP Packets", tcp_count)
col5.metric("ICMP Packets", icmp_count)
col6.metric("HTTP Requests", http_count)
col7.metric("SSH Connections", ssh_count)

st.divider()


# =========================
# Ruleset Status
# =========================

with st.expander("Snort Ruleset Status", expanded=False):
    snort_version = get_snort_version()
    ruleset_status = get_ruleset_status()

    st.caption(
        "This panel shows which local Snort engine and Community Rules file are being used. "
        "It helps make alert results reproducible because different rule versions may detect traffic differently."
    )

    r1, r2, r3, r4 = st.columns(4)

    r1.metric("Enabled Alert Rules", ruleset_status["enabled_alert_rules"])
    r2.metric("Disabled Alert Rules", ruleset_status["disabled_alert_rules"])
    r3.metric("Total Alert Rules", ruleset_status["total_alert_rules"])
    r4.metric("Rules File Size", ruleset_status["file_size"])

    st.markdown("#### Ruleset Details")

    ruleset_details = pd.DataFrame([
        {"Field": "Snort Version", "Value": snort_version},
        {"Field": "Rules File", "Value": ruleset_status["rules_file"]},
        {"Field": "Rules File Exists", "Value": ruleset_status["exists"]},
        {"Field": "Last Modified", "Value": ruleset_status["last_modified"]},
        {"Field": "SHA-256 Hash", "Value": ruleset_status["sha256"]},
    ])

    st.dataframe(
        ruleset_details,
        use_container_width=True,
        hide_index=True
    )

    if not ruleset_status["exists"]:
        st.warning(
            "The Snort Community Rules file was not found at the expected path. "
            "Rule lookup and signature explanation may not work until the path is corrected."
        )

# =========================
# Traffic Overview
# =========================

st.subheader("Network Traffic Overview")

left, right = st.columns(2)

with left:
    protocol_df = load_query("""
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
    """)

    if not protocol_df.empty:
        fig = px.pie(
            protocol_df,
            names="protocol",
            values="count",
            title="Protocol Distribution",
            hole=0.35
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No packet data available yet.")

with right:
    timeline_df = load_query("""
        SELECT timestamp, COUNT(*) AS packets
        FROM packets
        GROUP BY timestamp
        ORDER BY timestamp
    """)

    if not timeline_df.empty:
        fig = px.line(
            timeline_df,
            x="timestamp",
            y="packets",
            title="Packets Over Time",
            markers=True
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available yet.")

# =========================
# Top Talkers
# =========================

st.subheader("Top Network Hosts")

col_a, col_b = st.columns(2)

with col_a:
    src_df = load_query("""
        SELECT src, COUNT(*) AS packets
        FROM packets
        WHERE src != 'unknown'
        GROUP BY src
        ORDER BY packets DESC
        LIMIT 10
    """)

    if not src_df.empty:
        fig = px.bar(
            src_df,
            x="packets",
            y="src",
            orientation="h",
            title="Top Source IPs"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No source IP data available.")

with col_b:
    dst_df = load_query("""
        SELECT dst, COUNT(*) AS packets
        FROM packets
        WHERE dst != 'unknown'
        GROUP BY dst
        ORDER BY packets DESC
        LIMIT 10
    """)

    if not dst_df.empty:
        fig = px.bar(
            dst_df,
            x="packets",
            y="dst",
            orientation="h",
            title="Top Destination IPs"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No destination IP data available.")

# =========================
# Service Distribution
# =========================

st.subheader("Service Distribution")

service_df = load_query("""
    SELECT protocol AS service, COUNT(*) AS packets
    FROM packets
    WHERE protocol IN ('HTTP', 'SSH', 'ICMP', 'DNS', 'HTTPS')
    GROUP BY protocol
    ORDER BY packets DESC
""")

if not service_df.empty:
    fig = px.bar(
        service_df,
        x="packets",
        y="service",
        orientation="h",
        title="Observed Network Services"
    )
    fig.update_layout(
        yaxis={"categoryorder": "total ascending"},
        xaxis_title="Packets",
        yaxis_title="Service"
    )
    st.plotly_chart(fig, use_container_width=True)

    st.dataframe(
        service_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No service traffic available yet. Generate HTTP, SSH, ICMP, or DNS traffic.")

# =========================
# Alerts
# =========================

st.divider()
st.subheader("Snort Alert Analysis")

# Alert metrics
critical_alerts = 0
medium_alerts = 0
low_alerts = 0
unique_alert_types = 0

if not alerts.empty and "priority" in alerts.columns:
    critical_alerts = len(alerts[alerts["priority"] == 1])
    medium_alerts = len(alerts[alerts["priority"] == 2])
    low_alerts = len(alerts[alerts["priority"] == 3])

if not alerts.empty:
    if "msg" in alerts.columns:
        unique_alert_types = alerts["msg"].fillna(alerts.get("rule", "")).nunique()
    elif "rule" in alerts.columns:
        unique_alert_types = alerts["rule"].nunique()

a1, a2, a3, a4, a5 = st.columns(5)

a1.metric("Total Alerts", total_alerts)
a2.metric("Alert Types", unique_alert_types)
a3.metric("High Priority", critical_alerts)
a4.metric("Medium Priority", medium_alerts)
a5.metric("Low Priority", low_alerts)

alert_col1, alert_col2 = st.columns(2)

with alert_col1:
    alert_rules_df = load_query("""
        SELECT
            COALESCE(NULLIF(msg, ''), rule) AS signature,
            COUNT(*) AS alerts
        FROM alerts
        GROUP BY signature
        ORDER BY alerts DESC
        LIMIT 10
    """)

    if not alert_rules_df.empty:
        fig = px.bar(
            alert_rules_df,
            x="alerts",
            y="signature",
            orientation="h",
            title="Top Alert Messages"
        )
        fig.update_layout(
            yaxis={"categoryorder": "total ascending"},
            xaxis_title="Alerts",
            yaxis_title="Snort Alert Message"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No Snort alert signatures available yet.")

with alert_col2:
    priority_df = load_query("""
        SELECT
            CASE
                WHEN priority = 1 THEN 'High'
                WHEN priority = 2 THEN 'Medium'
                WHEN priority = 3 THEN 'Low'
                ELSE 'Unknown'
            END AS priority_level,
            COUNT(*) AS alerts
        FROM alerts
        GROUP BY priority
        ORDER BY priority
    """)

    if not priority_df.empty:
        fig = px.pie(
            priority_df,
            names="priority_level",
            values="alerts",
            title="Alert Priority Distribution",
            hole=0.35
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert priority data yet.")

# Alert timeline
alert_timeline_df = load_query("""
    SELECT timestamp, COUNT(*) AS alerts
    FROM alerts
    GROUP BY timestamp
    ORDER BY timestamp
""")

if not alert_timeline_df.empty:
    fig = px.line(
        alert_timeline_df,
        x="timestamp",
        y="alerts",
        title="Alert Timeline",
        markers=True
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No alert timeline available yet.")

# Extra JSON feature charts
feature_col1, feature_col2 = st.columns(2)

with feature_col1:
    protocol_alerts_df = load_query("""
        SELECT protocol, COUNT(*) AS alerts
        FROM alerts
        WHERE protocol IS NOT NULL AND protocol != ''
        GROUP BY protocol
        ORDER BY alerts DESC
    """)

    if not protocol_alerts_df.empty:
        fig = px.bar(
            protocol_alerts_df,
            x="alerts",
            y="protocol",
            orientation="h",
            title="Alert Protocol Distribution"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert protocol data available yet.")

with feature_col2:
    src_alerts_df = load_query("""
        SELECT COALESCE(NULLIF(src_addr, ''), src) AS source_ip, COUNT(*) AS alerts
        FROM alerts
        WHERE COALESCE(NULLIF(src_addr, ''), src) IS NOT NULL
          AND COALESCE(NULLIF(src_addr, ''), src) != ''
        GROUP BY source_ip
        ORDER BY alerts DESC
        LIMIT 10
    """)

    if not src_alerts_df.empty:
        fig = px.bar(
            src_alerts_df,
            x="alerts",
            y="source_ip",
            orientation="h",
            title="Top Alert Source IPs"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert source IP data available yet.")

port_col1, port_col2 = st.columns(2)

with port_col1:
    dst_port_df = load_query("""
        SELECT dst_port, COUNT(*) AS alerts
        FROM alerts
        WHERE dst_port IS NOT NULL
        GROUP BY dst_port
        ORDER BY alerts DESC
        LIMIT 10
    """)

    if not dst_port_df.empty:
        dst_port_df["dst_port"] = dst_port_df["dst_port"].astype(str)

        fig = px.bar(
            dst_port_df,
            x="alerts",
            y="dst_port",
            orientation="h",
            title="Top Alert Destination Ports"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No destination port data yet. This is normal for ICMP alerts.")

with port_col2:
    service_alerts_df = load_query("""
        SELECT service, COUNT(*) AS alerts
        FROM alerts
        WHERE service IS NOT NULL AND service != ''
        GROUP BY service
        ORDER BY alerts DESC
        LIMIT 10
    """)

    if not service_alerts_df.empty:
        fig = px.bar(
            service_alerts_df,
            x="alerts",
            y="service",
            orientation="h",
            title="Alert Service Distribution"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert service data available yet.")

# Recent detailed alert table
st.subheader("Detailed Recent Snort Alerts")

recent_alerts = load_query("""
    SELECT
        timestamp AS "Time",
        COALESCE(NULLIF(msg, ''), rule) AS "Alert Message",
        snort_rule AS "Rule ID",
        classification AS "Classification",
        priority AS "Priority",
        protocol AS "Protocol",
        service AS "Service",
        COALESCE(NULLIF(src_addr, ''), src) AS "Source IP",
        src_port AS "Source Port",
        COALESCE(NULLIF(dst_addr, ''), dst) AS "Destination IP",
        dst_port AS "Destination Port",
        direction AS "Direction",
        pkt_len AS "Packet Length",
        ttl AS "TTL",
        tcp_flags AS "TCP Flags",
        icmp_type AS "ICMP Type",
        icmp_code AS "ICMP Code",
        client_pkts AS "Client Packets",
        client_bytes AS "Client Bytes",
        server_pkts AS "Server Packets",
        server_bytes AS "Server Bytes"
    FROM alerts
    ORDER BY id DESC
    LIMIT 100
""")

if not recent_alerts.empty:
    def priority_label(p):
        if p == 1:
            return "High"
        elif p == 2:
            return "Medium"
        elif p == 3:
            return "Low"
        return "Unknown"

    recent_alerts["Priority Level"] = recent_alerts["Priority"].apply(priority_label)

    table_columns = [
        "Time",
        "Alert Message",
        "Rule ID",
        "Classification",
        "Priority",
        "Priority Level",
        "Protocol",
        "Service",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Direction",
        "Packet Length",
        "TTL",
        "TCP Flags",
        "ICMP Type",
        "ICMP Code",
        "Client Packets",
        "Client Bytes",
        "Server Packets",
        "Server Bytes",
    ]

    existing_columns = [col for col in table_columns if col in recent_alerts.columns]

    st.dataframe(
        recent_alerts[existing_columns],
        use_container_width=True,
        height=420
    )

    st.caption(
        "Each alert is generated when packet contents match a Snort rule signature. "
        "Priority indicates severity, where 1 is high, 2 is medium, and 3 is low. "
        "JSON alert fields add protocol, service, packet length, TTL, ICMP, TCP, and flow information."
    )
else:
    st.info("No recent Snort alerts yet.")

# =========================
# Signature Explanation
# =========================

st.subheader("Signature / Rule Explanation")

signature_alerts = load_query("""
    SELECT
        id,
        timestamp,
        COALESCE(NULLIF(msg, ''), rule) AS alert_message,
        snort_rule,
        classification,
        priority,
        protocol,
        service,
        COALESCE(NULLIF(src_addr, ''), src) AS src_ip,
        src_port,
        COALESCE(NULLIF(dst_addr, ''), dst) AS dst_ip,
        dst_port,
        direction,
        pkt_len,
        ttl,
        tcp_flags,
        icmp_type,
        icmp_code,
        gid,
        sid,
        rev,
        raw_json
    FROM alerts
    ORDER BY id DESC
    LIMIT 100
""")

if signature_alerts.empty:
    st.info("No alerts available to explain yet.")
else:
    selected_id = st.selectbox(
        "Select an alert/signature to understand",
        signature_alerts["id"].tolist(),
        format_func=lambda alert_id: (
            f"Alert {alert_id} | "
            f"{signature_alerts.loc[signature_alerts['id'] == alert_id, 'alert_message'].iloc[0]}"
        )
    )

    selected = signature_alerts[signature_alerts["id"] == selected_id].iloc[0]

    selected_for_explanation = {
        "Alert Message": selected.get("alert_message"),
        "Rule ID": selected.get("snort_rule"),
        "Classification": selected.get("classification"),
        "Priority": selected.get("priority"),
        "Protocol": selected.get("protocol"),
        "Service": selected.get("service"),
        "Source IP": selected.get("src_ip"),
        "Source Port": selected.get("src_port"),
        "Destination IP": selected.get("dst_ip"),
        "Destination Port": selected.get("dst_port"),
        "Direction": selected.get("direction"),
        "Packet Length": selected.get("pkt_len"),
        "TTL": selected.get("ttl"),
        "TCP Flags": selected.get("tcp_flags"),
        "ICMP Type": selected.get("icmp_type"),
        "ICMP Code": selected.get("icmp_code"),
    }

    st.markdown(signature_plain_english(selected_for_explanation))

    st.markdown("### Protocol-specific interpretation")
    st.info(protocol_meaning(selected_for_explanation))

    rule_text = find_rule_by_sid(selected.get("sid"))

    st.markdown("### Snort rule metadata")

    meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)

    meta_col1.metric("GID", selected.get("gid") if pd.notna(selected.get("gid")) else "N/A")
    meta_col2.metric("SID", selected.get("sid") if pd.notna(selected.get("sid")) else "N/A")
    meta_col3.metric("REV", selected.get("rev") if pd.notna(selected.get("rev")) else "N/A")
    meta_col4.metric("Priority", selected.get("priority") if pd.notna(selected.get("priority")) else "N/A")

    if rule_text:
        rule_msg = extract_rule_option(rule_text, "msg")
        rule_class = extract_rule_option(rule_text, "classtype")
        rule_sid = extract_rule_option(rule_text, "sid")
        rule_rev = extract_rule_option(rule_text, "rev")

        rule_details = pd.DataFrame([
            {"Field": "Rule Message", "Value": rule_msg},
            {"Field": "Class Type", "Value": rule_class},
            {"Field": "SID", "Value": rule_sid},
            {"Field": "Revision", "Value": rule_rev},
        ])

        st.dataframe(rule_details, use_container_width=True, hide_index=True)

        with st.expander("View original Snort rule"):
            st.code(rule_text, language="text")
    else:
        st.warning(
            "Could not find the original rule in the local Community rules file. "
            "The alert is still valid, but the rule may come from another inspector, "
            "a generated event, or a different rule file."
        )

    st.markdown("### 📚 Snort Rule Documentation Database")

    selected_gid = selected.get("gid", 1)
    selected_sid = selected.get("sid", None)

    rule_doc = load_rule_doc(selected_gid, selected_sid)

    if rule_doc:
        doc_found = rule_doc.get("doc_found", 0)

        st.markdown(
            f"**Rule ID:** `{rule_doc.get('gid', 1)}:{rule_doc.get('sid')}:{rule_doc.get('rev', '')}`"
        )

        doc_url = rule_doc.get("doc_url", "")
        if doc_url:
            st.markdown(f"**Documentation URL:** {doc_url}")

        if doc_found == 1:
            st.success("Snort.org documentation was found for this rule.")
        else:
            st.warning("No Snort.org documentation was found. Showing local rule-file metadata only.")

        show_doc_field("Rule Category", rule_doc.get("rule_category"))
        show_doc_field("Rule Explanation", rule_doc.get("rule_explanation"))
        show_doc_field("What To Look For", rule_doc.get("what_to_look_for"))
        show_doc_field("Known Usage", rule_doc.get("known_usage"))
        show_doc_field("False Positives", rule_doc.get("false_positives"))

        if rule_doc.get("cve_ids"):
            st.markdown("**CVE References:**")
            st.write(rule_doc.get("cve_ids"))

        if rule_doc.get("mitre_id"):
            st.markdown("**MITRE ATT&CK Mapping:**")
            st.write(
                f"{rule_doc.get('mitre_id')} — "
                f"{rule_doc.get('mitre_tactic', '')} / "
                f"{rule_doc.get('mitre_technique', '')}"
            )

        with st.expander("Local Snort Rule Metadata"):
            show_doc_field("Message", rule_doc.get("msg"))
            show_doc_field("Classification", rule_doc.get("classtype"))
            show_doc_field("Protocol", rule_doc.get("protocol"))
            show_doc_field("Source", f"{rule_doc.get('src_net')}:{rule_doc.get('src_port')}")
            show_doc_field("Destination", f"{rule_doc.get('dst_net')}:{rule_doc.get('dst_port')}")
            show_doc_field("Flow", rule_doc.get("flow"))
            show_doc_field("Service", rule_doc.get("service"))
            show_doc_field("Content Matches", rule_doc.get("content_matches"))
            show_doc_field("Metadata", rule_doc.get("metadata"))
            show_doc_field("References from Rule File", rule_doc.get("references_text"))

        with st.expander("Original Rule Text from rule_docs Database"):
            st.code(rule_doc.get("rule_text", ""), language="text")
    else:
        st.info("No rule documentation database entry found for this alert.")

with st.expander("ℹ️Snort JSON Feature Meaning"):
    feature_meaning = pd.DataFrame([
        {"Feature": "Alert Message", "Meaning": "The Snort rule message explaining what was detected."},
        {"Feature": "Rule ID", "Meaning": "Snort rule identifier in gid:sid:rev format."},
        {"Feature": "Classification", "Meaning": "The general category of the alert."},
        {"Feature": "Priority", "Meaning": "Severity level. Lower number means more serious."},
        {"Feature": "Protocol", "Meaning": "Network protocol, such as TCP, UDP, or ICMP."},
        {"Feature": "Service", "Meaning": "Detected application/service, such as HTTP, FTP, SNMP, or unknown."},
        {"Feature": "Source/Destination IP", "Meaning": "The endpoints involved in the alert."},
        {"Feature": "Source/Destination Port", "Meaning": "The TCP/UDP ports involved. ICMP alerts usually do not have ports."},
        {"Feature": "Direction", "Meaning": "C2S means client-to-server. S2C means server-to-client."},
        {"Feature": "Packet Length", "Meaning": "Size of the packet that triggered the alert."},
        {"Feature": "TTL", "Meaning": "Time To Live value from the IP header."},
        {"Feature": "TCP Flags", "Meaning": "TCP control flags, useful for SYN/FIN/NULL/Xmas scan analysis."},
        {"Feature": "ICMP Type/Code", "Meaning": "ICMP message details. Type 8 is Echo Request; type 0 is Echo Reply."},
        {"Feature": "Client/Server Packets and Bytes", "Meaning": "Flow counters showing traffic volume in each direction."},
    ])

    st.dataframe(feature_meaning, use_container_width=True, hide_index=True)

raw_alerts = load_query("""
    SELECT id, timestamp, COALESCE(NULLIF(msg, ''), rule) AS message, raw_json
    FROM alerts
    WHERE raw_json IS NOT NULL AND raw_json != ''
    ORDER BY id DESC
    LIMIT 100
""")

if not raw_alerts.empty:
    with st.expander("Inspect Raw JSON Alert"):
        selected_alert = st.selectbox(
            "Choose an alert",
            raw_alerts["id"].tolist(),
            format_func=lambda alert_id: (
                f"Alert {alert_id} | "
                f"{raw_alerts.loc[raw_alerts['id'] == alert_id, 'message'].iloc[0]}"
            )
        )

        selected_raw = raw_alerts.loc[raw_alerts["id"] == selected_alert, "raw_json"].iloc[0]

        try:
            st.json(json.loads(selected_raw))
        except Exception:
            st.code(selected_raw) 

# =========================
# Recent Packets
# =========================

st.divider()
st.subheader("Recent Network Packets")

recent_packets = load_query("""
    SELECT timestamp, src, dst, protocol, src_port, dst_port, size
    FROM packets
    ORDER BY id DESC
    LIMIT 100
""")

if not recent_packets.empty:
    st.dataframe(recent_packets, use_container_width=True, height=300)
else:
    st.info("No recent packet records yet.")


