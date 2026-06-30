import sqlite3
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

st_autorefresh(interval=10000, key="dashboard_refresh")

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
# Traffic Overview
# =========================

st.subheader("📡 Network Traffic Overview")

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

st.subheader("🌐 Top Network Hosts")

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

st.subheader("🌐 Service Distribution")

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
st.subheader("🚨 Snort Alert Analysis")

# Alert metrics
critical_alerts = 0
medium_alerts = 0
low_alerts = 0

if not alerts.empty:
    critical_alerts = len(alerts[alerts["priority"] == 1])
    medium_alerts = len(alerts[alerts["priority"] == 2])
    low_alerts = len(alerts[alerts["priority"] == 3])

a1, a2, a3, a4 = st.columns(4)

a1.metric("Total Alerts", total_alerts)
a2.metric("High Priority", critical_alerts)
a3.metric("Medium Priority", medium_alerts)
a4.metric("Low Priority", low_alerts)

alert_col1, alert_col2 = st.columns(2)

with alert_col1:
    alert_rules_df = load_query("""
        SELECT rule AS signature, COUNT(*) AS alerts
        FROM alerts
        GROUP BY rule
        ORDER BY alerts DESC
        LIMIT 10
    """)

    if not alert_rules_df.empty:
        fig = px.bar(
            alert_rules_df,
            x="alerts",
            y="signature",
            orientation="h",
            title="Top Alert Signatures"
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
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

# Recent detailed alert table
st.subheader("📋 Detailed Recent Snort Alerts")

recent_alerts = load_query("""
    SELECT 
        timestamp AS "Time",
        rule AS "Signature / Rule",
        classification AS "Classification",
        priority AS "Priority",
        protocol AS "Protocol",
        src AS "Source",
        dst AS "Destination"
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

    recent_alerts = recent_alerts[
        [
            "Time",
            "Signature / Rule",
            "Classification",
            "Priority",
            "Priority Level",
            "Protocol",
            "Source",
            "Destination"
        ]
    ]

    st.dataframe(
        recent_alerts,
        use_container_width=True,
        height=350
    )

    st.caption(
        "Each alert is generated when packet contents match a Snort rule signature. "
        "The priority indicates severity, where 1 is high and 3 is low."
    )
else:
    st.info("No recent Snort alerts yet.")

# =========================
# Recent Packets
# =========================

st.divider()
st.subheader("📋 Recent Network Packets")

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


