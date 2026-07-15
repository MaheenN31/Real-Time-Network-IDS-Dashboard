# 🛡️ Real-Time Network Intrusion Detection System Dashboard

A real-time Network Intrusion Detection System (NIDS) built using **Snort 3, Scapy, SQLite, and Streamlit**.

The system captures live network traffic, detects suspicious activity using Snort signature-based detection, stores packet and alert data in SQLite, and visualizes network activity through an interactive web dashboard.

The project also includes a **preprocessed Snort rule documentation dataset** created for future rule explanation, LLM/RAG-based alert interpretation, and security analysis.

---

## Features

- Real-time network traffic monitoring
- Live packet capture using Scapy
- Signature-based intrusion detection using Snort 3
- Snort JSON alert parsing
- SQLite backend for packet and alert storage
- Interactive Streamlit dashboard
- Automatic dashboard refresh
- Protocol and service distribution charts
- HTTP, SSH, ICMP, TCP, UDP, DNS and ARP traffic monitoring
- Snort alert visualization
- Alert severity and signature analysis
- Suspicious source IP monitoring
- Raw Snort JSON alert inspection
- Snort ruleset status display
- Rolling-window database storage
- Snort log rotation support
- Preprocessed Snort rule documentation dataset
- Normalized rule database exports
- JSON rule lookup dataset for future LLM/RAG integration

---

## System Architecture

```text
                     Host-Only Lab Network
                     (192.168.56.0/24)

           Kali VM                     Ubuntu Victim VM
      (Traffic Generator)             (Target Services)
       192.168.56.10                   192.168.56.20
                │                              │
                └──────────────┬───────────────┘
                               │
                               ▼
                        Ubuntu Snort VM
                         192.168.56.30
                ┌──────────────────────────────┐
                │         Snort 3 IDS          │
                │                              │
                │ Live Packet Collector        │
                │ Live Alert Collector         │
                │ SQLite Database              │
                │ Streamlit Dashboard          │
                │ Snort Rule Dataset           │
                └──────────────────────────────┘
```

---

## Working Pipeline

```text
                    Network Traffic
                           │
                           ▼
                 Monitoring Interface
                        (enp0s8)
                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼                                 ▼
     Scapy Collector                  Snort 3 IDS
          │                                 │
          ▼                                 ▼
 SQLite packets table              Snort JSON Alerts
 Latest 5000 packets               alert_json.txt
                                            │
                                            ▼
                                  Live Alert Collector
                                            │
                                            ▼
                                  SQLite alerts table
                                  Latest 1000 alerts
                                            │
                                            ▼
                                  Streamlit Dashboard
```

---

## Remote Dashboard Access

The Streamlit dashboard runs inside the Ubuntu Snort/Dashboard VM.

For private lab access, the dashboard can be exposed through the Windows host machine using VirtualBox NAT forwarding and Windows portproxy.

Current working access structure:

```text
Client Device / Mentor System
        │
        ▼
Windows Host IP:8501
        │
        ▼
Windows portproxy
        │
        ▼
127.0.0.1:8501
        │
        ▼
VirtualBox NAT Port Forwarding
        │
        ▼
Ubuntu VM Streamlit Dashboard
```

The dashboard is **hosted inside the Ubuntu VM**. The Windows host acts as a gateway/forwarding layer to make the dashboard accessible to other reachable systems.

Example URL:

```text
http://192.168.10.22:8501
```

The dashboard is accessible only while:

- Windows host is powered on
- Ubuntu VM is running
- Streamlit dashboard is running
- VirtualBox NAT forwarding is active
- Windows portproxy rule is active

Previously captured data can still be viewed from SQLite even if live attacks are not running, but the VM and Streamlit dashboard must still be online.

---

## Repository Structure

```text
Real-Time-Network-IDS-Dashboard/

├── README.md
├── requirements.txt
├── .gitignore
│
├── src/
│   ├── dashboard.py
│   ├── init_db.py
│   ├── live_packet_collector.py
│   └── live_alert_collector.py
│
├── data/
│   ├── README.md
│   ├── raw/
│   │   └── rule_docs_review.xlsx
│   │
│   ├── preprocessed/
│   │   └── rule_docs_preprocessed.xlsx
│   │
│   ├── normalized/
│   │   └── normalized_snort_rule_database.xlsx
│   │
│   └── json/
│       └── rule_docs_preprocessed_by_sid.json
│
├── scripts/
│   ├── README.md
│   ├── build_rule_docs_db.py
│   ├── repair_rule_docs_fetch.py
│   ├── export_preprocessed_rules.py
│   ├── create_rule_preprocessed_json.py
│   ├── export_normalized_database_excel.py
│   ├── create_rule_cves_table.py
│   ├── create_rule_mitre_table.py
│   ├── create_rule_references_table.py
│   ├── create_rule_content_matches_table.py
│   └── get_rule_context.py
│
├── docs/
│
└── screenshots/
    ├── image1.png
    ├── image2.png
    ├── image3.png
    └── image4.png
```

---

## Technologies Used

| Component | Technology |
|---|---|
| IDS | Snort 3 |
| Packet Capture | Scapy |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Database | SQLite |
| Programming Language | Python |
| Operating System | Ubuntu |
| Attacker Machine | Kali Linux |
| Virtualization | Oracle VirtualBox |
| Dataset Processing | Python, SQLite, Pandas, OpenPyXL |

---

## Network Configuration

| Machine | Role | IP |
|---|---|---|
| Kali Linux | Attacker / Traffic Generator | `192.168.56.10` |
| Ubuntu Victim | Target / Victim | `192.168.56.20` |
| Ubuntu Snort VM | IDS + Dashboard VM | `192.168.56.30` |
| Windows Host | Dashboard Access Gateway | Depends on active network |

---

## Dashboard Overview

The dashboard provides visualization for:

- Total packets
- Snort alerts
- Active hosts
- TCP packets
- ICMP packets
- HTTP requests
- SSH connections
- Protocol distribution
- Service distribution
- Top source IPs
- Suspicious source IPs
- Alert severity distribution
- Top Snort alert signatures
- Recent packet table
- Recent Snort alert table
- Raw Snort JSON alerts
- Snort ruleset status

---

## Dataset Overview

This project includes Snort rule documentation data collected and preprocessed for future rule explanation and retrieval-based analysis.

### Dataset Files

| Folder | Purpose |
|---|---|
| `data/raw/` | Raw or review-stage rule documentation exports |
| `data/preprocessed/` | Cleaned single-table preprocessed rule documentation dataset |
| `data/normalized/` | Multi-table normalized Snort rule database export |
| `data/json/` | JSON dataset keyed by SID for future LLM/RAG lookup |

### Included Dataset Versions

| File | Description |
|---|---|
| `rule_docs_review.xlsx` | Review-stage Snort rule documentation export |
| `rule_docs_preprocessed.xlsx` | Cleaned preprocessed rule documentation dataset |
| `normalized_snort_rule_database.xlsx` | Normalized multi-table rule database export |
| `rule_docs_preprocessed_by_sid.json` | JSON rule lookup dataset keyed by SID |

---

## Normalized Rule Database

The normalized Snort rule database separates rule data into multiple related tables.

| Table | Description |
|---|---|
| `rules` | Core Snort rule metadata |
| `rule_documentation` | Snort documentation fields |
| `rule_cves` | CVE mappings |
| `rule_mitre` | MITRE ATT&CK mappings |
| `rule_references` | External references such as CVE, URL, Bugtraq, and Nessus |
| `rule_content_matches` | Snort content match patterns |

Final normalized row counts:

| Table | Rows |
|---|---:|
| `rules` | 4017 |
| `rule_documentation` | 4017 |
| `rule_cves` | 2278 |
| `rule_mitre` | 207 |
| `rule_references` | 6735 |
| `rule_content_matches` | 7413 |

---

## Scripts Overview

The `scripts/` folder contains helper scripts used for dataset collection, cleaning, normalization, export, and retrieval.

| Script | Purpose |
|---|---|
| `build_rule_docs_db.py` | Scrapes Snort rule documentation and stores rule metadata in SQLite |
| `repair_rule_docs_fetch.py` | Repairs failed or incomplete documentation fetches |
| `export_preprocessed_rules.py` | Exports cleaned preprocessed rules to Excel |
| `create_rule_preprocessed_json.py` | Converts preprocessed Excel data into JSON keyed by SID |
| `export_normalized_database_excel.py` | Exports normalized tables to a multi-sheet Excel workbook |
| `create_rule_cves_table.py` | Creates normalized CVE mapping table |
| `create_rule_mitre_table.py` | Creates normalized MITRE mapping table |
| `create_rule_references_table.py` | Creates normalized rule reference table |
| `create_rule_content_matches_table.py` | Creates normalized content match table |
| `get_rule_context.py` | Retrieves full rule context using GID and SID |

---

## Installation

### Clone Repository

```bash
git clone https://github.com/MaheenN31/Real-Time-Network-IDS-Dashboard.git
cd Real-Time-Network-IDS-Dashboard
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Initialize Database

```bash
python src/init_db.py
```

### Install Snort 3

Install and configure:

- Snort 3
- Snort 3 Community Rules
- DAQ
- LuaJIT

Make sure the monitoring interface is configured correctly.

In this project, the Snort monitoring interface is:

```text
enp0s8
```

---

## Running the Project

Use separate terminal windows for each process.

### 1. Start the Packet Collector

```bash
cd /home/maheen/ids_streamlit_dashboard
sudo python3 src/live_packet_collector.py
```

### 2. Start the Alert Collector

```bash
cd /home/maheen/ids_streamlit_dashboard
python3 src/live_alert_collector.py
```

### 3. Start Snort

```bash
mkdir -p /home/maheen/snort_logs

sudo snort -q \
-c /usr/local/etc/snort/snort.lua \
-R /usr/local/etc/snort/rules/snort3-community.rules \
-i enp0s8 \
-A alert_json \
--lua "HOME_NET = '192.168.56.20/32'; EXTERNAL_NET = '192.168.56.10/32'; alert_json = { fields = 'timestamp iface proto service src_addr src_port dst_addr dst_port dir pkt_len action msg class priority rule gid sid rev ttl tos tcp_flags icmp_type icmp_code client_pkts client_bytes server_pkts server_bytes' }" \
2>/tmp/snort_json_errors.txt | tee -a /home/maheen/snort_logs/alert_json.txt
```

### 4. Start the Dashboard

```bash
streamlit run src/dashboard.py --server.address 0.0.0.0 --server.port 8501 --server.headless true
```

Open locally:

```text
http://127.0.0.1:8501
```

Or through the Windows forwarding setup:

```text
http://<windows-host-ip>:8501
```

---

## Generating Traffic

Run these commands from the Kali VM against the Ubuntu victim VM.

### ICMP

```bash
ping -c 10 192.168.56.20
```

### HTTP

```bash
curl http://192.168.56.20
```

### SSH

```bash
nc -vz 192.168.56.20 22
```

### Nmap Scan

```bash
sudo nmap -sS -Pn -p 1-1000 192.168.56.20
```

or:

```bash
sudo nmap -Pn -A 192.168.56.20
```

---

## Database Management

The system uses a rolling-window storage strategy.

### Packets

- Captured using Scapy
- Stored in SQLite
- Latest 5000 packets retained

### Alerts

- Generated by Snort
- Parsed from Snort JSON alert logs
- Stored in SQLite
- Latest 1000 alerts retained

This prevents unlimited database growth while preserving recent monitoring information for the dashboard.

---

## Snort Log Rotation

Snort alert logs can be managed using `logrotate`.

Recommended behavior:

- Rotate after 5 MB
- Keep the latest 5 rotated logs
- Compress old logs automatically
- Continue logging without restarting Snort

Example log files:

```text
alert_json.txt
alert_json.txt.1
alert_json.txt.2.gz
alert_json.txt.3.gz
```

---

## Versioning

This project uses Git tags for dashboard version history.

| Version | Description |
|---|---|
| `dashboard-v1.0` | First complete Streamlit IDS dashboard release |
| `dashboard-v2.0` | Updated dashboard with expanded Snort alert handling, rule dataset exports, scripts, and documentation |

To view a previous version:

```bash
git checkout dashboard-v1.0
```

To return to the latest version:

```bash
git checkout main
```

---

## Dashboard Preview

Screenshots are available in the `screenshots/` folder.

The dashboard includes:

- Main traffic metrics
- Protocol distribution
- Service distribution
- Snort alert analysis
- Recent packet view
- Recent alert view
- Snort ruleset status

---

## Troubleshooting

### Dashboard not updating

Ensure:

- Packet collector is running
- Alert collector is running
- Snort is running
- Streamlit dashboard is running
- Browser/dashboard refresh is enabled

### No packets captured

Check:

- Correct interface is configured
- Host-only adapter is connected
- Kali, victim, and Snort VM are on the same network
- Scapy collector is running with `sudo`

### No Snort alerts

Check:

- Snort community rules are loaded
- Snort is monitoring the correct interface
- Traffic matches enabled Snort signatures
- Alert collector is reading the correct JSON alert log

### Kali cannot reach victim

Check Kali IP and route:

```bash
ip -br addr
ip route
```

Expected Kali host-only IP:

```text
192.168.56.10/24
```

Test victim connectivity:

```bash
ping -c 4 192.168.56.20
```

### SQLite database growing too large

The project automatically limits:

```text
Packets → Latest 5000
Alerts  → Latest 1000
```

Snort logs are managed separately using log rotation.

### Dashboard accessible locally but not from other systems

Check:

- Windows host IP
- Windows firewall rule
- VirtualBox NAT port forwarding
- Windows portproxy rule
- Whether the other system can route to the Windows host IP

---

## Future Improvements

- LLM/RAG-based Snort alert explanation
- Automated rule context retrieval from the JSON dataset
- Machine learning based anomaly detection
- Email or Slack notifications
- Threat intelligence enrichment
- Multi-host monitoring
- Historical trend analysis
- Authentication for shared dashboard access
- Deployment on a dedicated lab-accessible server

---

## License

This project is released under the MIT License.

---

## Author

**Maheen Nadeem**  
BS Computer Science  
Real-Time Network Intrusion Detection System Internship Project
