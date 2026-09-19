# 🛡️ Python Network Intrusion Detection System (NIDS)

A lightweight, Python-based **Network Intrusion Detection System (NIDS)** built with **Scapy** that monitors network traffic in real time, analyzes packet behavior against configurable detection rules, generates security alerts, and preserves suspicious traffic for further investigation.

> ⚠️ **Educational Project:** This NIDS is designed for learning, authorized security testing, and controlled local environments.

---

## 📌 Overview

Traditional packet sniffers primarily capture and display network traffic.

This project goes a step further by analyzing traffic patterns and identifying potentially suspicious behavior such as:

- 🔴 Port Scanning
- 🔴 TCP SYN Floods
- 🔴 ICMP Floods
- 🟡 Abnormally High Packet Rates
- 🟡 Repeated Connection Attempts

When suspicious activity is detected, the system:

1. Identifies the source and destination.
2. Classifies the activity.
3. Assigns a severity level.
4. Generates a real-time alert.
5. Records the event in a log file.
6. Optionally preserves suspicious packets in a PCAP file.

---

## 🔎 Network Sniffer vs NIDS

This project builds upon the concepts from a basic network sniffer.

| Network Sniffer            | Network IDS                     |
| -------------------------- | ------------------------------- |
| Captures packets           | Captures packets                |
| Displays traffic           | Analyzes traffic                |
| Basic protocol information | Stateful traffic analysis       |
| No attack detection        | Detects suspicious patterns     |
| No security alerts         | Generates security alerts       |
| Mainly observation         | Detection + evidence collection |

### Simple flow

```text
Network Traffic
       ↓
Packet Capture
       ↓
Packet Analysis
       ↓
Detection Rules
       ↓
Suspicious Activity?
     ↙       ↘
   No         Yes
   ↓           ↓
Continue     Alert
               ↓
          Log + PCAP
```

---

# 🚨 Core Detection Rules

## 🔴 Port Scan Detection

Detects when a single source attempts to access multiple distinct destination ports within a configured time window.

Example:

```text
Source: 192.168.1.20

22
23
25
53
80
110
135
139
443
445
...
```

If the number of distinct ports exceeds the configured threshold, a `PORT_SCAN` alert is generated.

---

## 🔴 SYN Flood Detection

Tracks TCP SYN packets from a source toward a target.

A high number of SYN packets within a short time window can indicate a possible SYN flood.

The detector considers:

- Source IP
- Destination IP
- Destination port
- Number of SYN packets
- Detection time window

---

## 🔴 ICMP Flood Detection

Monitors ICMP Echo Requests and identifies unusually high request rates from a source.

This can help detect excessive ICMP traffic that may indicate an ICMP flood.

---

## 🟡 Rate Anomaly Detection

Tracks packet rates from individual sources.

If traffic exceeds the configured threshold, the system generates a lower-severity `RATE_ANOMALY` alert.

> ℹ️ A rate anomaly does not automatically mean malicious activity. Legitimate applications can generate high packet rates, so this detection is intentionally treated as a lower-confidence indicator.

---

# ✨ Features

- 📡 Real-time packet capture using Scapy
- 🔍 Stateful traffic analysis
- 🚨 Multiple intrusion detection rules
- 📊 Real-time terminal dashboard
- ⚙️ Configurable detection thresholds
- ⏱️ Time-window based detection
- 🛑 Alert cooldown mechanism
- 📝 Timestamped security logs
- 💾 Suspicious traffic PCAP export
- 🧪 Controlled attack simulation
- 🖥️ Windows, Linux, and macOS-aware ping handling
- 🔐 Designed for authorized security testing

---

# 🏗️ Project Architecture

```text
                    ┌──────────────────┐
                    │  Network Traffic │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │     capture.py   │
                    │   Scapy Sniffer  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    analyzer.py   │
                    │ Packet Analysis  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │     rules.py     │
                    │ Detection Engine │
                    └────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
        ┌─────────────────┐      ┌─────────────────┐
        │   Suspicious    │      │ Normal Traffic  │
        │    Activity     │      │                 │
        └────────┬────────┘      └─────────────────┘
                 │
                 ▼
        ┌─────────────────┐
        │    alert.py     │
        │  Alert Engine   │
        └────────┬────────┘
                 │
        ┌────────┼─────────┐
        ▼        ▼         ▼
      Alert     Log       PCAP
     Console    File     Evidence
```

---

# 📂 Project Structure

```text
CodeAlpha_NIDS/
│
├── alert.py
├── analyzer.py
├── capture.py
├── config.py
├── main.py
├── rules.py
├── simulate_attacks.py
│
├── requirements.txt
├── README.md
├── .gitignore
│
└── screenshots/
    ├── nids_dashboard.png
    ├── port_scan_detection.png
    ├── syn_flood_detection.png
    ├── alert_log.png
    └── pcap_analysis.png
```

### File Responsibilities

| File                  | Purpose                                      |
| --------------------- | -------------------------------------------- |
| `main.py`             | Application entry point                      |
| `capture.py`          | Handles packet capture                       |
| `analyzer.py`         | Extracts and analyzes packet information     |
| `rules.py`            | Implements intrusion detection rules         |
| `alert.py`            | Generates alerts, logs, and dashboard output |
| `config.py`           | Stores configurable thresholds               |
| `simulate_attacks.py` | Generates controlled local test traffic      |
| `requirements.txt`    | Python dependencies                          |

---

# ⚙️ Configuration

Detection thresholds are centralized in `config.py`.

Example configuration:

```python
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5

SYN_THRESHOLD = 20
SYN_WINDOW = 5

ICMP_THRESHOLD = 20
ICMP_WINDOW = 5

PACKET_RATE_THRESHOLD = 100

ALERT_COOLDOWN = 30
```

These values are intended as **testing and demonstration thresholds**, not universal definitions of malicious traffic.

Network environments vary, so production systems require proper baseline tuning.

---

# 🖥️ Dashboard

The NIDS provides a real-time terminal dashboard showing packet statistics and security alerts.

Example:

```text
╭──────────── NETWORK IDS ────────────╮
│ Packets     : 1,284                 │
│ TCP         : 721                   │
│ UDP         : 418                   │
│ ICMP        : 145                   │
│ Alerts      : 1                     │
╰─────────────────────────────────────╯

[!] PORT_SCAN
Source      : 192.168.1.50
Target      : 192.168.1.100
Details     : Scanned 20 distinct ports
Severity    : HIGH
```

The dashboard is implemented using the `Rich` library.

---

# 📸 Screenshots

## NIDS Dashboard

![NIDS Dashboard](Screenshots/nids_dashboard.png)

---

## Port Scan Detection

![Port Scan Detection](Screenshots/port_scan_detection.png)

---

## SYN Flood Detection

![SYN Flood Detection](Screenshots/syn_flood_detection.png)

---

## Alert Log

![Alert Log](Screenshots/alert_log.png)

---

## PCAP Analysis

![PCAP Analysis](screenshots/pcap_analysis.png)

---

# 🛠️ Technologies Used

- **Python 3**
- **Scapy** – packet capture and packet manipulation
- **Rich** – terminal dashboard and formatted output
- **Wireshark** – PCAP investigation
- **Npcap** – Windows packet capture support

---

# 📦 Installation

## 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY>
cd CodeAlpha_NIDS
```

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

### Windows

Packet capture requires **Npcap**.

Npcap is commonly installed alongside Wireshark.

### Linux

Scapy packet capture generally requires elevated privileges.

---

# ▶️ Usage

Start the NIDS:

```bash
python main.py
```

On systems requiring elevated privileges:

```bash
sudo python3 main.py
```

### Specify a network interface

```bash
python main.py -i "Wi-Fi"
```

For Linux, an interface may look like:

```bash
sudo python3 main.py -i eth0
```

---

# 🧪 Testing and Simulation

A controlled traffic simulation script is included to test the detection rules without requiring an actual attack against another system.

Run all available simulations:

```bash
python simulate_attacks.py --all
```

You can also specify a local target:

```bash
python simulate_attacks.py -t YOUR_LOCAL_IP --all
```

For example:

```bash
python simulate_attacks.py -t 192.168.1.50 --all
```

> ⚠️ Use the simulator only against systems and networks you own or have explicit permission to test.

---

# 🔬 Testing Workflow

A typical test can be performed using two terminals.

### Terminal 1

Start the NIDS:

```bash
python main.py
```

### Terminal 2

Run the controlled simulator:

```bash
python simulate_attacks.py --all
```

The NIDS should identify the generated traffic and produce corresponding alerts.

Expected flow:

```text
Simulator
    ↓
Controlled Traffic
    ↓
Scapy Capture
    ↓
Detection Rules
    ↓
Alert Generated
    ↓
nids_alerts.log
    ↓
Suspicious PCAP
```

---

# 📝 Logging

Detected events are written to:

```text
nids_alerts.log
```

Example:

```text
2026-08-09 23:41:14,130 - [WARNING] - RATE_ANOMALY
Src: 10.140.21.51
Dst: Multiple/Any
Exceeded 100 packets/s
Severity: LOW
```

The log provides:

- Timestamp
- Alert type
- Source address
- Destination information
- Detection details
- Severity

---

# 💾 PCAP Evidence

When enabled, suspicious packets can be preserved in a PCAP file.

The resulting capture can be opened using Wireshark for deeper packet-level investigation.

This allows the project to follow a basic security investigation workflow:

```text
Detection
   ↓
Alert
   ↓
Evidence Collection
   ↓
PCAP Analysis
```

Generated PCAP files are intentionally excluded from Git using `.gitignore` because they are runtime artifacts rather than source files.

---

# 🧠 Detection Severity

The system uses severity levels to distinguish stronger indicators from lower-confidence anomalies.

| Detection    | Severity  |
| ------------ | --------- |
| Port Scan    | 🔴 High   |
| SYN Flood    | 🔴 High   |
| ICMP Flood   | 🟠 Medium |
| Rate Anomaly | 🟡 Low    |

Severity represents the detection rule's confidence/importance and does **not** mean that every alert is automatically a confirmed attack.

---

# 🔐 Security Considerations

This project is intentionally designed for educational security testing.

Important considerations:

- Packet capture requires elevated privileges.
- Detection thresholds should be tuned for the monitored environment.
- Rate anomalies can generate false positives.
- A NIDS should not be treated as proof that an attack occurred.
- PCAP files may contain sensitive network information.
- Captured traffic should be handled securely.
- Monitoring networks without authorization may violate organizational policies or applicable laws.

---

# 🚧 Current Limitations

This project is intentionally lightweight and is not intended to replace enterprise IDS/IPS solutions.

Current limitations include:

- Rule-based detection rather than machine-learning detection.
- Thresholds require manual tuning.
- Rate-based rules can produce false positives.
- No centralized multi-host monitoring.
- No automated threat-intelligence integration.
- No automatic IP reputation lookup.
- No encrypted remote alerting.
- Limited application-layer protocol inspection.

---

# 🚀 Future Improvements

Potential future enhancements include:

- [ ] DNS anomaly detection
- [ ] HTTP/HTTPS traffic analysis
- [ ] ARP spoofing detection
- [ ] DNS tunneling detection
- [ ] Improved TCP state tracking
- [ ] Adaptive traffic baselines
- [ ] Threat-intelligence integration
- [ ] Email/Telegram security alerts
- [ ] Web-based monitoring dashboard
- [ ] Database-backed event storage
- [ ] Machine-learning based anomaly detection
- [ ] Multi-interface monitoring

---

# 🎥 Demonstration

The project demonstration covers:

1. Starting the NIDS.
2. Monitoring normal network traffic.
3. Displaying real-time packet statistics.
4. Generating controlled test traffic.
5. Detecting suspicious behavior.
6. Displaying security alerts.
7. Recording events in the alert log.
8. Preserving suspicious traffic for PCAP analysis.

---

# 📚 Learning Outcomes

Through this project, I gained practical experience with:

- Network packet analysis
- Python network programming
- Scapy
- TCP/IP fundamentals
- Stateful traffic analysis
- Rule-based intrusion detection
- Security alert generation
- Log management
- PCAP evidence collection
- Wireshark-based investigation
- False-positive considerations
- Security testing methodology

---

# 🔄 Project Progression

This project builds upon the concepts from my earlier **Network Sniffer** project.

```text
Network Sniffer
       │
       │ Capture & inspect traffic
       ▼
Network Intrusion Detection System
       │
       ├── Capture
       ├── Analyze
       ├── Detect
       ├── Alert
       └── Preserve Evidence
```

The main difference is that the NIDS introduces **stateful analysis and detection rules** instead of simply displaying captured packets.

---

# 📄 License

This project is intended for educational and authorized security-testing purposes.

See the repository license for usage and distribution terms.

---

# ⚠️ Disclaimer

This project is created strictly for **educational purposes and authorized security testing**.

Do not use the traffic simulation tools or packet-capture capabilities against systems, networks, or devices that you do not own or do not have explicit permission to test.

The author is not responsible for misuse of this software.
