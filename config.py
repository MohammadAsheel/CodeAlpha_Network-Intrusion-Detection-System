import os

# Threshold settings
PORT_SCAN_THRESHOLD = 10  # Distinct ports
PORT_SCAN_WINDOW = 5      # Seconds

SYN_THRESHOLD = 20        # SYN packets to same destination
SYN_WINDOW = 5            # Seconds

ICMP_THRESHOLD = 20       # ICMP packets to same destination
ICMP_WINDOW = 5           # Seconds

PACKET_RATE_THRESHOLD = 100 # Packets per second from same source
RATE_WINDOW = 5             # Seconds

# Alert Cooldowns (to prevent spam)
ALERT_COOLDOWN = 30       # Seconds before alerting again for same IP + alert type

# Logging and Output
LOG_FILE = "nids_alerts.log"
PCAP_FILE = "suspicious_traffic.pcap"
ENABLE_PCAP_EXPORT = True

# Ignore traffic from these IPs (e.g. localhost if desired)
WHITELIST_IPS = ["127.0.0.1"]
