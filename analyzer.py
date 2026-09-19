import time
from scapy.all import IP, TCP, UDP, ICMP
import config

class PacketAnalyzer:
    def __init__(self, detection_engine, alert_engine):
        self.detector = detection_engine
        self.alert_engine = alert_engine

    def analyze_packet(self, packet):
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        if src_ip in config.WHITELIST_IPS:
            return

        alerts = []

        # 1. Check Rate Anomaly for all packets
        alert = self.detector.check_rate_anomaly(src_ip, current_time)
        if alert:
            alerts.append(alert)

        # Protocol specific checks
        if TCP in packet:
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # 2. Check Port Scan
            alert = self.detector.check_port_scan(src_ip, dst_ip, dst_port, current_time)
            if alert:
                alerts.append(alert)
                
            # 3. Check SYN Flood (flags 'S' is SYN)
            if flags == 'S':
                alert = self.detector.check_syn_flood(src_ip, dst_ip, dst_port, current_time)
                if alert:
                    alerts.append(alert)

        elif ICMP in packet:
            # 4. Check ICMP Flood (ICMP type 8 is Echo Request)
            if packet[ICMP].type == 8:
                alert = self.detector.check_icmp_flood(src_ip, dst_ip, current_time)
                if alert:
                    alerts.append(alert)

        # Process any generated alerts
        for alert in alerts:
            self.alert_engine.process_alert(alert, packet)
