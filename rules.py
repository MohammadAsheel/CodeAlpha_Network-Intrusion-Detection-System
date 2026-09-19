import time
from collections import defaultdict
import config

class DetectionEngine:
    def __init__(self):
        # State for detection
        # src_ip -> list of (timestamp, dst_ip, dst_port)
        self.port_scan_history = defaultdict(list)
        
        # (src_ip, dst_ip) -> list of timestamps
        self.syn_history = defaultdict(list)
        
        # (src_ip, dst_ip) -> list of timestamps
        self.icmp_history = defaultdict(list)
        
        # src_ip -> list of timestamps
        self.rate_history = defaultdict(list)
        
        # Cooldown tracking: (src_ip, alert_type) -> timestamp of last alert
        self.cooldowns = {}

    def _is_on_cooldown(self, src_ip, alert_type, current_time):
        key = (src_ip, alert_type)
        if key in self.cooldowns:
            if current_time - self.cooldowns[key] < config.ALERT_COOLDOWN:
                return True
        return False

    def _set_cooldown(self, src_ip, alert_type, current_time):
        self.cooldowns[(src_ip, alert_type)] = current_time

    def _cleanup_old_records(self, history, current_time, window):
        """Removes records older than the time window. history is a list of timestamps or tuples where first element is timestamp."""
        if not history:
            return []
        
        # If it's a list of tuples (like port scan), index 0 is timestamp
        if isinstance(history[0], tuple):
            return [record for record in history if current_time - record[0] <= window]
        else:
            return [ts for ts in history if current_time - ts <= window]

    def check_port_scan(self, src_ip, dst_ip, dst_port, current_time):
        if self._is_on_cooldown(src_ip, "PORT_SCAN", current_time):
            return None

        self.port_scan_history[src_ip].append((current_time, dst_ip, dst_port))
        self.port_scan_history[src_ip] = self._cleanup_old_records(
            self.port_scan_history[src_ip], current_time, config.PORT_SCAN_WINDOW
        )

        # Count distinct ports for a specific target
        target_ports = set()
        for ts, dip, dport in self.port_scan_history[src_ip]:
            if dip == dst_ip:
                target_ports.add(dport)

        if len(target_ports) >= config.PORT_SCAN_THRESHOLD:
            self._set_cooldown(src_ip, "PORT_SCAN", current_time)
            # Clear history for this IP to prevent immediate re-trigger after cooldown
            self.port_scan_history[src_ip] = []
            return {
                "type": "PORT_SCAN",
                "source": src_ip,
                "target": dst_ip,
                "details": f"Scanned {len(target_ports)} distinct ports",
                "severity": "HIGH"
            }
        return None

    def check_syn_flood(self, src_ip, dst_ip, dst_port, current_time):
        if self._is_on_cooldown(src_ip, "SYN_FLOOD", current_time):
            return None

        key = (src_ip, dst_ip)
        self.syn_history[key].append(current_time)
        self.syn_history[key] = self._cleanup_old_records(
            self.syn_history[key], current_time, config.SYN_WINDOW
        )

        if len(self.syn_history[key]) >= config.SYN_THRESHOLD:
            self._set_cooldown(src_ip, "SYN_FLOOD", current_time)
            self.syn_history[key] = []
            return {
                "type": "SYN_FLOOD",
                "source": src_ip,
                "target": dst_ip,
                "details": f"Sent {config.SYN_THRESHOLD} SYN packets in {config.SYN_WINDOW}s to port {dst_port}",
                "severity": "HIGH"
            }
        return None

    def check_icmp_flood(self, src_ip, dst_ip, current_time):
        if self._is_on_cooldown(src_ip, "ICMP_FLOOD", current_time):
            return None

        key = (src_ip, dst_ip)
        self.icmp_history[key].append(current_time)
        self.icmp_history[key] = self._cleanup_old_records(
            self.icmp_history[key], current_time, config.ICMP_WINDOW
        )

        if len(self.icmp_history[key]) >= config.ICMP_THRESHOLD:
            self._set_cooldown(src_ip, "ICMP_FLOOD", current_time)
            self.icmp_history[key] = []
            return {
                "type": "ICMP_FLOOD",
                "source": src_ip,
                "target": dst_ip,
                "details": f"Sent {config.ICMP_THRESHOLD} ICMP echo requests in {config.ICMP_WINDOW}s",
                "severity": "MEDIUM"
            }
        return None

    def check_rate_anomaly(self, src_ip, current_time):
        if self._is_on_cooldown(src_ip, "RATE_ANOMALY", current_time):
            return None

        self.rate_history[src_ip].append(current_time)
        self.rate_history[src_ip] = self._cleanup_old_records(
            self.rate_history[src_ip], current_time, config.RATE_WINDOW
        )

        if len(self.rate_history[src_ip]) >= config.PACKET_RATE_THRESHOLD:
            self._set_cooldown(src_ip, "RATE_ANOMALY", current_time)
            self.rate_history[src_ip] = []
            return {
                "type": "RATE_ANOMALY",
                "source": src_ip,
                "target": "Multiple/Any",
                "details": f"Exceeded {config.PACKET_RATE_THRESHOLD} packets/s",
                "severity": "LOW"
            }
        return None
