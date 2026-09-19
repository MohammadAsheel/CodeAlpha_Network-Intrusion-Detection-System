import logging
from datetime import datetime
from scapy.all import wrpcap, TCP, UDP, ICMP, IP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
import config
import time
import threading

class AlertEngine:
    def __init__(self):
        self.stats = {
            "Total": 0,
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "Alerts": 0
        }
        
        # Setup logging
        logging.basicConfig(
            filename=config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - [%(levelname)s] - %(message)s'
        )
        
        self.console = Console()
        self.live = None
        self._running = False

    def start(self):
        self._running = True
        self.live = Live(self.generate_stats_panel(), console=self.console, refresh_per_second=4)
        self.live.start()

    def stop(self):
        self._running = False
        if self.live:
            self.live.stop()

    def generate_stats_panel(self):
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Stat", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Packets", f"{self.stats['Total']:,}")
        table.add_row("TCP", f"{self.stats['TCP']:,}")
        table.add_row("UDP", f"{self.stats['UDP']:,}")
        table.add_row("ICMP", f"{self.stats['ICMP']:,}")
        table.add_row("Alerts", f"{self.stats['Alerts']:,}")
        
        return Panel(table, title="NETWORK IDS", border_style="blue", expand=False)

    def update_stats(self, packet):
        self.stats["Total"] += 1
        
        if TCP in packet:
            self.stats["TCP"] += 1
        elif UDP in packet:
            self.stats["UDP"] += 1
        elif ICMP in packet:
            self.stats["ICMP"] += 1
            
        if self.live and self.stats["Total"] % 10 == 0:
            self.live.update(self.generate_stats_panel())

    def process_alert(self, alert, packet):
        self.stats["Alerts"] += 1
        if self.live:
            self.live.update(self.generate_stats_panel())
        
        # Format for console
        alert_text = Text()
        alert_text.append(f"\n[!] {alert['type']}\n", style="bold red")
        alert_text.append(f"Source      : {alert['source']}\n")
        alert_text.append(f"Target      : {alert['target']}\n")
        alert_text.append(f"Details     : {alert['details']}\n")
        alert_text.append(f"Severity    : {alert['severity']}\n", style="bold yellow" if alert['severity'] == "MEDIUM" else "bold red")
        
        # Print to console (above the live panel)
        if self.live:
            self.console.print(alert_text)
        else:
            self.console.print(alert_text)
            
        # Log to file
        logging.warning(
            f"{alert['type']} | Src: {alert['source']} | Dst: {alert['target']} | {alert['details']} | Severity: {alert['severity']}"
        )
        
        # Save PCAP if enabled
        if config.ENABLE_PCAP_EXPORT:
            try:
                wrpcap(config.PCAP_FILE, packet, append=True)
            except Exception as e:
                logging.error(f"Failed to write PCAP: {e}")
