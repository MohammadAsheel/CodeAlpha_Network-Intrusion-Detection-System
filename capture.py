from scapy.all import sniff
import logging

def start_sniffing(interface, packet_handler, alert_engine):
    """
    Starts the Scapy packet sniffer.
    """
    def process_packet(packet):
        # First update the stats on the dashboard
        alert_engine.update_stats(packet)
        # Then run it through the analyzer rules
        packet_handler(packet)

    try:
        # If interface is None, scapy will listen on all interfaces
        sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        if alert_engine.live:
            alert_engine.console.print(f"[bold red]Capture Error:[/bold red] {e}")
