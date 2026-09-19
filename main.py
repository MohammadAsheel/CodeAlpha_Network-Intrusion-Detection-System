import argparse
import sys
import threading
from rules import DetectionEngine
from alert import AlertEngine
from analyzer import PacketAnalyzer
from capture import start_sniffing

def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System (NIDS)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0, Wi-Fi)", default=None)
    args = parser.parse_args()

    # Initialize components
    detection_engine = DetectionEngine()
    alert_engine = AlertEngine()
    analyzer = PacketAnalyzer(detection_engine, alert_engine)

    try:
        # Start the dashboard
        alert_engine.start()
        
        # This will block and run the sniffer
        start_sniffing(args.interface, analyzer.analyze_packet, alert_engine)
        
    except KeyboardInterrupt:
        # Stop gracefully
        alert_engine.stop()
        print("\n[!] NIDS shut down by user.")
        sys.exit(0)
    except Exception as e:
        alert_engine.stop()
        print(f"\n[!] Fatal Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
