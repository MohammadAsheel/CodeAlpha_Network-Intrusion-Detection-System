import time
import argparse
from scapy.all import IP, TCP, ICMP, send

def simulate_port_scan(target_ip, num_ports=20):
    print(f"[*] Simulating Port Scan against {target_ip} ({num_ports} ports)...")
    for port in range(1024, 1024 + num_ports):
        # Sending a SYN packet to each distinct port
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
    print("[+] Port Scan simulation complete.\n")

def simulate_icmp_flood(target_ip, count=25):
    print(f"[*] Simulating ICMP Flood against {target_ip} ({count} packets)...")
    for _ in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=False)
    print("[+] ICMP Flood simulation complete.\n")

def simulate_syn_flood(target_ip, target_port=80, count=25):
    print(f"[*] Simulating SYN Flood against {target_ip}:{target_port} ({count} packets)...")
    for _ in range(count):
        pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(pkt, verbose=False)
    print("[+] SYN Flood simulation complete.\n")

def main():
    parser = argparse.ArgumentParser(description="Simulate network traffic to test the NIDS")
    parser.add_argument("-t", "--target", help="Target IP for tests", default="127.0.0.1")
    parser.add_argument("--scan", action="store_true", help="Run Port Scan test")
    parser.add_argument("--icmp", action="store_true", help="Run ICMP Flood test")
    parser.add_argument("--syn", action="store_true", help="Run SYN Flood test")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    args = parser.parse_args()

    # Note: Sending packets via Scapy to 127.0.0.1 often bypasses standard interface 
    # capturing on some OSs. If testing locally, targeting your own LAN IP is often better.
    
    if not (args.scan or args.icmp or args.syn or args.all):
        print("Please specify a test to run (e.g. --all). Use -h for help.")
        return

    if args.scan or args.all:
        simulate_port_scan(args.target)
        time.sleep(2) # brief pause between tests

    if args.icmp or args.all:
        simulate_icmp_flood(args.target)
        time.sleep(2)

    if args.syn or args.all:
        simulate_syn_flood(args.target)
        
    print("[*] All selected simulations finished.")

if __name__ == "__main__":
    main()
