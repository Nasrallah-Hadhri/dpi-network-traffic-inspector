from scapy.all import IP, ICMP, send
import time
import sys

def simulate_ddos(target_ip, count=100):
    print(f"Simulating DDoS attack on {target_ip} with {count} packets...")
    for i in range(count):
        # We send to localhost or a dummy IP that will be captured by NFQUEUE
        pkt = IP(dst=target_ip, src="1.2.3.4") / ICMP()
        send(pkt, verbose=False)
        if i % 10 == 0:
            print(f"Sent {i} packets...")
    print("Simulation complete.")

if __name__ == "__main__":
    target = "127.0.0.1"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    simulate_ddos(target)
