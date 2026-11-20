import os
import time
import sys

from scapy.all import IP, TCP, UDP, ICMP, Raw, send

# Configuration (override with environment variables, see .env.example)
TARGET_IP = os.environ.get("DPI_TARGET_IP", "127.0.0.1")
# Dummy value placed in the test payload only to trigger the "password =" signature rule.
# It is NOT a real credential.
TEST_PASSWORD_PLACEHOLDER = os.environ.get("DPI_TEST_PAYLOAD_SECRET", "<dummy-value>")

def send_packet(src_ip, payload=None, protocol="TCP", dport=80):
    """Utility to send a custom packet."""
    if protocol == "TCP":
        pkt = IP(src=src_ip, dst=TARGET_IP) / TCP(dport=dport)
    elif protocol == "UDP":
        pkt = IP(src=src_ip, dst=TARGET_IP) / UDP(dport=dport)
    elif protocol == "ICMP":
        pkt = IP(src=src_ip, dst=TARGET_IP) / ICMP()
    
    if payload:
        pkt = pkt / Raw(load=payload.encode())
    
    print(f"Sending {protocol} packet from {src_ip} to {TARGET_IP} | Payload: {payload}")
    send(pkt, verbose=0)

def simulate_ddos(src_ip, count=100):
    """Simulates a DDoS attack by flooding packets."""
    print(f"\n--- Simulating DDoS attack from {src_ip} ({count} packets) ---")
    for i in range(count):
        pkt = IP(src=src_ip, dst=TARGET_IP) / ICMP()
        send(pkt, verbose=0)
        if i % 20 == 0:
            print(f"Sent {i} flood packets...")
    print("--- DDoS Simulation complete ---")

if __name__ == "__main__":
    print("--- Starting Advanced DPI Rule Testing ---\n")

    # 1. signature: "password =" -> DROP
    send_packet("192.168.1.10", f"Login attempt with password = {TEST_PASSWORD_PLACEHOLDER}", "TCP")

    # 2. regex: "admin" -> ALERT
    send_packet("192.168.1.11", "Accessing /admin/panel", "TCP")

    # 3. ip_block: 8.8.8.8 -> DROP
    send_packet("8.8.8.8", "Standard traffic from blocked IP", "TCP")

    # 4. ip_block: 1.1.1.1 -> ALERT
    send_packet("1.1.1.1", "Standard traffic from alert IP", "TCP")

    # 5. signature: "hack" -> DROP
    send_packet("192.168.1.12", "User tried to hack the system", "TCP")

    # 6. regex: "select" -> ALERT (SQLi)
    send_packet("192.168.1.13", "GET /search?id=1; SELECT * FROM users", "TCP")

    print("\n--- Starting Advanced Protocol & Header Testing ---")

    # 8. Protocol Identification: SSH -> ALERT
    send_packet("192.168.1.14", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1", "TCP", dport=22)

    # 9. Protocol Identification: FTP -> ALERT
    send_packet("192.168.1.15", "220 (vsFTPd 3.0.3)", "TCP", dport=21)

    # 10. Protocol Identification: SMTP -> ALERT
    send_packet("192.168.1.16", "220 mx.google.com ESMTP", "TCP", dport=25)

    # 11. Custom Rule: Admin port block (DNS example in engine)
    send_packet("192.168.1.17", "DNS Query payload", "UDP", dport=53)

    # 12. Fragmentation Inspection -> ALERT
    print("Sending fragmented ICMP packet (Fragmentation Detection Test)...")
    frag_pkt = IP(src="192.168.1.18", dst=TARGET_IP, frag=1, flags="MF") / ICMP()
    send(frag_pkt, verbose=0)

    # 13. High Port Traffic -> ALERT
    send_packet("192.168.1.19", "Traffic on dynamic port", "TCP", dport=50000)

    # 14. DDoS Protection Test
    # Sending more than 50 packets/sec (default window)
    simulate_ddos("2.2.2.2", 100)

    print("\n--- All tests sent. Check the DPI UI for Alerts and Blocked Packets. ---")
