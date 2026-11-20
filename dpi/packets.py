import os

from scapy.all import IP, TCP, Raw, send

# Configuration
# Replace with an IP address that your WSL can reach (e.g., your host Windows IP, or another internal IP)
# For simplicity, you can use 127.0.0.1 if testing purely internal WSL routing via NFQUEUE
# If you want to simulate external traffic, use a public IP or your host machine's IP.
TARGET_IP = os.environ.get("DPI_TARGET_IP", "127.0.0.1") # Override with your WSL IP or a test IP
SOURCE_IP = "192.168.1.100" # A fictitious source IP

def send_signature_packet(payload_data):
    """Sends a packet with a specific signature in the payload."""
    packet = IP(src=SOURCE_IP, dst=TARGET_IP) / TCP(dport=80) / Raw(load=payload_data.encode())
    print(f"Sending signature packet: {payload_data}")
    send(packet, verbose=0)

def send_regex_packet(payload_data):
    """Sends a packet with a specific regex pattern in the payload."""
    packet = IP(src=SOURCE_IP, dst=TARGET_IP) / TCP(dport=443) / Raw(load=payload_data.encode())
    print(f"Sending regex packet: {payload_data}")
    send(packet, verbose=0)

if __name__ == "__main__":
    print("--- Sending Custom Packets ---")

    # Test for signature rule: "secret_data_pattern"
    send_signature_packet("This packet contains some secret_data_pattern that should be detected.")

    # Test for regex rule: "(user|admin)_token=\d{4}"
    send_regex_packet("Authenticating with user_token=5678 for access.")
    send_regex_packet("Admin access requested with admin_token=1234. Please verify.")
    send_regex_packet("password =")

    print("--- Custom packets sent ---")
