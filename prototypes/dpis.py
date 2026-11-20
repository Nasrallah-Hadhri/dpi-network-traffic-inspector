from scapy.all import *

def dpi(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        if "password" in data.lower():
            print("🔍 DPI: Found the word 'password'")
            print("Packet content:", data)
def detect_torrent(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        if "BitTorrent protocol" in data:
            print("🔥 Torrent traffic detected!")
            print(packet.summary())
def http_dpi(packet):
    if packet.haslayer(Raw):
        raw = packet[Raw].load.decode(errors="ignore")
        if "Host: facebook.com" in raw:
            print("📡 DPI: Facebook request detected!")
            print(raw)
def dns_dpi(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        print("DNS Query:", query)
        if "facebook.com" in query:
            print("🚫 DPI: Query for blocked domain detected!")

sniff(filter="udp port 53", prn=dns_dpi)
sniff(filter="tcp port 80", prn=http_dpi)
sniff(prn=detect_torrent)
sniff(prn=dpi)
