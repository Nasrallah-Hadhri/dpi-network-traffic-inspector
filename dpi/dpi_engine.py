from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, sniff # Removed NFQUEUE from scapy.all as it's separate
from netfilterqueue import NetfilterQueue
import re
import threading
import time
import datetime


from database import Database

class DPIEngine:
    def __init__(self, queue_num=0, db_instance=None):
        self.queue_num = queue_num
        self.nfqueue = None
        self.db = db_instance # Expecting an instance of the Database class
        self.running = False
        self.capture_thread = None
        self.rules = [] # To be loaded from database by controller
        self.captured_packets_buffer = [] # Store recent packets for viewing
        self.MAX_PACKETS_BUFFER = 500 # Max packets to store in buffer
        self.blocking_enabled = True # Toggle for automatic blocking
        self.packet_update_callback = None # Callback function for UI updates
        
        # DDoS Protection parameters
        self.ip_track = {} # {ip: [timestamps]}
        self.ddos_threshold = 15 # Reduced for easier testing with scapy
        self.ddos_window = 5.0 # Increased window to catch slower bursts
        self.blocked_ips = set() # Manually or automatically blocked IPs
        
        # Protocol mapping
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}

    def _load_rules(self):
        if self.db:
            db_rules = self.db.get_rules()
            self.rules = []
            for rule in db_rules:
                pattern = rule[2].encode() if rule[1] == 'signature' else rule[2]
                self.rules.append({'id': rule[0], 'type': rule[1], 'pattern': pattern, 'action': rule[3]})
            print(f"DEBUG: Loaded {len(self.rules)} rules from database.")
        else:
            self.rules = [
                {'type': 'signature', 'pattern': b'malicious_pattern', 'action': 'DROP'},
                {'type': 'regex', 'pattern': r'evil\.com', 'action': 'ALERT'},
            ]
            print(f"DEBUG: Using default {len(self.rules)} hardcoded rules (no DB instance).")


    def _packet_handler(self, packet):
        db_thread_instance = None
        try:
            db_thread_instance = Database() # Create a new DB instance for this thread
            
            scapy_packet = IP(packet.get_payload()) # Convert netfilterqueue packet to scapy packet
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            verdict = self._analyze_packet(scapy_packet, db_thread_instance)

            # Store packet in buffer for viewing
            self._add_packet_to_buffer(scapy_packet, timestamp, verdict)

            # Only drop if blocking is enabled
            if verdict and "DROP" in verdict and self.blocking_enabled:
                print(f"Packet BLOCKED ({verdict}): {scapy_packet.summary()}")
                db_thread_instance.add_blocked_packet(
                    scapy_packet.src if scapy_packet.haslayer(IP) else "N/A",
                    scapy_packet.dst if scapy_packet.haslayer(IP) else "N/A",
                    self.protocol_map.get(scapy_packet.proto, str(scapy_packet.proto)) if scapy_packet.haslayer(IP) else "N/A",
                    str(scapy_packet.payload) if scapy_packet.haslayer(Raw) else None
                )
                packet.drop()
            else:
                if verdict == "DROP" and not self.blocking_enabled:
                    print(f"Packet would be DROPPED but blocking is disabled: {scapy_packet.summary()}")
                packet.accept()
        except Exception as e:
            print(f"Error processing packet: {e}")
            packet.accept() # Accept by default on error
        finally:
            if db_thread_instance:
                db_thread_instance.close()

    def _add_packet_to_buffer(self, scapy_packet, timestamp, verdict):
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "N/A"
        payload_snippet = ""

        if scapy_packet.haslayer(IP):
            src_ip = scapy_packet.src
            dst_ip = scapy_packet.dst
            protocol = self.protocol_map.get(scapy_packet.proto, str(scapy_packet.proto))
        elif scapy_packet.haslayer(Ether):
            src_ip = scapy_packet.src
            dst_ip = scapy_packet.dst
            protocol = f"Ether:{hex(scapy_packet.type)}"

        if scapy_packet.haslayer(Raw):
            payload_snippet = str(scapy_packet[Raw].load)[:100]

        self.captured_packets_buffer.append((
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            payload_snippet,
            verdict # Add verdict here
        ))

        if len(self.captured_packets_buffer) > self.MAX_PACKETS_BUFFER:
            self.captured_packets_buffer.pop(0)

        if self.packet_update_callback:
            self.packet_update_callback()

    def get_recent_packets(self):
        return list(self.captured_packets_buffer)


    def _analyze_packet(self, packet, db_instance):
        final_verdict = "ACCEPT"
        alert_description = []

        # Only proceed with DPI analysis if it's an IP packet
        if packet.haslayer(IP):
            # 1. Header Inspection
            header_verdict, header_alert = self._header_inspection(packet)
            if header_alert:
                alert_description.append(header_alert)
            if header_verdict == "DROP":
                final_verdict = "DROP"

            # 2. Payload Inspection
            payload = None
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                payload_verdict, payload_alerts = self._payload_inspection(packet, payload)
                alert_description.extend(payload_alerts)
                if payload_verdict == "DROP":
                    final_verdict = "DROP"

            # 3. DDoS Inspection (Highest priority drop)
            ddos_verdict, ddos_alert = self._ddos_inspection(packet)
            if ddos_alert:
                alert_description.append(ddos_alert)
            if ddos_verdict == "DROP":
                final_verdict = "DROP (DDoS)"

            # 4. Admin Rules
            admin_rule_verdict, admin_rule_alerts = self._apply_admin_rules(packet, payload)
            alert_description.extend(admin_rule_alerts)
            if admin_rule_verdict == "DROP":
                final_verdict = "DROP"

            # Log any alerts found during any stage
            if alert_description and db_instance:
                db_instance.add_alert(
                    packet.src if packet.haslayer(IP) else "N/A",
                    packet.dst if packet.haslayer(IP) else "N/A",
                    self.protocol_map.get(packet.proto, str(packet.proto)) if packet.haslayer(IP) else "N/A",
                    "; ".join(alert_description),
                    str(packet.payload) if packet.haslayer(Raw) else None
                )
            
            # Final Verdict Logic
            if "DROP" in final_verdict:
                return final_verdict
            elif alert_description:
                return "ALERT"
            else:
                return "ACCEPT"
        return "ACCEPT"

    def _header_inspection(self, packet):
        alert = None
        if packet.haslayer(IP):
            if packet[IP].flags & 0x02 or packet[IP].frag != 0:
                alert = "Fragmented IP packet detected"
        return "ACCEPT", alert

    def _payload_inspection(self, packet, payload):
        verdict = "ACCEPT"
        alerts = []

        # Signature Matching
        sig_verdict, sig_alerts = self._signature_inspection(payload)
        if sig_verdict == "DROP":
            return "DROP", alerts
        alerts.extend(sig_alerts)

        # Regex Matching
        regex_verdict, regex_alerts = self._regex_inspection(payload)
        if regex_verdict == "DROP":
            return "DROP", alerts
        alerts.extend(regex_alerts)

        # Binary Protocol Analysis
        binary_verdict, binary_alerts = self._binary_protocol_inspection(packet, payload)
        if binary_verdict == "DROP":
            return "DROP", alerts
        alerts.extend(binary_alerts)

        return verdict, alerts

    def _signature_inspection(self, payload):
        verdict = "ACCEPT"
        alerts = []
        for rule in self.rules:
            if rule['type'] == 'signature':
                try:
                    if rule['pattern'].lower() in payload.lower():
                        alerts.append(f"Signature match: {rule['pattern'].decode()}")
                        if rule['action'] == 'DROP':
                            verdict = "DROP"
                            break
                except (AttributeError, TypeError): # Handle cases where pattern is not bytes or payload is not bytes-like
                    pass
        return verdict, alerts

    def _regex_inspection(self, payload):
        verdict = "ACCEPT"
        alerts = []
        for rule in self.rules:
            if rule['type'] == 'regex':
                try:
                    if re.search(rule['pattern'], payload.decode('utf-8'), re.IGNORECASE):
                        alerts.append(f"Regex match: {rule['pattern']}")
                        if rule['action'] == 'DROP':
                            verdict = "DROP"
                            break
                except (UnicodeDecodeError, TypeError):
                    pass
        return verdict, alerts

    def _binary_protocol_inspection(self, packet, payload):
        verdict = "ACCEPT"
        alerts = []
        
        # HTTP Detection
        if packet.haslayer(TCP) and (b"GET /" in payload or b"POST /" in payload or b"HTTP/" in payload):
            alerts.append("HTTP traffic detected (binary pattern)")
        
        # DNS Detection (Port 53)
        if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
            alerts.append("DNS traffic detected")
        
        # FTP Detection (Port 21)
        if packet.haslayer(TCP) and (packet[TCP].sport == 21 or packet[TCP].dport == 21):
            if b"USER " in payload or b"PASS " in payload or b"220 " in payload:
                alerts.append("FTP traffic detected (binary pattern)")
        
        # SMTP Detection (Port 25)
        if packet.haslayer(TCP) and (packet[TCP].sport == 25 or packet[TCP].dport == 25):
            if b"MAIL FROM" in payload or b"RCPT TO" in payload or b"220 " in payload:
                alerts.append("SMTP traffic detected (binary pattern)")
        
        # SSH Detection (Port 22)
        if packet.haslayer(TCP) and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
            if b"SSH-" in payload:
                alerts.append("SSH traffic detected (binary pattern)")
        
        # Suspicious high ports (above 49152 - dynamic/private ports)
        if packet.haslayer(TCP):
            if packet[TCP].dport > 49152 or packet[TCP].sport > 49152:
                alerts.append(f"Traffic on high port detected: {packet[TCP].dport if packet[TCP].dport > 49152 else packet[TCP].sport}")
        
        return verdict, alerts

    def _ddos_inspection(self, packet):
        """Monitors packet rate from source IPs to detect potential DDoS attacks"""
        if not packet.haslayer(IP):
            return "ACCEPT", None

        src_ip = packet[IP].src
        now = time.time()

        # Check if IP is already in our internal blocked set (or if we want to check DB rules)
        # For this implementation, we handle automatic temporary blocking
        
        if src_ip not in self.ip_track:
            self.ip_track[src_ip] = []
        
        # Record this packet timestamp
        self.ip_track[src_ip].append(now)
        
        # Remove timestamps outside the window
        self.ip_track[src_ip] = [ts for ts in self.ip_track[src_ip] if now - ts <= self.ddos_window]
        
        # Check threshold
        count = len(self.ip_track[src_ip])
        if count > self.ddos_threshold:
            alert = f"DDoS attack detected from {src_ip} ({count} pkts/window)"
            return "DROP", alert

        return "ACCEPT", None

    def _apply_admin_rules(self, packet, payload=None):
        verdict = "ACCEPT"
        alerts = []
        # Example: Add a simple admin rule to drop all UDP traffic on port 53 (DNS)
        for rule in self.rules:
            if rule['type'] == 'admin_custom' and rule['action'] == 'DROP':
                # This is a placeholder for more complex admin rules
                if 'port' in rule and packet.haslayer(UDP) and packet[UDP].dport == rule['port']:
                    alerts.append(f"Admin rule: Dropping UDP traffic on port {rule['port']}")
                    verdict = "DROP"
                    break
            elif rule['type'] == 'ip_block':
                if packet.haslayer(IP) and (packet[IP].src == rule['pattern'] or packet[IP].dst == rule['pattern']):
                    alerts.append(f"IP Block Rule: Dropping traffic from/to {rule['pattern']}")
                    if rule['action'] == 'DROP':
                        verdict = "DROP"
                        break
        return verdict, alerts

    def start(self):
        if not self.running:
            self._load_rules() # Load rules when starting
            self.nfqueue = NetfilterQueue()
            try:
                self.nfqueue.bind(self.queue_num, self._packet_handler)
                print(f"DPI Engine started, listening on NFQUEUE {self.queue_num}")
                self.running = True
                self.capture_thread = threading.Thread(target=self.nfqueue.run)
                self.capture_thread.daemon = True # Allow program to exit even if thread is running
                self.capture_thread.start()
            except Exception as e:
                print(f"Failed to bind to NFQUEUE: {e}. Make sure you have root privileges and iptables rules are set.")
                self.running = False

    def set_packet_update_callback(self, callback):
        self.packet_update_callback = callback

    def reload_rules(self):
        self._load_rules()
        print("DPI Engine rules reloaded from database.")

    def set_blocking_enabled(self, enabled):
        """Enable or disable automatic packet blocking"""
        self.blocking_enabled = enabled
        status = "enabled" if enabled else "disabled"
        print(f"Automatic blocking {status}.")
        return f"Automatic blocking {status}."

    def is_blocking_enabled(self):
        """Check if automatic blocking is enabled"""
        return self.blocking_enabled

    def stop(self):
        if self.running:
            print("DPI Engine stopping...")
            self.running = False
            if self.nfqueue:
                self.nfqueue.unbind()
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=1)
            print("DPI Engine stopped.")
