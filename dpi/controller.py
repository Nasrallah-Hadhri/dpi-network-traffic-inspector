from database import Database
from dpi_engine import DPIEngine

class Controller:
    def __init__(self, ui):
        self.ui = ui
        self.db = Database()
        self.dpi_engine = DPIEngine(db_instance=self.db)
        self.dpi_engine.set_packet_update_callback(self.notify_packet_update)
        self.current_user = None
        self.packet_view_open = False # Flag to indicate if packet view is open

    def set_ui_packet_refresh_callback(self, callback):
        self.packet_refresh_callback = callback

    def notify_packet_update(self):
        if self.packet_view_open and self.packet_refresh_callback:
            self.ui.after(0, self.packet_refresh_callback) # Use after to schedule on main thread

    def login(self, username, password):
        user = self.db.authenticate_user(username, password)
        if user:
            self.current_user = user
            if user['role'] == "ADMIN":
                self.ui.show_admin_dashboard()
            else:
                self.ui.show_user_dashboard(user)
            return True
        return False

    def register(self, username, password, role="USER"):
        if self.db.add_user(username, password, role):
            return True
        return False

    # DPI Engine commands
    def start_capture(self):
        if not self.dpi_engine.running:
            self.dpi_engine.start()
            return "Packet capture started successfully!"
        return "Packet capture is already running."

    def stop_capture(self):
        if self.dpi_engine.running:
            self.dpi_engine.stop()
            return "Packet capture stopped."
        return "Packet capture is not running."

    def get_captured_packets(self):
        return self.dpi_engine.get_recent_packets()

    # Database query methods
    def get_all_alerts(self):
        return self.db.get_alerts()

    def get_blocked_packets(self):
        return self.db.get_blocked_packets()

    def get_all_rules(self):
        return self.db.get_rules()

    def add_new_rule(self, type, pattern, action):
        success = self.db.add_rule(type, pattern, action)
        if success:
            self.dpi_engine.reload_rules() # Reload DPI rules after adding
        return success

    def delete_existing_rule(self, rule_id):
        success = self.db.delete_rule(rule_id)
        if success:
            self.dpi_engine.reload_rules() # Reload DPI rules after deleting
        return success

    def get_all_users(self):
        return self.db.get_all_users()

    def update_user_role(self, username, new_role):
        return self.db.update_user_role(username, new_role)

    def delete_user_account(self, username):
        return self.db.delete_user(username)

    # Admin specific functionalities
    def toggle_blocking(self):
        # Toggle the automatic blocking in DPI Engine
        current_state = self.dpi_engine.is_blocking_enabled()
        new_state = not current_state
        result = self.dpi_engine.set_blocking_enabled(new_state)
        return result

    def export_reports(self, format="CSV"):
        import pandas as pd
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            if format.upper() == "CSV":
                # Export alerts
                alerts = self.db.get_alerts()
                if alerts:
                    df_alerts = pd.DataFrame(alerts, columns=['Alert ID', 'Timestamp', 'Src IP', 'Dst IP', 'Protocol', 'Description', 'Payload'])
                    alerts_filename = f"alerts_report_{timestamp}.csv"
                    df_alerts.to_csv(alerts_filename, index=False)
                
                # Export blocked packets
                blocked = self.db.get_blocked_packets()
                if blocked:
                    df_blocked = pd.DataFrame(blocked, columns=['Packet ID', 'Timestamp', 'Src IP', 'Dst IP', 'Protocol', 'Payload'])
                    blocked_filename = f"blocked_packets_report_{timestamp}.csv"
                    df_blocked.to_csv(blocked_filename, index=False)
                
                # Export rules
                rules = self.db.get_rules()
                if rules:
                    df_rules = pd.DataFrame(rules, columns=['Rule ID', 'Type', 'Pattern', 'Action'])
                    rules_filename = f"rules_report_{timestamp}.csv"
                    df_rules.to_csv(rules_filename, index=False)
                
                return f"Reports exported successfully to CSV files with timestamp {timestamp}"
            
            elif format.upper() == "TXT":
                # Export to text files
                report_filename = f"dpi_report_{timestamp}.txt"
                with open(report_filename, 'w') as f:
                    f.write(f"DPI System Report - Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*80 + "\n\n")
                    
                    # Alerts section
                    f.write("ALERTS:\n")
                    f.write("-"*80 + "\n")
                    alerts = self.db.get_alerts()
                    for alert in alerts:
                        f.write(f"[{alert[1]}] {alert[2]} -> {alert[3]} | {alert[4]} | {alert[5]}\n")
                    f.write("\n")
                    
                    # Blocked packets section
                    f.write("\nBLOCKED PACKETS:\n")
                    f.write("-"*80 + "\n")
                    blocked = self.db.get_blocked_packets()
                    for pkt in blocked:
                        f.write(f"[{pkt[1]}] {pkt[2]} -> {pkt[3]} | Protocol: {pkt[4]}\n")
                    f.write("\n")
                    
                    # Rules section
                    f.write("\nACTIVE RULES:\n")
                    f.write("-"*80 + "\n")
                    rules = self.db.get_rules()
                    for rule in rules:
                        f.write(f"ID: {rule[0]} | Type: {rule[1]} | Pattern: {rule[2]} | Action: {rule[3]}\n")
                
                return f"Report exported successfully to {report_filename}"
            
            else:
                return f"Unsupported format: {format}. Use CSV or TXT."
        
        except Exception as e:
            return f"Error exporting reports: {str(e)}"

    def close_db(self):
        self.db.close()
