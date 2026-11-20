
import sqlite3
import datetime
from utils import hash_password, check_password

class Database:
    def __init__(self, db_name="dpi.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS Alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                description TEXT NOT NULL,
                payload TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS Rules (
                rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS BlockedPackets (
                packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                payload TEXT
            )
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # User Management
    def add_user(self, username, password, role):
        hashed_password = hash_password(password)
        try:
            self.cursor.execute("""
                INSERT INTO Users (username, password, role) VALUES (?, ?, ?)
            """, (username, hashed_password, role))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False # Username already exists

    def get_user(self, username):
        self.cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
        return self.cursor.fetchone()

    def authenticate_user(self, username, password):
        user = self.get_user(username)
        if user and check_password(password, user[2]): # user[2] is the hashed password
            return {"user_id": user[0], "username": user[1], "role": user[3]}
        return None

    def update_user_role(self, username, new_role):
        self.cursor.execute("UPDATE Users SET role = ? WHERE username = ?", (new_role, username))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def delete_user(self, username):
        self.cursor.execute("DELETE FROM Users WHERE username = ?", (username,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_all_users(self):
        self.cursor.execute("SELECT user_id, username, role FROM Users")
        return self.cursor.fetchall()

    # Alert Management
    def add_alert(self, src_ip, dst_ip, protocol, description, payload=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO Alerts (timestamp, src_ip, dst_ip, protocol, description, payload)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, protocol, description, payload))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_alerts(self, limit=None):
        query = "SELECT * FROM Alerts ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def clear_alerts(self):
        self.cursor.execute("DELETE FROM Alerts")
        self.conn.commit()
        return self.cursor.rowcount

    # Rule Management
    def add_rule(self, type, pattern, action):
        self.cursor.execute("""
            INSERT INTO Rules (type, pattern, action) VALUES (?, ?, ?)
        """, (type, pattern, action))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_rules(self):
        self.cursor.execute("SELECT * FROM Rules")
        return self.cursor.fetchall()

    def delete_rule(self, rule_id):
        self.cursor.execute("DELETE FROM Rules WHERE rule_id = ?", (rule_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    # Blocked Packets Management
    def add_blocked_packet(self, src_ip, dst_ip, protocol, payload=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO BlockedPackets (timestamp, src_ip, dst_ip, protocol, payload)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, protocol, payload))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_blocked_packets(self, limit=None):
        query = "SELECT * FROM BlockedPackets ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def clear_blocked_packets(self):
        self.cursor.execute("DELETE FROM BlockedPackets")
        self.conn.commit()
        return self.cursor.rowcount
