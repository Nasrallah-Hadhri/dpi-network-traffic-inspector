"""Standalone schema initialiser for the early Tkinter prototype (login.py).

Creates users.db with the same tables as login.init_db(). The initial admin
credentials come from DPI_ADMIN_USERNAME / DPI_ADMIN_PASSWORD; if no password is
set, a random one is generated and printed once.
"""
import hashlib
import os
import secrets
import sqlite3


def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()


def init_db(path="users.db"):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    # Rules table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rules(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT
    )
    """)

    # Alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT,
        date TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings(
        id INTEGER PRIMARY KEY,
        auto_block INTEGER
    )
    """)

    # Initial admin (credentials from the environment, never hard-coded)
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    if not cursor.fetchone():
        admin_user = os.environ.get("DPI_ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("DPI_ADMIN_PASSWORD")
        if not admin_password:
            admin_password = secrets.token_urlsafe(12)
            print(f"Initial admin '{admin_user}' created with a random one-time password: {admin_password}")
        cursor.execute("INSERT INTO users (username,password,role) VALUES(?,?,?)",
                       (admin_user, hash_pass(admin_password), "admin"))

    # Default setting
    cursor.execute("SELECT * FROM settings WHERE id=1")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO settings (id,auto_block) VALUES(1,0)")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("success")
