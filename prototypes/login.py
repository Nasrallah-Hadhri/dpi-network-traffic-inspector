import os
import secrets
import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import threading
import time
import re

# ===================== DATABASE =====================
def init_db():
    conn = sqlite3.connect("users.db")
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

def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ================= LOGIN =================
def login():
    username = username_entry.get()
    password = hash_pass(password_entry.get())

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    result = cursor.fetchone()
    conn.close()

    if result:
        if result[0] == "admin":
            admin_panel()
        else:
            user_panel()
    else:
        messagebox.showerror("Error", "Invalid login")

# ================= SIGNUP =================
def open_signup():
    signup_win = tk.Toplevel(root)
    signup_win.title("Create Account")
    signup_win.geometry("300x250")

    tk.Label(signup_win, text="Username").pack()
    new_user = tk.Entry(signup_win)
    new_user.pack()

    tk.Label(signup_win, text="Password").pack()
    new_pass = tk.Entry(signup_win, show="*")
    new_pass.pack()

    def create_account():
        username = new_user.get()
        password = hash_pass(new_pass.get())

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users VALUES(NULL,?,?,?)",
                           (username, password, "user"))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Account created")
            signup_win.destroy()
        except:
            messagebox.showerror("Error", "Username exists")

    tk.Button(signup_win, text="Create", command=create_account).pack(pady=10)

# ================= USER PANEL =================
capturing = False

def user_panel():
    user_win = tk.Toplevel(root)
    user_win.title("User Space")
    user_win.geometry("400x250")

    tk.Label(user_win, text="USER PANEL", font=("Arial",14,"bold")).pack(pady=10)

    status = tk.Label(user_win, text="Status: stopped", fg="red")
    status.pack()

    def capture():
        global capturing
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        while capturing:
            fake_packet = "Login attempt from 192.168.1.5"

            cursor.execute("SELECT pattern FROM rules")
            rules = cursor.fetchall()

            for r in rules:
                if re.search(r[0], fake_packet):
                    cursor.execute("INSERT INTO alerts(content) VALUES(?)", (fake_packet,))
                    conn.commit()

            time.sleep(3)

    def start_capture():
        global capturing
        capturing = True
        status.config(text="Status: Capturing...", fg="green")
        threading.Thread(target=capture).start()

    def stop_capture():
        global capturing
        capturing = False
        status.config(text="Status: Stopped", fg="red")

    tk.Button(user_win, text="Start Capture", width=20, command=start_capture).pack(pady=5)
    tk.Button(user_win, text="Stop Capture", width=20, command=stop_capture).pack()

# ================= ADMIN PANEL =================
def admin_panel():
    admin_win = tk.Toplevel(root)
    admin_win.title("Admin Dashboard")
    admin_win.geometry("650x500")

    tk.Label(admin_win, text="ADMIN PANEL", font=("Arial",16,"bold")).pack()

    tabs = tk.Frame(admin_win)
    tabs.pack()

    # ---------------- USERS ----------------
    user_frame = tk.LabelFrame(admin_win, text="Users")
    user_frame.pack(fill="x", padx=10, pady=5)

    user_list = tk.Listbox(user_frame, width=70)
    user_list.pack()

    def refresh_users():
        user_list.delete(0, tk.END)
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id,username,role FROM users")
        for u in cursor.fetchall():
            user_list.insert(tk.END, f"{u[0]} - {u[1]} ({u[2]})")
        conn.close()

    def delete_user():
        selected = user_list.get(tk.ACTIVE)
        if selected:
            user_id = selected.split(" - ")[0]
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            refresh_users()

    tk.Button(user_frame, text="Delete User", command=delete_user).pack()
    refresh_users()

    # ---------------- RULES ----------------
    rule_frame = tk.LabelFrame(admin_win, text="Analysis Rules (Regex / Signatures)")
    rule_frame.pack(fill="x", padx=10, pady=5)

    rule_list = tk.Listbox(rule_frame, width=50)
    rule_list.pack(side="left")

    rule_entry = tk.Entry(rule_frame)
    rule_entry.pack()

    def refresh_rules():
        rule_list.delete(0, tk.END)
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT pattern FROM rules")
        for r in cursor.fetchall():
            rule_list.insert(tk.END, r[0])
        conn.close()

    def add_rule():
        rule = rule_entry.get()
        if rule:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO rules(pattern) VALUES(?)", (rule,))
            conn.commit()
            conn.close()
            rule_entry.delete(0, tk.END)
            refresh_rules()

    def delete_rule():
        selected = rule_list.get(tk.ACTIVE)
        if selected:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rules WHERE pattern=?", (selected,))
            conn.commit()
            conn.close()
            refresh_rules()

    tk.Button(rule_frame, text="Add Rule", command=add_rule).pack()
    tk.Button(rule_frame, text="Delete Rule", command=delete_rule).pack()

    refresh_rules()

    # ---------------- ALERTS ----------------
    alert_frame = tk.LabelFrame(admin_win, text="Reports & Alerts")
    alert_frame.pack(fill="x", padx=10, pady=5)

    alert_list = tk.Listbox(alert_frame, width=70)
    alert_list.pack()

    def refresh_alerts():
        alert_list.delete(0, tk.END)
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT content, date FROM alerts ORDER BY id DESC")
        for a in cursor.fetchall():
            alert_list.insert(tk.END, f"{a[1]} - {a[0]}")
        conn.close()

    tk.Button(alert_frame, text="Refresh Alerts", command=refresh_alerts).pack()
    refresh_alerts()

    # ---------------- AUTO BLOCK ----------------
    block_frame = tk.LabelFrame(admin_win, text="Auto Block")
    block_frame.pack(fill="x", padx=10, pady=5)

    var_block = tk.IntVar()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT auto_block FROM settings WHERE id=1")
    var_block.set(cursor.fetchone()[0])
    conn.close()

    def toggle_block():
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE settings SET auto_block=? WHERE id=1", (var_block.get(),))
        conn.commit()
        conn.close()

    tk.Checkbutton(block_frame, text="Enable automatic blocking",
                   variable=var_block, command=toggle_block).pack()


# ================= MAIN =================
init_db()

root = tk.Tk()
root.title("Gestion des utilisateurs")
root.geometry("350x300")

tk.Label(root, text="LOGIN SYSTEM", font=("Arial",16,"bold")).pack(pady=10)

tk.Label(root, text="Username").pack()
username_entry = tk.Entry(root)
username_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

tk.Button(root, text="Login", width=20, command=login).pack(pady=10)
tk.Button(root, text="Create account", width=20, command=open_signup).pack()

root.mainloop()
