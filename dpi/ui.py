import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

class UI(tk.Tk):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.title("DPI System - Deep Packet Inspection")
        self.geometry("1000x800")
        self.configure(bg="#0f172a")
        
        # Cross-platform maximize
        try:
            self.state("zoomed") # Windows
        except tk.TclError:
            try:
                self.attributes('-zoomed', True) # Linux
            except tk.TclError:
                self.geometry("1000x800") # Fallback
        
        # User state
        self.current_user = None
        self.current_role = None
        self.content_frame = None
        self.active_nav_btn = None
        self.nav_buttons = {}

        # Apply modern theme
        self._configure_styles()
        self._create_login_window()

    def _configure_styles(self):
        """Configure modern ttk styles for the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Treeview styling
        style.configure("Modern.Treeview",
                       background="#1e293b",
                       foreground="#e2e8f0",
                       fieldbackground="#1e293b",
                       borderwidth=0,
                       font=('Segoe UI', 10),
                       rowheight=30)
        
        style.configure("Modern.Treeview.Heading",
                       background="#334155",
                       foreground="#f1f5f9",
                       borderwidth=1,
                       relief="flat",
                       font=('Segoe UI', 10, 'bold'))
        
        style.map("Modern.Treeview",
                 background=[('selected', '#2563eb')])
        
        style.map("Modern.Treeview.Heading",
                 background=[('active', '#475569')])
                 
        # Scrollbar styling
        style.configure("Vertical.TScrollbar",
                       background="#334155",
                       troughcolor="#0f172a",
                       borderwidth=0,
                       arrowcolor="#e2e8f0")

    def _create_modern_frame(self, parent, bg="#1e293b"):
        return tk.Frame(parent, bg=bg, relief="flat", bd=0)

    def _create_card_frame(self, parent, bg="#334155"):
        shadow_frame = tk.Frame(parent, bg="#0f172a", relief="flat", bd=0)
        card_frame = tk.Frame(shadow_frame, bg=bg, relief="flat", bd=2, highlightthickness=1, highlightbackground="#475569")
        card_frame.pack(padx=2, pady=2, fill="both", expand=True)
        return shadow_frame, card_frame

    def _create_modern_label(self, parent, text, font_size=10, bold=False, fg="#e2e8f0"):
        font_weight = 'bold' if bold else 'normal'
        return tk.Label(parent, text=text, bg=parent['bg'], fg=fg, 
                       font=('Segoe UI', font_size, font_weight))

    def _create_modern_entry(self, parent, show=None):
        entry = tk.Entry(parent, bg="#334155", fg="#e2e8f0", 
                        font=('Segoe UI', 10), relief="flat", bd=0,
                        insertbackground="#06b6d4", highlightthickness=2,
                        highlightbackground="#475569", highlightcolor="#2563eb")
        if show:
            entry.config(show=show)
        return entry

    def _create_modern_button(self, parent, text, command, bg="#2563eb", fg="#ffffff", hover_bg="#1e40af"):
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                       font=('Segoe UI', 10, 'bold'), relief="flat", bd=0,
                       padx=24, pady=12, cursor="hand2", activebackground=hover_bg,
                       activeforeground="#ffffff")
        
        def on_enter(e): btn['background'] = hover_bg
        def on_leave(e): btn['background'] = bg
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _create_nav_button(self, parent, text, command, icon=""):
        btn_text = f"{icon}  {text}" if icon else text
        btn = tk.Button(parent, text=btn_text, command=command, bg="#0f172a", fg="#94a3b8",
                       font=('Segoe UI', 10, 'bold'), relief="flat", bd=0,
                       padx=20, pady=14, cursor="hand2", activebackground="#1e293b",
                       activeforeground="#f1f5f9", anchor="w")
        
        def on_enter(e): 
            if self.active_nav_btn != btn:
                btn['background'] = '#1e293b'
                btn['foreground'] = '#f1f5f9'
        
        def on_leave(e): 
            if self.active_nav_btn != btn:
                btn['background'] = '#0f172a'
                btn['foreground'] = '#94a3b8'
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _set_active_nav(self, btn_name):
        # Reset all buttons
        for name, btn in self.nav_buttons.items():
            btn.config(bg="#0f172a", fg="#94a3b8")
            
        # Highlight active
        if btn_name in self.nav_buttons:
            btn = self.nav_buttons[btn_name]
            btn.config(bg="#1e293b", fg="#06b6d4")
            self.active_nav_btn = btn

    # ================= LOGIN =================

    def _create_login_window(self):
        for widget in self.winfo_children():
            widget.destroy()

        main_frame = self._create_modern_frame(self, "#0f172a")
        main_frame.pack(fill="both", expand=True)
        
        center_frame = tk.Frame(main_frame, bg="#0f172a")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        header_label = self._create_modern_label(center_frame, "DPI SYSTEM", 24, True, "#06b6d4")
        header_label.pack(pady=(0, 8))
        
        subtitle_label = self._create_modern_label(center_frame, "Deep Packet Inspection", 11, False, "#94a3b8")
        subtitle_label.pack(pady=(0, 32))
        
        shadow, card = self._create_card_frame(center_frame)
        shadow.pack(padx=40, pady=20)
        
        content_frame = tk.Frame(card, bg="#334155")
        content_frame.pack(padx=32, pady=32)
        
        login_title = self._create_modern_label(content_frame, "Sign In", 16, True, "#f1f5f9")
        login_title.pack(pady=(0, 24))
        
        username_label = self._create_modern_label(content_frame, "Username", 9, False, "#94a3b8")
        username_label.pack(anchor="w", pady=(0, 4))
        self.username_entry = self._create_modern_entry(content_frame)
        self.username_entry.pack(fill="x", pady=(0, 16), ipady=8)
        self.username_entry.focus()
        
        password_label = self._create_modern_label(content_frame, "Password", 9, False, "#94a3b8")
        password_label.pack(anchor="w", pady=(0, 4))
        self.password_entry = self._create_modern_entry(content_frame, show="●")
        self.password_entry.pack(fill="x", pady=(0, 24), ipady=8)
        
        self.username_entry.bind('<Return>', lambda e: self._handle_login())
        self.password_entry.bind('<Return>', lambda e: self._handle_login())
        
        login_button = self._create_modern_button(content_frame, "LOGIN", self._handle_login)
        login_button.pack(fill="x", pady=(0, 8))

    def _handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.controller.login(username, password):
            pass # Controller calls show_user/admin_dashboard
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    # ================= MAIN LAYOUT =================

    def _setup_main_layout(self, user_info, role):
        for widget in self.winfo_children():
            widget.destroy()
            
        self.current_user = user_info
        self.current_role = role
        self.nav_buttons = {}
        
        # Top Container
        top_bar = self._create_modern_frame(self, "#0f172a")
        top_bar.pack(side="top", fill="x", ipady=0)
        
        # Logo Area (Left)
        logo_frame = tk.Frame(top_bar, bg="#0f172a")
        logo_frame.pack(side="left", padx=20, pady=10)
        
        logo_label = tk.Label(logo_frame, text="DPI", bg="#0f172a", fg="#06b6d4",
                             font=('Segoe UI', 18, 'bold'))
        logo_label.pack(side="left")
        
        # Navigation Buttons (Center/Left)
        nav_frame = tk.Frame(top_bar, bg="#0f172a")
        nav_frame.pack(side="left", padx=40, fill="y")
        
        # Define nav items based on role
        if role == "ADMIN":
            nav_items = [
                ("Dashboard", "🏠", self._show_dashboard_view),
                ("Monitoring", "📊", self._show_monitoring_view),
                ("Rules", "⚙", self._show_rules_view),
                ("Users", "👥", self._show_users_view),
                ("System", "🔧", self._show_system_view)
            ]
        else:
            nav_items = [
                ("Dashboard", "🏠", self._show_dashboard_view),
                ("Packets", "📊", self._show_packets_only_view),
                ("Alerts", "⚠", self._show_alerts_only_view)
            ]
            
        for name, icon, command in nav_items:
            btn = self._create_nav_button(nav_frame, name, 
                                        lambda n=name, c=command: [self._set_active_nav(n), c()], 
                                        icon)
            btn.pack(side="left", padx=2)
            self.nav_buttons[name] = btn

        # User Profile & Logout (Right)
        profile_frame = tk.Frame(top_bar, bg="#0f172a")
        profile_frame.pack(side="right", padx=20)
        
        user_label = tk.Label(profile_frame, text=f"{user_info.get('username', 'User')} ({role})", 
                             bg="#0f172a", fg="#94a3b8", font=('Segoe UI', 10))
        user_label.pack(side="left", padx=10)
        
        logout_btn = self._create_modern_button(profile_frame, "Logout", self._logout, 
                                                bg="#334155", hover_bg="#475569")
        logout_btn.config(pady=6, padx=12, font=('Segoe UI', 9))
        logout_btn.pack(side="left")
        
        # Separator
        ttk.Separator(self, orient='horizontal').pack(fill='x')
        
        # Content Area (Main)
        self.content_frame = self._create_modern_frame(self, "#1e293b")
        self.content_frame.pack(side="top", fill="both", expand=True)

    def _logout(self):
        self.controller.current_user = None
        self._create_login_window()

    def show_user_dashboard(self, user_info):
        self._setup_main_layout(user_info, "USER")
        self._show_dashboard_view()
        self._set_active_nav("Dashboard")

    def show_admin_dashboard(self):
        user_info = {"username": "Admin", "role": "ADMIN"} # Default for now
        self._setup_main_layout(user_info, "ADMIN")
        self._show_dashboard_view()
        self._set_active_nav("Dashboard")

    # ================= VIEWS =================

    def _clear_content(self):
        # cleanup previous view state
        if hasattr(self, 'controller'):
            self.controller.packet_view_open = False
            self.controller.set_ui_packet_refresh_callback(None)

        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _show_dashboard_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        
        # Welcome Banner
        header = self._create_modern_label(container, f"Dashboard Overview", 24, True, "#f1f5f9")
        header.pack(anchor="w", pady=(0, 20))
        
        # Info Cards Grid
        cards_frame = tk.Frame(container, bg="#1e293b")
        cards_frame.pack(fill="x", pady=(0, 40))
        
        # Stats logic can be expanded here
        stats = [
            ("Packets Captured", f"{len(self.controller.get_captured_packets())}", "#3b82f6"),
            ("Alerts Generated", f"{len(self.controller.get_all_alerts())}", "#f59e0b"),
            ("Blocked Threats", f"{len(self.controller.get_blocked_packets())}", "#ef4444"),
        ]
        
        for i, (label, value, color) in enumerate(stats):
            shadow, card = self._create_card_frame(cards_frame)
            card.configure(bg=color) # Colored cards
            shadow.grid(row=0, column=i, sticky="ew", padx=10 if i==1 else 0)
            
            # Inner white frame for better contrast
            inner = tk.Frame(card, bg=color, bd=0)
            inner.pack(padx=20, pady=20, fill="both")
            
            val_lbl = tk.Label(inner, text=value, font=('Segoe UI', 32, 'bold'), 
                               bg=color, fg="white")
            val_lbl.pack(anchor="w")
            
            lbl = tk.Label(inner, text=label, font=('Segoe UI', 11), 
                          bg=color, fg="white")
            lbl.pack(anchor="w")
            
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)
        
        # Quick Actions
        action_header = self._create_modern_label(container, "Quick Actions", 16, True, "#94a3b8")
        action_header.pack(anchor="w", pady=(0, 16))
        
        actions_grid = tk.Frame(container, bg="#1e293b")
        actions_grid.pack(fill="x")
        
        # Start/Stop Capture UI (integrated here)
        btn_start = self._create_modern_button(actions_grid, "▶ Start Capture", self._start_capture_act, bg="#10b981", hover_bg="#059669")
        btn_start.pack(side="left", padx=(0, 10))
        
        btn_stop = self._create_modern_button(actions_grid, "■ Stop Capture", self._stop_capture_act, bg="#ef4444", hover_bg="#dc2626")
        btn_stop.pack(side="left")

    def _start_capture_act(self):
        msg = self.controller.start_capture()
        messagebox.showinfo("Status", msg)
        self._show_dashboard_view() # Refresh

    def _stop_capture_act(self):
        msg = self.controller.stop_capture()
        messagebox.showinfo("Status", msg)

    # --- PACKETS / MONITORING VIEW ---
    
    def _show_monitoring_view(self):
        # Admin view combining Packets, Alerts, Blocked
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Tabs for sub-navigation
        tab_frame = tk.Frame(container, bg="#1e293b")
        tab_frame.pack(fill="x", pady=(0, 10))
        
        def switch_tab(tab_name):
            # Cleanup packet callback if it was active
            if self.controller.packet_view_open:
                self.controller.packet_view_open = False
                self.controller.set_ui_packet_refresh_callback(None)

            if hasattr(self, 'monitor_content'): self.monitor_content.destroy()
            self.monitor_content = tk.Frame(container, bg="#1e293b")
            self.monitor_content.pack(fill="both", expand=True)
            
            if tab_name == "Live Analysis":
                self._render_packet_table(self.monitor_content, realtime=True)
            elif tab_name == "Alerts":
                self._render_alerts_table(self.monitor_content)
            elif tab_name == "Blocked":
                self._render_blocked_table(self.monitor_content)
        
        # Tab Buttons
        for name in ["Live Analysis", "Alerts", "Blocked"]:
            btn = tk.Button(tab_frame, text=name, command=lambda n=name: switch_tab(n),
                            bg="#334155", fg="white", relief="flat", padx=16, pady=8, font=('Segoe UI', 10))
            btn.pack(side="left", padx=2)
            
        switch_tab("Live Analysis") # Default

    def _show_packets_only_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self._create_modern_label(container, "Live Packet Analysis", 20, True).pack(anchor="w", pady=(0,10))
        self._render_packet_table(container, realtime=True)

    def _show_alerts_only_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self._create_modern_label(container, "Security Alerts", 20, True, "#f59e0b").pack(anchor="w", pady=(0,10))
        self._render_alerts_table(container)

    # --- REUSABLE TABLES ---

    def _render_packet_table(self, parent, realtime=False):
        shadow, card = self._create_card_frame(parent)
        shadow.pack(fill="both", expand=True)
        
        columns = ("Timestamp", "Src IP", "Dst IP", "Protocol", "Payload", "State")
        tree = ttk.Treeview(card, columns=columns, show="headings", style="Modern.Treeview")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
            
        scroll = ttk.Scrollbar(card, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        
        # Initial populate (reversed to show newest at top)
        packets = self.controller.get_captured_packets()
        for i, pkt in enumerate(reversed(packets)):
            tag = 'evenrow' if i%2==0 else 'oddrow'
            tree.insert("", tk.END, values=(*pkt,), tags=(tag,))
        
        tree.tag_configure('evenrow', background='#1e293b')
        tree.tag_configure('oddrow', background='#0f172a')

        if realtime:
            # Register for real-time updates
            self.controller.packet_view_open = True
            self.controller.set_ui_packet_refresh_callback(lambda: self._refresh_packet_table(tree))
            
            # Simple manual refresh button as backup
            refresh_btn = self._create_modern_button(parent, "Refresh View", 
                lambda: self._refresh_packet_table(tree), bg="#3b82f6")
            refresh_btn.pack(pady=10)

    def _refresh_packet_table(self, tree):
        try:
            if not tree.winfo_exists():
                return
            for i in tree.get_children(): tree.delete(i)
            packets = self.controller.get_captured_packets()
            for i, pkt in enumerate(reversed(packets)):
                tag = 'evenrow' if i%2==0 else 'oddrow'
                tree.insert("", tk.END, values=(*pkt,), tags=(tag,))
        except tk.TclError:
            pass # Widget already destroyed

    def _render_alerts_table(self, parent):
        shadow, card = self._create_card_frame(parent)
        shadow.pack(fill="both", expand=True)
        
        columns = ("Timestamp", "Src IP", "Dst IP", "Protocol", "Description")
        tree = ttk.Treeview(card, columns=columns, show="headings", style="Modern.Treeview")
        
        for col in columns: 
            tree.heading(col, text=col)
            tree.column(col, width=150)
            
        scroll = ttk.Scrollbar(card, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        
        alerts = self.controller.get_all_alerts()
        for i, alrt in enumerate(alerts):
            tag = 'evenrow' if i%2==0 else 'oddrow'
            # alert structure: id, timestamp, src, dst, proto, desc, payload
            tree.insert("", tk.END, values=alrt[1:6], tags=(tag,))
        
        tree.tag_configure('evenrow', background='#1e293b')
        tree.tag_configure('oddrow', background='#0f172a')
        
        btn = self._create_modern_button(parent, "Refresh", lambda: self._render_alerts_table(parent))
        # Note: simplistic recursion for refresh, effectively redraws frame. Better to split populate logic.

    def _render_blocked_table(self, parent):
        shadow, card = self._create_card_frame(parent)
        shadow.pack(fill="both", expand=True)
        
        columns = ("Timestamp", "Src IP", "Dst IP", "Protocol", "Payload")
        tree = ttk.Treeview(card, columns=columns, show="headings", style="Modern.Treeview")
        
        for col in columns: tree.heading(col, text=col)
        tree.pack(side="left", fill="both", expand=True)
        
        blocked = self.controller.get_blocked_packets()
        for i, b in enumerate(blocked):
            # blocked: id, date, src, dst, proto, payload
            tree.insert("", tk.END, values=b[1:], tags=('evenrow' if i%2==0 else 'oddrow',))
            
        tree.tag_configure('evenrow', background='#1e293b')
        tree.tag_configure('oddrow', background='#0f172a')

    # --- RULES VIEW ---

    def _show_rules_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        self._create_modern_label(container, "Manage DPI Rules", 20, True).pack(anchor="w", pady=(0,10))
        
        # Add Rules Form
        shadow, add_form = self._create_card_frame(container)
        shadow.pack(fill="x", pady=(0, 20))
        
        form_inner = tk.Frame(add_form, bg="#334155")
        form_inner.pack(padx=20, pady=20, fill="x")
        
        # Compact horizontal form
        tk.Label(form_inner, text="Type:", bg="#334155", fg="#cbd5e1").pack(side="left")
        type_var = tk.StringVar(value="signature")
        tk.OptionMenu(form_inner, type_var, "signature", "regex", "binary").pack(side="left", padx=5)
        
        tk.Label(form_inner, text="Pattern:", bg="#334155", fg="#cbd5e1").pack(side="left", padx=10)
        pat_entry = self._create_modern_entry(form_inner)
        pat_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        tk.Label(form_inner, text="Action:", bg="#334155", fg="#cbd5e1").pack(side="left", padx=10)
        act_var = tk.StringVar(value="ALERT")
        tk.OptionMenu(form_inner, act_var, "ALERT", "DROP").pack(side="left", padx=5)
        
        def add_cb():
            t, p, a = type_var.get(), pat_entry.get(), act_var.get()
            if not p: return messagebox.showwarning("Error", "Missing pattern")
            if self.controller.add_new_rule(t, p, a):
                messagebox.showinfo("Success", "Rule Added")
                self._update_rules_list(tree)
                pat_entry.delete(0, tk.END)
        
        self._create_modern_button(form_inner, "Add Rule", add_cb, bg="#10b981").pack(side="left", padx=20)
        
        # Rules List
        shadow2, list_frame = self._create_card_frame(container)
        shadow2.pack(fill="both", expand=True)
        
        cols = ("ID", "Type", "Pattern", "Action")
        tree = ttk.Treeview(list_frame, columns=cols, show="headings", style="Modern.Treeview")
        for c in cols: tree.heading(c, text=c)
        tree.pack(side="left", fill="both", expand=True)
        
        self._update_rules_list(tree)
        
        # Delete button at bottom
        del_btn = self._create_modern_button(container, "Delete Selected Rule", 
            lambda: self._delete_rule_cb(tree), bg="#ef4444")
        del_btn.pack(pady=10, fill="x")

    def _update_rules_list(self, tree):
        for i in tree.get_children(): tree.delete(i)
        for r in self.controller.get_all_rules():
            tree.insert("", tk.END, values=r)

    def _delete_rule_cb(self, tree):
        sel = tree.selection()
        if not sel: return
        rid = tree.item(sel[0])['values'][0]
        if self.controller.delete_existing_rule(rid):
            self._update_rules_list(tree)

    # --- USERS VIEW ---

    def _show_users_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        self._create_modern_label(container, "User Management", 20, True).pack(anchor="w", pady=(0,10))
        
        # Simple list + Add button logic (simplified for brevity but functional)
        shadow, table_frame = self._create_card_frame(container)
        shadow.pack(fill="both", expand=True, pady=(0, 20))
        
        cols = ("ID", "Username", "Role")
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", style="Modern.Treeview")
        for c in cols: tree.heading(c, text=c)
        tree.pack(fill="both", expand=True)
        
        for u in self.controller.get_all_users():
             tree.insert("", tk.END, values=u)
             
        # Add User Form (Horizontal)
        add_frame = tk.Frame(container, bg="#1e293b")
        add_frame.pack(fill="x")
        
        u_ent = self._create_modern_entry(add_frame)
        u_ent.insert(0, "Username")
        u_ent.pack(side="left", padx=5)
        
        p_ent = self._create_modern_entry(add_frame)
        p_ent.insert(0, "Password")
        p_ent.pack(side="left", padx=5)
        
        r_var = tk.StringVar(value="USER")
        tk.OptionMenu(add_frame, r_var, "USER", "ADMIN").pack(side="left", padx=5)
        
        def add_user():
            if self.controller.register(u_ent.get(), p_ent.get(), r_var.get()):
                messagebox.showinfo("Success", "User Added")
                self._show_users_view() # reload
        
        self._create_modern_button(add_frame, "Add User", add_user).pack(side="left", padx=10)
        
        # Delete
        def del_user():
            sel = tree.selection()
            if sel:
                uname = tree.item(sel[0])['values'][1]
                if self.controller.delete_user_account(uname):
                     self._show_users_view()
        
        self._create_modern_button(add_frame, "Delete Selected", del_user, bg="#ef4444").pack(side="right")

    # --- SYSTEM VIEW ---

    def _show_system_view(self):
        self._clear_content()
        container = tk.Frame(self.content_frame, bg="#1e293b")
        container.pack(fill="both", expand=True, padx=40, pady=40)
        
        self._create_modern_label(container, "System Configuration", 24, True).pack(anchor="w", pady=(0, 30))
        
        # Settings Grid
        grid = tk.Frame(container, bg="#1e293b")
        grid.pack(fill="x")
        
        # Toggle Blocking Card
        shadow1, card1 = self._create_card_frame(grid)
        shadow1.pack(fill="x", pady=10)
        
        inner1 = tk.Frame(card1, bg="#334155")
        inner1.pack(padx=20, pady=20, fill="x")
        
        lbl = self._create_modern_label(inner1, "Automatic Packet Blocking", 14, True)
        lbl.pack(side="left")
        
        def toggle_cb():
            res = self.controller.toggle_blocking()
            messagebox.showinfo("Result", res)
            
        btn = self._create_modern_button(inner1, "Toggle On/Off", toggle_cb, bg="#f59e0b")
        btn.pack(side="right")

        # Export Reports Card
        shadow2, card2 = self._create_card_frame(grid)
        shadow2.pack(fill="x", pady=10)
        
        inner2 = tk.Frame(card2, bg="#334155")
        inner2.pack(padx=20, pady=20, fill="x")
        
        lbl2 = self._create_modern_label(inner2, "Export System Reports", 14, True)
        lbl2.pack(side="left")
        
        def export_cb(fmt):
            res = self.controller.export_reports(fmt)
            messagebox.showinfo("Export", res)
            
        btn_txt = self._create_modern_button(inner2, "TXT Report", lambda: export_cb("TXT"), bg="#06b6d4")
        btn_txt.pack(side="right", padx=5)
        
        btn_csv = self._create_modern_button(inner2, "CSV Report", lambda: export_cb("CSV"), bg="#10b981")
        btn_csv.pack(side="right", padx=5)
