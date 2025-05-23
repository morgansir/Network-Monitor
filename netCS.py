
#!/usr/bin/env python3
"""
Network Monitor Pro -- Professional Network Monitor Application
Revised in English with enhanced UI colors, extra columns, protocol display,
and export (CSV/HTML) features.
تم إضافة دعم استيراد قواعد SIGMA الرسمية (YAML) من خلال زر "استيراد من ملف sigma yaml"
ليتيح للمستخدم تحميل ملف أو مجلد يحتوي على قواعد .yml، ويتم حفظها في قاعدة بيانات SQLite.
كما تم تعديل ألوان رؤوس الأعمدة في القوائم لتكون أكثر وضوحاً.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import sqlite3
import time
import threading
import asyncio
import concurrent.futures
import logging
import configparser
import csv
from datetime import datetime, timedelta, date
from ttkthemes import ThemedTk
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict, deque
import platform
import socket
import getpass
import os
import json
import yaml  # مكتبة PyYAML لدعم قواعد SIGMA

# ---------------------------
# Configuration Settings
# ---------------------------
config = configparser.ConfigParser()
default_config = {
    'scan': {
        'interval': '2',
        'heuristic_window': '60',
        'heuristic_conn_threshold': '10'
    },
    'threat': {
        'threat_list': '192.168.1.100,10.0.0.200',
        'suspicious_ports': '135,137,139,445,31337,6667'
    },
    'database': {
        'db_name': 'network_monitor_pro.db'
    },

    'logging': {
        'level': 'INFO',
        'log_file': 'network_monitor_pro.log'
    },
    'ui': {
        'theme': 'radiance',
        'base_color': '#34495e',
        'accent_color': '#1abc9c',
        'text_color': '#ecf0f1',
        'danger_color': '#e74c3c',
        'warning_color': '#f39c12',
        'info_color': '#3498db',
        # Extra colors for enhanced UI:
        'header_bg': '#2c3e50',
        'suspicious_bg': '#8e44ad',
        'normal_bg': '#27ae60',
        'gradient_bg': '#3b5998'
    }
}
config.read_dict(default_config)
config_file = "config_pro.ini"
config.read(config_file)

# ---------------------------
# Logging Setup
# ---------------------------
log_level_str = config.get('logging', 'level', fallback='INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
log_file = config.get('logging', 'log_file', fallback='network_monitor_pro.log')
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)
logging.info("--- Network Monitor Pro Initializing ---")
logging.info(f"Running on platform: {platform.system()} {platform.release()}")

# ---------------------------
# Database Class
# ---------------------------
class NetworkMonitorDB:
    def __init__(self):
        db_name = config.get('database', 'db_name', fallback='network_monitor_pro.db')
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.lock = threading.Lock()
        self.initialize_database()
        logging.info(f"Database initialized: {db_name}")

    def initialize_database(self):
        with self.lock:
            cursor = self.conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    local_address TEXT,
                    local_port INTEGER,
                    remote_address TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    process_name TEXT,
                    process_path TEXT,
                    pid INTEGER,
                    traffic_sent REAL DEFAULT 0,
                    traffic_received REAL DEFAULT 0,
                    duration REAL DEFAULT 0,
                    reason TEXT,
                    severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                    analysis_type TEXT CHECK(analysis_type IN ('list', 'heuristic', 'anomaly', 'unknown')),
                    owner TEXT,
                    frequency INTEGER DEFAULT 1,
                    connection_location TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_lists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_type TEXT CHECK(list_type IN ('blacklist', 'whitelist', 'monitored_ports', 'keywords', 'suspicious_ports')),
                    value TEXT UNIQUE,
                    created_at TEXT
                )
            ''')
            # إنشاء جدول لقواعد SIGMA
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sigma_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    rule_data TEXT,
                    imported_at TEXT
                )
            ''')
            self.conn.commit()
            logging.debug("Database tables checked/created.")

    def add_to_list(self, list_type, value):
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO monitoring_lists (list_type, value, created_at)

                    VALUES (?, ?, ?)
                ''', (list_type, value, datetime.now().isoformat()))
                self.conn.commit()
                if cursor.rowcount > 0:
                    logging.info(f"Added '{value}' to list '{list_type}'.")
                else:
                    logging.warning(f"Value '{value}' already exists in list '{list_type}'.")
            except sqlite3.Error as e:
                logging.error(f"Database error adding to list {list_type}: {e}")

    def remove_from_list(self, list_type, value):
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    DELETE FROM monitoring_lists WHERE list_type = ? AND value = ?
                ''', (list_type, value))
                self.conn.commit()
                if cursor.rowcount > 0:
                    logging.info(f"Removed '{value}' from list '{list_type}'.")
                else:
                    logging.warning(f"Value '{value}' not found in list '{list_type}' for removal.")
            except sqlite3.Error as e:
                logging.error(f"Database error removing from list {list_type}: {e}")

    def get_list(self, list_type):
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    SELECT value FROM monitoring_lists WHERE list_type = ?
                ''', (list_type,))
                return {row[0] for row in cursor.fetchall()}
            except sqlite3.Error as e:
                logging.error(f"Database error getting list {list_type}: {e}")
                return set()

    def save_result(self, data):
        if len(data) != 19:
            logging.error(f"Incorrect number of items in data tuple for save_result. Expected 19, got {len(data)}. Data: {data}")
            return
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO scan_results
                    (timestamp, local_address, local_port, remote_address, remote_port,
                     protocol, state, process_name, process_path, pid,
                     traffic_sent, traffic_received, duration, reason,
                     severity, analysis_type, owner, frequency, connection_location)

                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', data)
                self.conn.commit()
                logging.debug(f"Saved result: {data[14]} - {data[15]} - {data[13]}")
            except sqlite3.Error as e:
                logging.error(f"Database error saving result: {e}")

    def get_results(self, limit=500):
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                desc = cursor.description
                column_names = [col[0] for col in desc]
                data = [dict(zip(column_names, row)) for row in cursor.fetchall()]
                return data
            except sqlite3.Error as e:
                logging.error(f"Database error getting results: {e}")
                return []

    def save_sigma_rule(self, filename, rule_data):
        with self.lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO sigma_rules (filename, rule_data, imported_at)
                    VALUES (?, ?, ?)
                ''', (filename, json.dumps(rule_data, ensure_ascii=False), datetime.now().isoformat()))
                self.conn.commit()
                logging.info(f"Sigma rule '{filename}' imported.")
                return True
            except sqlite3.Error as e:
                logging.error(f"Database error saving sigma rule {filename}: {e}")
                return False

    def close(self):
        if self.conn:
            self.conn.close()
            logging.info("Database connection closed.")

# ---------------------------
# Main Application Class
# ---------------------------
class NetworkMonitorApp(ThemedTk):
    def __init__(self):
        self.theme = config.get('ui', 'theme', fallback='radiance')
        try:
            super().__init__(theme=self.theme)
            logging.info(f"Using theme: {self.theme}")

        except tk.TclError:
            logging.warning(f"Theme '{self.theme}' not found, falling back to default.")
            super().__init__()
            self.theme = 'default'
        self.title("Professional Network Monitor")
        self.geometry("1400x900")
        self.configure(bg=config.get('ui', 'gradient_bg'))
        self.db = NetworkMonitorDB()
        self.scan_active = False
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix="ScanWorker")
        self.scan_interval = float(config.get('scan', 'interval', fallback='2'))
        self.heuristic_window = timedelta(seconds=int(config.get('scan', 'heuristic_window', fallback='60')))
        self.heuristic_conn_threshold = int(config.get('scan', 'heuristic_conn_threshold', fallback='10'))
        self.connection_history = defaultdict(lambda: deque(maxlen=50))
        self.last_heuristic_analysis_time = datetime.min
        self.loop = None
        self.async_thread = threading.Thread(target=self.start_async_loop, daemon=True, name="AsyncLoopThread")
        self.async_thread.start()
        self.severity_colors = {
            'critical': config.get('ui', 'danger_color'),
            'high': config.get('ui', 'warning_color'),
            'medium': config.get('ui', 'info_color'),
            'low': config.get('ui', 'normal_bg')
        }
        self.time_series_data = deque(maxlen=100)
        self.current_user = getpass.getuser()
        self.setup_styles()
        self.setup_ui()
        self.load_initial_data()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        logging.info("UI Initialized.")

    def start_async_loop(self):
        logging.debug("Starting asyncio event loop in dedicated thread.")
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()
            logging.debug("Asyncio event loop closed.")

    def setup_styles(self):
        style = ttk.Style(self)
        base_color = config.get('ui', 'base_color', fallback='#34495e')
        accent_color = config.get('ui', 'accent_color', fallback='#1abc9c')
        text_color = config.get('ui', 'text_color', fallback='#ecf0f1')
        danger_color = config.get('ui', 'danger_color', fallback='#e74c3c')
        warning_color = config.get('ui', 'warning_color', fallback='#f39c12')

        info_color = config.get('ui', 'info_color', fallback='#3498db')
        button_fg = text_color
        button_font = ("Segoe UI", 10, "bold")
        label_font = ("Segoe UI", 10)
        style.configure("TFrame", background=base_color, borderwidth=1, relief="solid")
        style.configure("TLabel", background=base_color, foreground=text_color, font=label_font)
        style.configure("TLabelframe", background=base_color, foreground=text_color, font=label_font)
        style.configure("TLabelframe.Label", background=base_color, foreground=text_color, font=label_font)
        style.configure("TNotebook", background=base_color, borderwidth=0)
        style.configure("TNotebook.Tab", background=base_color, foreground=text_color, font=label_font, padding=[5, 2])
        style.map("TNotebook.Tab", background=[("selected", accent_color), ("active", info_color)],
                  foreground=[("selected", button_fg), ("active", button_fg)])
        style.configure("TButton", relief="raised", borderwidth=2, background=accent_color,
                        foreground=button_fg, font=button_font, padding=5)
        style.map("TButton", background=[("active", info_color), ("disabled", "#95a5a6")],
                  foreground=[("active", button_fg), ("disabled", "#bdc3c7")])
        style.configure("Danger.TButton", background=danger_color)
        style.map("Danger.TButton", background=[("active", "#c0392b")])
        style.configure("Warning.TButton", background=warning_color)
        style.map("Warning.TButton", background=[("active", "#e67e22")])
        # تعديل رؤوس الأعمدة لتكون بلون عصري واضح (على سبيل المثال خلفية داكنة مع نص أسود)
        style.configure("Treeview.Heading",
                        background=config.get('ui', 'header_bg'),
                        foreground="black",  # تغيير لون النص إلى أسود
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading", background=[('active', info_color)])
        style.configure("TEntry", borderwidth=1, relief="solid", fieldbackground="white", foreground="#2c3e50")

    def setup_ui(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        # Left Panel
        left_panel = ttk.Frame(main_frame, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        # Control Frame (Top of Left Panel)
        control_frame = ttk.LabelFrame(left_panel, text="Scan Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.stop_btn = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.export_csv_btn = ttk.Button(control_frame, text="Export CSV", command=lambda: self.export_report(all_results=True))
        self.export_csv_btn.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        self.export_html_btn = ttk.Button(control_frame, text="Export HTML", command=self.export_html_report)
        self.export_html_btn.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.refresh_btn = ttk.Button(control_frame, text="Refresh", command=self.manual_refresh)

        self.refresh_btn.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        self.close_btn = ttk.Button(control_frame, text="Close", command=self.on_close, style="Danger.TButton")
        self.close_btn.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        # زر استيراد قواعد SIGMA YAML
        self.import_sigma_btn = ttk.Button(control_frame, text="استيراد من ملف sigma yaml", command=self.import_sigma_yaml)
        self.import_sigma_btn.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        # Lists Notebook
        list_notebook = ttk.Notebook(left_panel)
        list_notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        self.create_list_tab(list_notebook, "Blacklist (IP)", "blacklist", "Enter IP Address")
        self.create_list_tab(list_notebook, "Monitored Ports", "monitored_ports", "Enter Port (0-65535)")
        self.create_list_tab(list_notebook, "Suspicious Ports", "suspicious_ports", "Enter Port (0-65535)")
        self.create_list_tab(list_notebook, "Keywords", "keywords", "Enter Keyword (e.g., temp)")
        self.create_list_tab(list_notebook, "Whitelist (IP)", "whitelist", "Enter IP Address")
        # Right Panel
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        # Results Notebook
        results_notebook = ttk.Notebook(right_panel)
        results_notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        all_results_frame = ttk.Frame(results_notebook)
        results_notebook.add(all_results_frame, text="All Activities")
        self.results_tree = self.create_results_treeview(all_results_frame)
        suspicious_frame = ttk.Frame(results_notebook)
        results_notebook.add(suspicious_frame, text="Suspicious Activities")
        self.suspicious_tree = self.create_results_treeview(suspicious_frame)
        # Action Frame at bottom of right panel
        action_frame = ttk.Frame(right_panel)
        action_frame.pack(fill=tk.X, pady=5)
        action_frame.columnconfigure(0, weight=1)
        info_action_frame = ttk.Frame(action_frame)
        info_action_frame.grid(row=0, column=0, sticky="ew")
        self.stop_conn_btn = ttk.Button(info_action_frame, text="Stop Selected Conn.", command=self.stop_connection, state=tk.DISABLED, style="Warning.TButton")
        self.block_btn = ttk.Button(info_action_frame, text="Block (Add IP)", command=self.block_connection, state=tk.DISABLED, style="Danger.TButton")
        self.allow_btn = ttk.Button(info_action_frame, text="Allow (Add IP)", command=self.allow_connection, state=tk.DISABLED)
        self.stop_conn_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.block_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.allow_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.info_txt = tk.Text(action_frame, height=8, wrap=tk.WORD, relief="solid", borderwidth=1,
                                 font=("Consolas", 9), background="#dfe6e9", foreground="#2d3436")
        self.info_txt.grid(row=1, column=0, sticky='ew', pady=(5, 0))
        # Graph Frame
        graph_frame = ttk.LabelFrame(right_panel, text="Graphical Info Panel")
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.graph_notebook = ttk.Notebook(graph_frame)
        self.graph_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.pie_chart_frame = ttk.Frame(self.graph_notebook)
        self.graph_notebook.add(self.pie_chart_frame, text="Risk Summary")
        self.line_chart_frame = ttk.Frame(self.graph_notebook)
        self.graph_notebook.add(self.line_chart_frame, text="Activity Over Time")
        self.bar_chart_frame = ttk.Frame(self.graph_notebook)
        self.graph_notebook.add(self.bar_chart_frame, text="Top Sources")
        self.initialize_graphs()

    def create_list_tab(self, notebook, tab_title, list_type, placeholder):
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=tab_title)
        label = ttk.Label(frame, text=f"Enter {list_type}:", font=("Segoe UI", 10))
        label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        entry = ttk.Entry(frame, font=("Segoe UI", 10), width=30)
        entry.grid(row=1, column=0, padx=5, pady=5)
        def add_to_list():
            value = entry.get().strip()
            if value:
                if list_type in ['monitored_ports', 'suspicious_ports']:
                    if value.isdigit() and 0 <= int(value) <= 65535:
                        self.db.add_to_list(list_type, value)
                        messagebox.showinfo("Addition Successful", f"Added {value} to {list_type}.", parent=self)
                        entry.delete(0, tk.END)
                    else:
                        messagebox.showwarning("Invalid Port", "Port must be between 0 and 65535.", parent=self)
                else:
                    self.db.add_to_list(list_type, value)
                    messagebox.showinfo("Addition Successful", f"Added '{value}' to {list_type}.", parent=self)
                    entry.delete(0, tk.END)
            else:
                messagebox.showwarning("Invalid Input", "Please enter a valid value.", parent=self)
        add_button = ttk.Button(frame, text="Add", command=add_to_list)
        add_button.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        listbox = tk.Listbox(frame, font=("Segoe UI", 10), height=10)
        listbox.grid(row=3, column=0, padx=5, pady=5, sticky="ew")
        items = self.db.get_list(list_type)
        for item in items:
            listbox.insert(tk.END, item)
        def remove_selected():
            selected_items = listbox.curselection()
            if selected_items:
                value = listbox.get(selected_items[0])
                self.db.remove_from_list(list_type, value)
                listbox.delete(selected_items[0])
                messagebox.showinfo("Removal Successful", f"Removed {value} from '{list_type}'.", parent=self)
        remove_button = ttk.Button(frame, text="Remove", command=remove_selected)
        remove_button.grid(row=4, column=0, padx=5, pady=5, sticky="ew")

    def create_results_treeview(self, parent_frame):
        tree_frame = ttk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("timestamp", "severity", "reason", "analysis", "local", "remote",
                   "protocol", "status", "process", "pid", "owner", "frequency", "path")
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        col_map = {
            "timestamp": ("Time", 160),
            "severity": ("Severity", 80),
            "reason": ("Reason", 220),
            "analysis": ("Analysis Type", 100),
            "local": ("Local", 150),
            "remote": ("Remote", 150),
            "protocol": ("Protocol", 70),
            "status": ("Status", 90),
            "process": ("Process", 130),
            "pid": ("PID", 60),
            "owner": ("Owner", 70),
            "frequency": ("Frequency", 90),
            "path": ("Conn. Path", 220)
        }
        for col, (text, width) in col_map.items():
            tree.heading(col, text=text, anchor=tk.W)
            tree.column(col, width=width, anchor=tk.W, stretch=tk.NO)
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree.bind("<<TreeviewSelect>>", self.on_select)
        tree.bind("<Double-1>", self.on_double_click)
        return tree

    def initialize_graphs(self):
        self.fig_pie = Figure(figsize=(3.5, 3), dpi=90, facecolor=config.get('ui', 'base_color'))
        self.ax_pie = self.fig_pie.add_subplot(111)
        self.ax_pie.set_facecolor(config.get('ui', 'base_color'))
        self.fig_pie.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)
        self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, master=self.pie_chart_frame)
        self.canvas_pie.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.fig_line = Figure(figsize=(4, 3), dpi=90, facecolor=config.get('ui', 'base_color'))
        self.ax_line = self.fig_line.add_subplot(111)
        self.ax_line.set_facecolor('#ecf0f1')
        self.ax_line.tick_params(axis='x', colors=config.get('ui', 'text_color'))
        self.ax_line.tick_params(axis='y', colors=config.get('ui', 'text_color'))
        self.ax_line.spines['top'].set_visible(False)
        self.ax_line.spines['right'].set_visible(False)
        self.ax_line.spines['bottom'].set_color(config.get('ui', 'text_color'))
        self.ax_line.spines['left'].set_color(config.get('ui', 'text_color'))
        self.fig_line.subplots_adjust(left=0.15, right=0.95, top=0.9, bottom=0.2)
        self.canvas_line = FigureCanvasTkAgg(self.fig_line, master=self.line_chart_frame)

        self.canvas_line.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.fig_bar = Figure(figsize=(4, 3), dpi=90, facecolor=config.get('ui', 'base_color'))
        self.ax_bar = self.fig_bar.add_subplot(111)
        self.ax_bar.set_facecolor('#ecf0f1')
        self.ax_bar.tick_params(axis='x', colors=config.get('ui', 'text_color'))
        self.ax_bar.tick_params(axis='y', colors=config.get('ui', 'text_color'))
        self.ax_bar.spines['top'].set_visible(False)
        self.ax_bar.spines['right'].set_visible(False)
        self.ax_bar.spines['bottom'].set_color(config.get('ui', 'text_color'))
        self.ax_bar.spines['left'].set_color(config.get('ui', 'text_color'))
        self.fig_bar.subplots_adjust(left=0.2, right=0.95, top=0.9, bottom=0.25)
        self.canvas_bar = FigureCanvasTkAgg(self.fig_bar, master=self.bar_chart_frame)
        self.canvas_bar.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        logging.debug("Graph canvases initialized.")

    async def run_scan_async(self):
        logging.debug("Scan loop initiated.")
        while self.scan_active:
            start_time = time.monotonic()
            try:
                monitored_ports = self.db.get_list('monitored_ports')
                suspicious_ports = self.db.get_list('suspicious_ports')
                blacklist = self.db.get_list('blacklist')
                keywords = self.db.get_list('keywords')
                whitelist = self.db.get_list('whitelist')
                current_conns = await self.get_connections_async()
                now = datetime.now()
                analysis_tasks = []
                for conn in current_conns:
                    task = self.loop.run_in_executor(
                        self.executor,
                        self.analyze_and_save_conn,
                        conn, monitored_ports, suspicious_ports, blacklist, keywords, whitelist, now
                    )
                    analysis_tasks.append(task)
                processed_results = await asyncio.gather(*analysis_tasks)
                valid_results = [res for res in processed_results if res]
                if now - self.last_heuristic_analysis_time > self.heuristic_window / 4:
                    heuristic_results = await self.perform_heuristic_analysis(current_conns, now)
                    valid_results.extend(heuristic_results)
                    self.last_heuristic_analysis_time = now
                if valid_results:
                    self.after(0, self.update_ui, valid_results)
            except Exception as e:
                logging.exception(f"Error in scanning loop: {e}")
            elapsed = time.monotonic() - start_time
            sleep_duration = max(0, self.scan_interval - elapsed)
            await asyncio.sleep(sleep_duration)
        logging.debug("Scan loop finished.")

    async def get_connections_async(self):

        try:
            conns = await self.loop.run_in_executor(self.executor, psutil.net_connections, "inet")
            return conns
        except Exception as e:
            logging.error(f"Failed to get network connections: {e}")
            return []

    def analyze_and_save_conn(self, conn, monitored_ports, suspicious_ports, blacklist, keywords, whitelist, timestamp):
        try:
            laddr = getattr(conn, 'laddr', None)
            raddr = getattr(conn, 'raddr', None)
            pid = getattr(conn, 'pid', None)
            status = getattr(conn, 'status', 'N/A')
            numeric_type = getattr(conn, 'type', None)
            if numeric_type == socket.SOCK_STREAM:
                protocol = "TCP"
            elif numeric_type == socket.SOCK_DGRAM:
                protocol = "UDP"
            else:
                protocol = "N/A"
            local_ip = laddr.ip if laddr else "N/A"
            local_port = laddr.port if laddr else 0
            remote_ip = raddr.ip if raddr else "N/A"
            remote_port = raddr.port if raddr else 0
            if remote_ip != "N/A" and remote_ip in whitelist:
                return None
            reasons = []
            severity = "low"
            analysis_type = "list"
            list_reasons = []
            current_severity_score = 0
            if remote_ip != "N/A" and remote_ip in blacklist:
                list_reasons.append("Blacklisted IP")
                current_severity_score = max(current_severity_score, 2)
            if str(local_port) in monitored_ports or str(remote_port) in monitored_ports:
                list_reasons.append("Monitored Port")
                current_severity_score = max(current_severity_score, 1)
            if str(local_port) in suspicious_ports or str(remote_port) in suspicious_ports:
                list_reasons.append("Suspicious Port")
                current_severity_score = max(current_severity_score, 2)
            process_name = "N/A"
            process_path = "N/A"
            owner = "System"
            if pid:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                    try:
                        process_path = proc.exe()
                    except (psutil.AccessDenied, OSError) as pe:

                        process_path = f"Access Denied ({pe})"
                        logging.warning(f"Access denied getting exe for PID {pid} ({process_name}).")
                    try:
                        username = proc.username()
                        owner = "User" if username == self.current_user else "System"
                    except psutil.Error:
                        owner = "Unknown"
                except psutil.NoSuchProcess:
                    process_name = "Terminated/Zombie"
                    process_path = "N/A"
                except psutil.AccessDenied:
                    process_name = "Access Denied"
                    process_path = "Access Denied"
                    logging.warning(f"Access denied getting process info for PID {pid}.")
            for kw in keywords:
                try:
                    if process_path not in ["N/A", "Access Denied"] and kw.lower() in process_path.lower():
                        list_reasons.append(f"Keyword: {kw}")
                        current_severity_score = max(current_severity_score, 1)
                        break
                except Exception as e:
                    logging.error(f"Error checking keyword '{kw}' against path '{process_path}': {e}")
            threat_list = config.get('threat', 'threat_list', fallback="").split(',')
            threat_list_cleaned = {ip.strip() for ip in threat_list if ip.strip()}
            if remote_ip != "N/A" and remote_ip in threat_list_cleaned:
                list_reasons.append("Known Threat IP")
                current_severity_score = max(current_severity_score, 3)
            if list_reasons:
                reasons.extend(list_reasons)
            if current_severity_score == 3:
                severity = "critical"
            elif current_severity_score == 2:
                severity = "high"
            elif current_severity_score == 1:
                severity = "medium"
            else:
                severity = "low"
            if reasons:
                reason_str = " | ".join(reasons)
                frequency = 1
                connection_location = process_path
                data = (
                    timestamp.isoformat(), local_ip, local_port, remote_ip, remote_port,
                    protocol, status, process_name, process_path, pid,
                    0, 0, 0,
                    reason_str, severity, analysis_type,
                    owner, frequency, connection_location
                )
                self.db.save_result(data)
                return data
            return None

        except Exception as e:
            logging.exception(f"Error analyzing connection {conn}: {e}")
            return None

    async def perform_heuristic_analysis(self, connections, timestamp):
        try:
            ip_conn_counts = defaultdict(int)
            for conn in connections:
                raddr = getattr(conn, 'raddr', None)
                if raddr:
                    ip_conn_counts[raddr.ip] += 1
            heuristic_results = []
            for ip, count in ip_conn_counts.items():
                if count > self.heuristic_conn_threshold:
                    data = (
                        timestamp.isoformat(), "N/A", 0, ip, 0,
                        "N/A", "N/A", "N/A", "N/A", 0,
                        0, 0, 0,
                        f"High connection count: {count} (threshold: {self.heuristic_conn_threshold})",
                        "high", "heuristic",
                        "N/A", 1, "N/A"
                    )
                    heuristic_results.append(data)
                    self.db.save_result(data)
            return heuristic_results
        except Exception as e:
            logging.exception(f"Error in heuristic analysis: {e}")
            return []

    def update_ui(self, new_results):
        if not new_results:
            return
        self.after(0, self.refresh_results_and_graphs, new_results)

    def refresh_results_and_graphs(self, new_results_data_tuples):
        if not self.winfo_exists():
            logging.warning("UI update requested, but window no longer exists.")
            return
        logging.debug(f"Updating UI with {len(new_results_data_tuples)} new results.")
        results = self.db.get_results(limit=500)
        today_str = date.today().isoformat()
        freq_map = defaultdict(int)
        for row in results:
            ts_date = row['timestamp'].split("T")[0]
            if ts_date == today_str and row['remote_address'] != "N/A":
                freq_map[row['remote_address']] += 1
        self.results_tree.delete(*self.results_tree.get_children())
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        for row in results:
            owner = row.get('owner', 'N/A')
            frequency = freq_map.get(row['remote_address'], 1)

            values = (
                row['timestamp'],
                row['severity'].upper(),
                row['reason'],
                row['analysis_type'],
                f"{row['local_address']}:{row['local_port']}",
                f"{row['remote_address']}:{row['remote_port']}" if row['remote_address'] != "N/A" else "N/A",
                row['protocol'],
                row['state'],
                row['process_name'],
                row['pid'],
                owner,
                frequency,
                row['process_path']
            )
            tag = row['severity'].capitalize()
            self.results_tree.insert('', 0, values=values, tags=(tag,))
            if row['analysis_type'] in ['heuristic', 'anomaly']:
                self.suspicious_tree.insert('', 0, values=values, tags=(tag,))
        self.limit_treeview(self.results_tree, 500)
        self.limit_treeview(self.suspicious_tree, 200)
        self.update_graphs()
        logging.debug("UI updated.")

    def limit_treeview(self, tree, max_items):
        children = tree.get_children('')
        if len(children) > max_items:
            items_to_delete = children[max_items:]
            tree.delete(*items_to_delete)
        self.results_tree.tag_configure('Critical', background='#ff6666')
        self.results_tree.tag_configure('High', background='#ff9999')

    def update_graphs(self):
        if not self.winfo_exists():
            return
        results = self.db.get_results(limit=200)
        if not results:
            self.ax_pie.clear()
            self.ax_line.clear()
            self.ax_bar.clear()
            self.canvas_pie.draw_idle()
            self.canvas_line.draw_idle()
            self.canvas_bar.draw_idle()
            return
        severity_counts = defaultdict(int)
        for row in results:
            severity_counts[row['severity']] += 1
        labels = [s.capitalize() for s in self.severity_colors.keys()]
        sizes = [severity_counts.get(s, 0) for s in self.severity_colors.keys()]
        colors = [self.severity_colors[s] for s in self.severity_colors.keys()]
        non_zero_data = [(label, size, color) for label, size, color in zip(labels, sizes, colors) if size > 0]

        if non_zero_data:
            labels, sizes, colors = zip(*non_zero_data)
        else:
            labels, sizes, colors = (['No Data'], [1], ['grey'])
        self.ax_pie.clear()
        wedges, texts, autotexts = self.ax_pie.pie(
            sizes, labels=labels, colors=colors,
            autopct='%1.1f%%', startangle=90, pctdistance=0.85,
            textprops={'color': config.get('ui', 'text_color')}
        )
        for autotext in autotexts:
            autotext.set_weight('bold')
            autotext.set_size(8)
            autotext.set_color('white')
        self.ax_pie.set_title("Severity Distribution", color=config.get('ui', 'text_color'), fontsize=10)
        self.ax_pie.axis('equal')
        self.canvas_pie.draw_idle()
        self.time_series_data.append((datetime.now(), len(results)))
        timestamps = [item[0] for item in self.time_series_data]
        counts = [item[1] for item in self.time_series_data]
        self.ax_line.clear()
        if timestamps:
            self.ax_line.plot(timestamps, counts, marker='o', linestyle='-', color=config.get('ui', 'accent_color'), markersize=3)
        self.ax_line.set_ylabel("Activity Count", color=config.get('ui', 'text_color'), fontsize=9)
        self.ax_line.tick_params(axis='x', rotation=30, labelsize=8)
        self.ax_line.tick_params(axis='y', labelsize=8)
        self.ax_line.xaxis.set_major_formatter(matplotlib.dates.DateFormatter('%H:%M:%S'))
        self.fig_line.autofmt_xdate()
        self.ax_line.set_title("Activity Over Time", color=config.get('ui', 'text_color'), fontsize=10)
        self.ax_line.grid(True, axis='y', linestyle=':', color='grey')
        self.canvas_line.draw_idle()
        critical_high_results = [r for r in results if r['severity'] in ['critical', 'high'] and r['remote_address'] != 'N/A']
        ip_counts = defaultdict(int)
        for row in critical_high_results:
            ip_counts[row['remote_address']] += 1
        top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        self.ax_bar.clear()
        if top_ips:
            ips, counts = zip(*top_ips)
            bars = self.ax_bar.barh(ips, counts, color=config.get('ui', 'danger_color'))
            self.ax_bar.set_xlabel("Occurrence Count", color=config.get('ui', 'text_color'), fontsize=9)
            self.ax_bar.tick_params(axis='x', labelsize=8)
            self.ax_bar.tick_params(axis='y', labelsize=8)
            self.ax_bar.invert_yaxis()
            for bar in bars:
                self.ax_bar.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                                 f'{bar.get_width()}', va='center', ha='left',
                                 color=config.get('ui', 'text_color'), size=8)
            self.ax_bar.set_title("Top High-Risk Source IPs", color=config.get('ui', 'text_color'), fontsize=10)
        self.canvas_bar.draw_idle()


    def get_current_selection(self):
        for tree in [self.results_tree, self.suspicious_tree]:
            selection = tree.selection()
            if selection:
                item = tree.item(selection[0])
                if item and item.get('values'):
                    return tree, item['values']
        return None, None

    def on_select(self, event):
        tree, data = self.get_current_selection()
        if data:
            self.stop_conn_btn.config(state=tk.NORMAL)
            remote_info = data[5]
            is_valid_remote = remote_info != "N/A" and ':' in remote_info
            self.block_btn.config(state=tk.NORMAL if is_valid_remote else tk.DISABLED)
            self.allow_btn.config(state=tk.NORMAL if is_valid_remote else tk.DISABLED)
            self.show_connection_info(data)
        else:
            self.stop_conn_btn.config(state=tk.DISABLED)
            self.block_btn.config(state=tk.DISABLED)
            self.allow_btn.config(state=tk.DISABLED)
            self.info_txt.delete(1.0, tk.END)

    def on_double_click(self, event):
        tree, data = self.get_current_selection()
        if data:
            remote_info = data[5]
            if remote_info != "N/A" and ':' in remote_info:
                ip_to_copy = remote_info.split(':')[0]
                try:
                    self.clipboard_clear()
                    self.clipboard_append(ip_to_copy)
                    messagebox.showinfo("Copied", f"Remote IP '{ip_to_copy}' copied to clipboard.", parent=self)
                    logging.info(f"Copied remote IP to clipboard: {ip_to_copy}")
                except tk.TclError:
                    messagebox.showwarning("Clipboard Error", "Unable to access clipboard.", parent=self)
            else:
                messagebox.showinfo("No IP", "No valid remote IP available for copying.", parent=self)

    def show_connection_info(self, data):
        self.info_txt.delete(1.0, tk.END)
        info = f"""--- Connection Details ---
Time: {data[0]}
Severity: {data[1]}
Reason: {data[2]}
Analysis Type: {data[3]}
Local Address: {data[4]}
Remote Address: {data[5]}
Protocol: {data[6]}

Status: {data[7]}
Process: {data[8]}
PID: {data[9]}
Owner: {data[10]}
Frequency: {data[11]}
Conn. Path: {data[12]}
"""
        self.info_txt.insert(tk.END, info)

    def stop_connection(self):
        tree, data = self.get_current_selection()
        if not data:
            messagebox.showwarning("No Selection", "Please select a connection first.", parent=self)
            return
        pid_str = str(data[9])
        remote_info = data[5]
        if not pid_str.isdigit():
            messagebox.showerror("Invalid PID", "Invalid process ID. Cannot stop connection.", parent=self)
            return
        pid = int(pid_str)
        confirm = messagebox.askyesno("Confirm Termination",
                                      f"Are you sure you want to terminate process PID {pid} ({data[8]})?\nThis could lead to system instability or data loss!",
                                      icon='warning', parent=self)
        if confirm:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                logging.info(f"Attempted to terminate process PID {pid} ({proc.name()}) associated with connection to {remote_info}.")
                messagebox.showinfo("Termination Requested", f"Termination request sent for process PID {pid}.", parent=self)
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", f"Process PID {pid} not found.", parent=self)
                logging.warning(f"Process PID {pid} not found for termination.")
            except psutil.AccessDenied:
                messagebox.showerror("Access Denied", f"You do not have permission to terminate process PID {pid}.\nPlease try running as administrator.", parent=self)
                logging.error(f"Access denied terminating process PID {pid}.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while attempting to terminate process PID {pid}: {e}", parent=self)
                logging.exception(f"Error terminating process PID {pid}")

    def block_connection(self):
        tree, data = self.get_current_selection()
        if not data:
            return
        remote_info = data[5]
        if remote_info == "N/A" or ':' not in remote_info:
            messagebox.showwarning("No IP", "No valid remote IP available for blocking.", parent=self)

            return
        ip_to_block = remote_info.split(':')[0]
        confirm = messagebox.askyesno("Confirm Block", f"Do you want to add '{ip_to_block}' to the blacklist?", parent=self)
        if confirm:
            self.db.add_to_list('blacklist', ip_to_block)
            messagebox.showinfo("Blocked", f"'{ip_to_block}' has been added to the blacklist.", parent=self)

    def allow_connection(self):
        tree, data = self.get_current_selection()
        if not data:
            return
        remote_info = data[5]
        if remote_info == "N/A" or ':' not in remote_info:
            messagebox.showwarning("No IP", "No valid remote IP available for allowing.", parent=self)
            return
        ip_to_allow = remote_info.split(':')[0]
        confirm = messagebox.askyesno("Confirm Allow", f"Do you want to add '{ip_to_allow}' to the whitelist?", parent=self)
        if confirm:
            self.db.add_to_list('whitelist', ip_to_allow)
            messagebox.showinfo("Allowed", f"'{ip_to_allow}' has been added to the whitelist.", parent=self)

    def load_initial_data(self):
        logging.debug("Loading initial list data...")
        susp_ports = config.get('threat', 'suspicious_ports', fallback='').split(',')
        susp_ports_list = [p.strip() for p in susp_ports if p.strip().isdigit()]
        if not self.db.get_list('suspicious_ports'):
            for port in susp_ports_list:
                self.db.add_to_list('suspicious_ports', port)
            logging.info(f"Added default suspicious ports: {susp_ports_list}")
        common_ports = ['80', '443', '22', '21', '25', '110', '143', '3389', '5900']
        if not self.db.get_list('monitored_ports'):
            for port in common_ports:
                self.db.add_to_list('monitored_ports', port)
            logging.info(f"Added default monitored ports: {common_ports}")

    def import_sigma_yaml(self):
        # فتح نافذة اختيار متعددة للملفات من نوع YAML
        file_paths = filedialog.askopenfilenames(title="اختر ملف/ملفات sigma YAML", filetypes=[("YAML Files", "*.yaml *.yml")], parent=self)
        if not file_paths:
            return
        imported_count = 0
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule_content = f.read()
                rule_dict = yaml.safe_load(rule_content)
                filename = os.path.basename(file_path)
                if self.db.save_sigma_rule(filename, rule_dict):

                    imported_count += 1
            except Exception as e:
                logging.exception(f"Error importing sigma rule from {file_path}: {e}")
        messagebox.showinfo("Import Complete", f"تم استيراد {imported_count} قاعدة Sigma بنجاح.", parent=self)
        logging.info(f"Imported {imported_count} sigma rules.")

    def export_report(self, all_results=True):
        try:
            if all_results:
                results = self.db.get_results(limit=10000)
                file_prefix = "all_activities"
                title = "Export All Activities"
            else:
                results = [r for r in self.db.get_results(limit=10000) if r['analysis_type'] in ['heuristic', 'anomaly']]
                file_prefix = "suspicious_activities"
                title = "Export Suspicious Activities Only"
            if not results:
                messagebox.showinfo("No Data", "No data available for export.", parent=self)
                return
            default_filename = f"{file_prefix}_report_{datetime.now():%Y%m%d_%H%M%S}.csv"
            file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                     filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                                                     title=title, initialfile=default_filename, parent=self)
            if not file_path:
                return
            headers = results[0].keys()
            with open(file_path, mode='w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                writer.writerows(results)
            messagebox.showinfo("Export Complete", f"Report successfully exported to:\n{file_path}", parent=self)
            logging.info(f"Report exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Report export failed: {e}", parent=self)
            logging.exception("Error exporting report")

    def export_html_report(self):
        mode = messagebox.askquestion("Export HTML", "Export only suspicious activities? (Click 'No' for exporting all)", icon='question', parent=self)
        try:
            if mode == 'yes':
                results = [r for r in self.db.get_results(limit=10000) if r['analysis_type'] in ['heuristic', 'anomaly']]
                file_prefix = "html_suspicious"
                title = "Export Suspicious Activities (HTML)"
            else:
                results = self.db.get_results(limit=10000)
                file_prefix = "html_all"
                title = "Export All Activities (HTML)"
            if not results:

                messagebox.showinfo("No Data", "No data available for export.", parent=self)
                return
            default_filename = f"{file_prefix}_report_{datetime.now():%Y%m%d_%H%M%S}.html"
            file_path = filedialog.asksaveasfilename(defaultextension=".html",
                                                     filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                                                     title=title, initialfile=default_filename, parent=self)
            if not file_path:
                return
            html_content = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Network Monitor Report</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #cccccc; padding: 8px; text-align: left; }
    th { background: linear-gradient(to right, #2c3e50, #34495e); color: #ecf0f1; }
    tr:nth-child(even) { background-color: #e8e8e8; }
    .suspicious { background-color: #dcd0f1; }
  </style>
</head>
<body>
  <h2>Network Monitor Report</h2>
  <table>
    <tr>
      <th>Time</th>
      <th>Severity</th>
      <th>Reason</th>
      <th>Analysis</th>
      <th>Local</th>
      <th>Remote</th>
      <th>Protocol</th>
      <th>Status</th>
      <th>Process</th>
      <th>PID</th>
      <th>Owner</th>
      <th>Frequency</th>
      <th>Conn. Path</th>
    </tr>
"""
            for r in results:
                row_class = ""
                if r['severity'] in ['critical', 'high']:
                    row_class = 'suspicious'
                html_content += f"""    <tr class="{row_class}">
      <td>{r['timestamp']}</td>
      <td>{r['severity'].upper()}</td>
      <td>{r['reason']}</td>
      <td>{r['analysis_type']}</td>
      <td>{r['local_address']}:{r['local_port']}</td>

      <td>{r['remote_address']}:{r['remote_port'] if r['remote_address'] != 'N/A' else ''}</td>
      <td>{r['protocol']}</td>
      <td>{r['state']}</td>
      <td>{r['process_name']}</td>
      <td>{r['pid']}</td>
      <td>{r.get('owner', 'N/A')}</td>
      <td>{r.get('frequency', 1)}</td>
      <td>{r['process_path']}</td>
    </tr>
"""
            html_content += """  </table>
</body>
</html>
"""
            with open(file_path, "w", encoding="utf-8") as htmlfile:
                htmlfile.write(html_content)
            messagebox.showinfo("Export Complete", f"HTML Report successfully exported to:\n{file_path}", parent=self)
            logging.info(f"HTML report exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"HTML export failed: {e}", parent=self)
            logging.exception("Error exporting HTML report")

    def manual_refresh(self):
        self.refresh_results_and_graphs([])

    def on_close(self):
        logging.info("Shutdown sequence initiated.")
        if self.scan_active:
            self.stop_scan()
            time.sleep(self.scan_interval / 2 + 0.1)
        if self.loop and self.loop.is_running():
            logging.debug("Requesting asyncio loop stop...")
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.executor.shutdown(wait=True)
        self.db.close()
        logging.info("--- Network Monitor Pro Exiting ---")
        self.destroy()

    def start_scan(self):
        if not self.scan_active:
            self.scan_active = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.results_tree.delete(*self.results_tree.get_children())
            self.suspicious_tree.delete(*self.suspicious_tree.get_children())
            self.time_series_data.clear()
            self.connection_history.clear()
            logging.info("Scan started.")
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.run_scan_async(), self.loop)

            else:
                logging.error("Asyncio loop is not running. Cannot start scan.")

    def stop_scan(self):
        if self.scan_active:
            self.scan_active = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.on_select(None)
            logging.info("Scan stopped.")

# ---------------------------
# Main Application Entry Point
# ---------------------------
if __name__ == "__main__":
    try:
        app = NetworkMonitorApp()
        app.mainloop()
    except Exception as e:
        logging.critical("Unhandled exception in main application thread!", exc_info=True)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred:\n{e}\n\nPlease check the log file: {log_file}")
            root.destroy()
        except Exception as me:
            print(f"CRITICAL ERROR: {e}")
            print(f"Could not show error messagebox: {me}")

















































