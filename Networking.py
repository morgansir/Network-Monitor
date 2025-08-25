import sys, os, json, time, socket, platform, threading
from collections import Counter, defaultdict
from datetime import datetime
from io import BytesIO

import psutil
import folium  # تأكد من تثبيت المكتبة: pip install folium

from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize, QUrl
from PyQt5.QtGui import QFont, QIcon, QCursor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QGroupBox, QLabel, QLineEdit, QComboBox, QToolButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QStatusBar, QProgressBar,
    QMessageBox, QAction, QCheckBox, QFileDialog, QListWidget, QListWidgetItem,
    QFormLayout, QDialog, QFrame, QScrollArea, QSizePolicy, QMenuBar, QGridLayout, QInputDialog
)

# Optional deps
try:
    import pefile
except Exception:
    pefile = None

try:
    import requests
except Exception:
    requests = None

# WebEngine for map
try:
    from PyQt5.QtWebEngineWidgets import QWebEngineView
    WEB_OK = True
except Exception:
    WEB_OK = False

# Matplotlib chart
try:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MPL_OK = True
except Exception:
    MPL_OK = False

# XLSX export
try:
    import openpyxl
    from openpyxl import Workbook
    XLSX_OK = True
except Exception:
    XLSX_OK = False

# Optional per-connection bytes (Windows)
try:
    import pydivert
except Exception:
    pydivert = None

APP_NAME = "Network Activity Monitor PRO v6"
APP_ID = "netmon_pro_v6"
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), f".{APP_ID}_settings.json")

# ---------------- Language ----------------
LANG = {
    "ar": {
        "title": "مراقبة النشاط الشبكي - نسخة برو v6",
        "filters_box": "الإعدادات والفلاتر",
        "chart_box": "الرسم والإحصائيات + الخريطة المصغرة",
        "results_box": "نتائج الفحص",
        "public_ip": "IP العام: {}",
        "quick_search": "بحث سريع…",
        "start": "◀️ تشغيل",
        "stop": "⏸️ إيقاف",
        "interval": "الفاصل (ث)",
        "only_susp": "عرض المشبوه فقط",
        "protocol": "البروتوكول",
        "protocol_any": "الكل",
        "activity_type": "نوع النشاط",
        "activity_any": "الكل",
        "keywords": "كلمات مفتاحية (اسم/مسار العملية)",
        "keywords_ph": "chrome,powershell,bot",
        "bytes_from": "مرسل (MB) ≥",
        "bytes_to": "مستلم (MB) ≥",
        "enable_divert": "حجم لكل اتصال (pydivert/ويندوز)",
        "perproc_note": "افتراضي: حجم لكل عملية (psutil)",
        "sus_ips": "IP مشبوه",
        "sus_ports": "منفذ مشبوه",
        "sus_words": "كلمات مشبوهة",
        "allow_ips": "Whitelist IPs (استثناء)",
        "allow_ports": "Whitelist Ports (استثناء)",
        "allow_words": "Whitelist Words (استثناء)",
        "add": "+", "remove": "−",
        "export": "تصدير…",
        "import": "استيراد…",
        "save_rules": "حفظ القواعد…",
        "load_rules": "تحميل القواعد…",
        "table": {
            "type": "نوع النشاط",
            "proto": "البروتوكول",
            "laddr": "العنوان المحلي",
            "lport": "المنفذ المحلي",
            "raddr": "العنوان البعيد",
            "rport": "المنفذ البعيد",
            "state": "الحالة",
            "exe": "مسار العملية",
            "bytes": "حجم البيانات (مرسل/مستلم)",
            "sig": "توقيع العملية",
            "reason": "سبب الاشتباه"
        },
        "stats_label": "الإحصائيات: الكل={} | TCP={} | UDP={} | LISTEN={} | ESTABLISHED={}",
        "map_hint": "الخريطة المصغرة (folium + OpenStreetMap).",
        "map_disabled": "الخريطة غير متاحة (منصة folium أو PyQtWebEngine غير مثبتة).",
        "details_title": "تفاصيل السجل",
        "menu_file": "ملف",
        "menu_rules": "قواعد",
        "menu_view": "عرض",
        "menu_lang": "اللغة",
        "menu_theme": "الثيم",
        "lang_ar": "العربية",
        "lang_en": "English",
        "theme_aurora": "Aurora (افتراضي)",
        "theme_cyber": "Cyberpunk",
        "theme_glass": "Glassy",
        "theme_midnight": "Midnight",
        "theme_royal": "Royal",
        "theme_carbon": "Carbon",
        "theme_neon": "Neon",
        "ok": "موافق"
    },
    "en": {
        "title": "Network Activity Monitor - PRO v6",
        "filters_box": "Settings & Filters",
        "chart_box": "Chart, Stats & Mini Map",
        "results_box": "Scan Results",
        "public_ip": "Public IP: {}",
        "quick_search": "Quick search…",
        "start": "◀️ Start",
        "stop": "⏸️ Stop",
        "interval": "Interval (s)",
        "only_susp": "Show suspicious only",
        "protocol": "Protocol",
        "protocol_any": "Any",
        "activity_type": "Activity Type",
        "activity_any": "Any",
        "keywords": "Keywords (proc name/path)",
        "keywords_ph": "chrome,powershell,bot",
        "bytes_from": "Sent (MB) ≥",
        "bytes_to": "Recv (MB) ≥",
        "enable_divert": "Per-connection bytes (pydivert/Windows)",
        "perproc_note": "Default: Per-process bytes (psutil)",
        "sus_ips": "Suspicious IP",
        "sus_ports": "Suspicious Port",
        "sus_words": "Suspicious Words",
        "allow_ips": "Whitelist IPs (Allow)",
        "allow_ports": "Whitelist Ports (Allow)",
        "allow_words": "Whitelist Words (Allow)",
        "add": "+", "remove": "−",
        "export": "Export…",
        "import": "Import…",
        "save_rules": "Save Rules…",
        "load_rules": "Load Rules…",
        "table": {
            "type": "Activity Type",
            "proto": "Protocol",
            "laddr": "Local Address",
            "lport": "Local Port",
            "raddr": "Remote Address",
            "rport": "Remote Port",
            "state": "State",
            "exe": "Process Path",
            "bytes": "Bytes (Sent/Recv)",
            "sig": "Signature",
            "reason": "Suspicion Reason"
        },
        "stats_label": "Stats: ALL={} | TCP={} | UDP={} | LISTEN={} | ESTABLISHED={}",
        "map_hint": "Mini map (folium + OpenStreetMap).",
        "map_disabled": "Map disabled (folium or PyQtWebEngine missing).",
        "details_title": "Record Details",
        "menu_file": "File",
        "menu_rules": "Rules",
        "menu_view": "View",
        "menu_lang": "Language",
        "menu_theme": "Theme",
        "lang_ar": "العربية",
        "lang_en": "English",
        "theme_aurora": "Aurora (Default)",
        "theme_cyber": "Cyberpunk",
        "theme_glass": "Glassy",
        "theme_midnight": "Midnight",
        "theme_royal": "Royal",
        "theme_carbon": "Carbon",
        "theme_neon": "Neon",
        "ok": "OK"
    }
}

def fmt_bytes(n):
    try:
        n = float(n)
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

# ---------------- Workers ----------------
class DivertSniffer(QThread):
    bytes_update = pyqtSignal(dict)  # key: (proto,lip,lport,rip,rport) -> [sent, recv]
    def __init__(self):
        super().__init__()
        self._stop = False
    def stop(self):
        self._stop = True
    def run(self):
        if pydivert is None or platform.system().lower() != "windows":
            return
        try:
            with pydivert.WinDivert("tcp or udp", layer=pydivert.Layer.NETWORK) as w:
                local_ips = set()
                for _, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        try:
                            if a.family in (socket.AF_INET, socket.AF_INET6):
                                local_ips.add(a.address.split('%')[0])
                        except Exception:
                            pass
                counters = defaultdict(lambda: [0, 0])
                last_emit = time.time()
                for pkt in w:
                    if self._stop:
                        break
                    proto = "TCP" if getattr(pkt, "tcp", None) else "UDP" if getattr(pkt, "udp", None) else "OTHER"
                    if proto == "OTHER":
                        continue
                    try:
                        saddr, daddr = str(pkt.src_addr), str(pkt.dst_addr)
                        sport, dport = int(pkt.src_port), int(pkt.dst_port)
                        length = getattr(pkt, "payload_len", None) or len(pkt.raw)
                    except Exception:
                        continue
                    if saddr in local_ips:
                        counters[(proto, saddr, sport, daddr, dport)][0] += length
                    elif daddr in local_ips:
                        counters[(proto, daddr, dport, saddr, sport)][1] += length
                    if time.time() - last_emit >= 1.0:
                        self.bytes_update.emit(dict(counters))
                        last_emit = time.time()
        except Exception:
            return

class ScanWorker(QThread):
    scanned = pyqtSignal(list, dict)  # rows, stats
    def __init__(self):
        super().__init__()
        self._stop = False
        self.filters = {}
        self.rules = {"ips": set(), "ports": set(), "keywords": set(),
                      "allow_ips": set(), "allow_ports": set(), "allow_words": set()}
        self.want_divert = False
        self.divert_bytes = {}
    def configure(self, filters, rules, want_divert, divert_bytes):
        self.filters = filters; self.rules = rules
        self.want_divert = want_divert; self.divert_bytes = divert_bytes or {}
    def stop(self):
        self._stop = True
    def run(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []
        rows = []; counts = Counter()
        proto_filter = self.filters.get("proto", None)
        type_filter = self.filters.get("atype", None)
        kw = self.filters.get("keywords", set())
        min_sent = self.filters.get("min_sent", 0)
        min_recv = self.filters.get("min_recv", 0)
        show_only_susp = self.filters.get("only_susp", False)
        bad_ips = self.rules.get("ips", set())
        bad_ports = self.rules.get("ports", set())
        bad_kw = self.rules.get("keywords", set())
        allow_ips = self.rules.get("allow_ips", set())
        allow_ports = self.rules.get("allow_ports", set())
        allow_words = self.rules.get("allow_words", set())

        for c in conns:
            if self._stop:
                break
            try:
                laddr = c.laddr.ip if c.laddr else ""
                lport = c.laddr.port if c.laddr else 0
                if c.raddr:
                    raddr, rport = c.raddr.ip, c.raddr.port
                else:
                    raddr, rport = "", 0
                proto = "TCP" if c.type == socket.SOCK_STREAM else ("UDP" if c.type == socket.SOCK_DGRAM else "OTHER")
                if proto_filter and proto_filter not in ("Any", "الكل") and proto != proto_filter:
                    continue
                state = str(c.status).upper() if proto == "TCP" else ("CONNECTED" if raddr else "LISTEN")
                if type_filter and type_filter not in ("Any", "الكل") and state != type_filter:
                    continue
                exe, sig = "", "Unknown"
                sent_p, recv_p = 0, 0
                if c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        exe = p.exe() or p.name() or ""
                        try:
                            io = p.io_counters()
                            sent_p, recv_p = getattr(io, "write_bytes", 0), getattr(io, "read_bytes", 0)
                        except Exception:
                            pass
                    except Exception:
                        pass
                if self.want_divert:
                    key = (proto, laddr, int(lport or 0), raddr, int(rport or 0))
                    vs = self.divert_bytes.get(key, [0, 0])
                    sent, recv = (vs if isinstance(vs, (list, tuple)) else (0, 0))
                    bytes_txt = f"{fmt_bytes(sent)}/{fmt_bytes(recv)}" if (sent or recv) else "N/A"
                    cmp_sent, cmp_recv = sent, recv
                else:
                    bytes_txt = f"{fmt_bytes(sent_p)}/{fmt_bytes(recv_p)}" if (sent_p or recv_p) else "N/A (per-process)"
                    cmp_sent, cmp_recv = sent_p, recv_p

                hay = (exe or "").lower()
                all_kw = set(kw) | set(bad_kw)
                if all_kw and not any(k in hay for k in all_kw):
                    continue

                # Signature (optional)
                if exe and pefile is not None and os.path.isfile(exe):
                    try:
                        pe = pefile.PE(exe, fast_load=True)
                        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                        sig = "Signed" if getattr(sec, "VirtualAddress", 0) != 0 else "Unsigned"
                    except Exception:
                        sig = "N/A"

                # Allowlist checks (override any suspicion)
                allow_hit = (laddr in allow_ips or raddr in allow_ips or
                             lport in allow_ports or rport in allow_ports or
                             any(w in hay for w in allow_words))

                reasons = []
                if not allow_hit:
                    if raddr in bad_ips or laddr in bad_ips:
                        reasons.append("Suspicious IP")
                    if (rport and rport in bad_ports) or (lport and lport in bad_ports):
                        reasons.append("Suspicious Port")
                    if sig == "Unsigned":
                        reasons.append("Unsigned Binary")
                    if (cmp_sent >= min_sent) or (cmp_recv >= min_recv):
                        reasons.append("High Data Volume")
                suspicious = (not allow_hit) and bool(reasons)

                if show_only_susp and not suspicious:
                    continue

                rows.append({
                    "type": state, "proto": proto,
                    "laddr": laddr, "lport": lport,
                    "raddr": raddr, "rport": rport,
                    "state": state, "exe": exe,
                    "bytes": bytes_txt, "sig": sig,
                    "reason": ", ".join(reasons) if reasons else ("Allowed" if allow_hit else "")
                })
                counts["ALL"] += 1; counts[proto] += 1; counts[state] += 1
            except Exception:
                continue

        for k in ("TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV"):
            counts[k] = counts.get(k, 0)
        counts["OTHER"] = len([r for r in rows if r["proto"] not in ("TCP", "UDP")])
        self.scanned.emit(rows, dict(counts))

# ---------------- UI Pieces ----------------
class DetailsDialog(QDialog):
    def __init__(self, lang_map, record, parent=None):
        super().__init__(parent)
        self.setWindowTitle(lang_map["details_title"])
        self.resize(720, 460)
        layout = QVBoxLayout(self)
        grid = QFormLayout()
        def lab(text, val):
            l1 = QLabel(text)
            l2 = QLabel(val or "-")
            l2.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addRow(l1, l2)
        t = lang_map["table"]
        lab(t["type"], record.get("type", "-"))
        lab(t["proto"], record.get("proto", "-"))
        lab(t["laddr"], f'{record.get("laddr", "-")}:{record.get("lport", "-")}')
        lab(t["raddr"], f'{record.get("raddr", "-")}:{record.get("rport", "-")}')
        lab(t["state"], record.get("state", "-"))
        lab(t["exe"], record.get("exe", "-"))
        lab(t["bytes"], record.get("bytes", "-"))
        lab(t["sig"], record.get("sig", "-"))
        lab(t["reason"], record.get("reason", "-"))
        layout.addLayout(grid)
        btn = QToolButton()
        btn.setText(lang_map["ok"])
        btn.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(btn)
        layout.addLayout(row)

class StatChip(QWidget):
    clicked = pyqtSignal(str)
    def __init__(self, label, key, color_css):
        super().__init__()
        self.value_key = key
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(2)
        self.setObjectName("statChip")
        # CSS مخصص لكل كرت مع لون الخلفية الخاص
        self.setStyleSheet(f"""
        QWidget#statChip {{
            border-radius: 12px; padding: 6px;
            background: {color_css};
            color: #fff; border: 1px solid rgba(255,255,255,0.25);
        }}
        QWidget#statChip:hover {{
            border: 2px solid #fff;
        }}
        """)
        self.title = QLabel(label)
        self.title.setObjectName("chipTitle")
        self.val = QLabel("0")
        self.val.setObjectName("chipValue")
        self.title.setStyleSheet("font-weight:700;font-size:10px; letter-spacing:.3px;")
        self.val.setStyleSheet("font-size:15px;font-weight:800;")
        lay.addWidget(self.title, 0, Qt.AlignCenter)
        lay.addWidget(self.val, 0, Qt.AlignCenter)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setFixedSize(110, 58)
    def mousePressEvent(self, e):
        self.clicked.emit(self.value_key)
        super().mousePressEvent(e)
    def setText(self, t):
        self.val.setText(t)
    def set_value(self, v):
        self.val.setText(str(v))
    def set_title(self, t):
        self.title.setText(t)

class MplBarCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5.6, height=2.0, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)
        self.setParent(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(200)
    def plot_counts(self, labels, counts):
        ax = self.axes
        ax.clear()
        xs = list(range(len(labels)))
        palette = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6",
                   "#06b6d4", "#84cc16", "#a855f7", "#f97316", "#22c55e"]
        colors = [palette[i % len(palette)] for i in range(len(labels))]
        bars = ax.bar(xs, counts, color=colors, edgecolor="white")
        ax.set_xticks(xs)
        ax.set_xticklabels(labels, rotation=0, fontsize=9)
        ax.set_ylabel("Count", fontsize=9)
        for rect in bars:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width()/2., height+0.05, f'{int(height)}',
                    ha='center', va='bottom', fontsize=8)
        ax.margins(x=0.02)
        ax.grid(axis='y', linestyle=':', alpha=0.5)
        self.draw()

# ---------------- Main Window ----------------
class NetworkMonitorPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.lang = "en"    # English default
        self.theme = "aurora"
        self.worker = ScanWorker()
        self.worker.scanned.connect(self.on_scanned)
        self.scan_inflight = False  # freeze-guard

        self.divert = None
        self.divert_bytes = {}
        self.rules = {"ips": set(), "ports": set(), "keywords": set(),
                      "allow_ips": set(), "allow_ports": set(), "allow_words": set()}
        self.map_cache = {}

        self._init_ui()
        self.load_settings()  # حمّل القوائم من الإعدادات إن وجدت
        self._apply_theme()
        self._translate()
        self.fetch_public_ip()
        self.statusBar().showMessage("Ready.")

        self.refresh_timer = QTimer(self)
        # ضبط الفاصل الزمني ليكون 120 ثانية (2 دقيقة)
        self.refresh_timer.timeout.connect(self.scan_once)

    # ---------- Build UI ----------
    def _init_ui(self):
        self.setWindowTitle(LANG[self.lang]["title"])
        self.resize(1520, 920)
        base_font = QFont()
        base_font.setPointSize(base_font.pointSize() + 1)
        self.setFont(base_font)

        # Menus
        self.menubar = QMenuBar()
        self.setMenuBar(self.menubar)
        self._build_menus(self.menubar)

        # Status bar / progress
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress, 1)

        # Central Layout
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 8, 10, 8)
        root.setSpacing(8)

        # Header controls
        header = QHBoxLayout()
        self.public_ip_label = QLabel(LANG[self.lang]["public_ip"].format("--"))
        self.public_ip_label.setFont(QFont("Consolas", 11, QFont.Bold))
        header.addWidget(self.public_ip_label)

        header.addStretch(1)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(LANG[self.lang]["quick_search"])
        self.search_input.textChanged.connect(self.apply_client_filter)
        self.search_input.setFixedWidth(360)
        header.addWidget(self.search_input)

        header.addSpacing(10)
        self.start_btn = QToolButton()
        self.start_btn.setText(LANG[self.lang]["start"])
        self.stop_btn  = QToolButton()
        self.stop_btn.setText(LANG[self.lang]["stop"])
        self.start_btn.clicked.connect(self.on_start_clicked)
        self.stop_btn.clicked.connect(self.on_stop_clicked)
        header.addWidget(self.start_btn)
        header.addWidget(self.stop_btn)

        header.addSpacing(6)
        header.addWidget(QLabel(LANG[self.lang]["interval"]))
        self.interval_spin = QSpinBox()
        # تغيير المدى الافتراضي لفترة التحديث بحيث تكون أقل قيمة 120 ثانية
        self.interval_spin.setRange(120, 600)
        self.interval_spin.setValue(120)
        self.interval_spin.valueChanged.connect(self.on_interval_change)
        header.addWidget(self.interval_spin)
        root.addLayout(header)

        # Add colored statistic cards instead of stats_label
        self.cards = {}
        cards_widget = QWidget()
        cards_layout = QHBoxLayout(cards_widget)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        stat_keys = ["ALL", "TCP", "UDP", "LISTEN", "ESTABLISHED"]
        palette = {
            "ALL": "#3b82f6",
            "TCP": "#10b981",
            "UDP": "#f59e0b",
            "LISTEN": "#ef4444",
            "ESTABLISHED": "#8b5cf6"
        }
        for key in stat_keys:
            card = StatChip(label=key, key=key, color_css=palette.get(key, "#3b82f6"))
            card.clicked.connect(self.on_chip_clicked)
            self.cards[key] = card
            cards_layout.addWidget(card)
        root.addWidget(cards_widget)

        # Vertical splitter (Top vs Bottom)
        self.split_main = QSplitter(Qt.Vertical)
        root.addWidget(self.split_main, 1)
        self.split_main.setChildrenCollapsible(False)
        self.split_main.setHandleWidth(10)

        # -------- Top area: horizontal splitter (left filters | right chart+cards+map)
        self.split_top = QSplitter(Qt.Horizontal)
        self.split_main.addWidget(self.split_top)
        self.split_top.setChildrenCollapsible(False)
        self.split_top.setHandleWidth(8)

        # Left: Filters in scroll area
        left_box = QGroupBox(LANG[self.lang]["filters_box"])
        left_v = QVBoxLayout(left_box)
        left_v.setSpacing(8)

        row1 = QHBoxLayout()
        self.proto_combo = QComboBox()
        self.proto_combo.addItems([LANG[self.lang]["protocol_any"], "TCP", "UDP"])
        self.proto_combo.currentIndexChanged.connect(self.scan_once)
        self.atype_combo = QComboBox()
        self.atype_combo.addItems([LANG[self.lang]["activity_any"], "LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV"])
        self.atype_combo.currentIndexChanged.connect(self.scan_once)
        self.only_susp_cb = QCheckBox(LANG[self.lang]["only_susp"])
        self.only_susp_cb.stateChanged.connect(self.scan_once)
        row1.addWidget(QLabel(LANG[self.lang]["protocol"]))
        row1.addWidget(self.proto_combo)
        row1.addSpacing(10)
        row1.addWidget(QLabel(LANG[self.lang]["activity_type"]))
        row1.addWidget(self.atype_combo)
        row1.addStretch(1)
        row1.addWidget(self.only_susp_cb)
        left_v.addLayout(row1)

        # Keywords filter
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText(LANG[self.lang]["keywords_ph"])
        self.kw_input.textChanged.connect(self.scan_once)
        left_v.addWidget(QLabel(LANG[self.lang]["keywords"]))
        left_v.addWidget(self.kw_input)

        # Bytes thresholds
        row2 = QHBoxLayout()
        self.min_sent_mb = QSpinBox()
        self.min_sent_mb.setRange(0, 100000)
        self.min_sent_mb.setValue(10)
        self.min_sent_mb.valueChanged.connect(self.scan_once)
        self.min_recv_mb = QSpinBox()
        self.min_recv_mb.setRange(0, 100000)
        self.min_recv_mb.setValue(1)
        self.min_recv_mb.valueChanged.connect(self.scan_once)
        row2.addWidget(QLabel(LANG[self.lang]["bytes_from"]))
        row2.addWidget(self.min_sent_mb)
        row2.addSpacing(10)
        row2.addWidget(QLabel(LANG[self.lang]["bytes_to"]))
        row2.addWidget(self.min_recv_mb)
        left_v.addLayout(row2)

        # Divert option
        self.divert_cb = QCheckBox(LANG[self.lang]["enable_divert"])
        note = QLabel("• " + LANG[self.lang]["perproc_note"])
        left_v.addWidget(self.divert_cb)
        left_v.addWidget(note)

        # Suspicious Rules + −
        left_v.addWidget(QLabel(LANG[self.lang]["sus_ips"]))
        self.ip_list = QListWidget()
        self.ip_list.setFixedHeight(90)
        left_v.addWidget(self.ip_list)
        left_v.addLayout(self.plus_minus_bar(self.ip_list, "ip"))
        self.ip_list.itemDoubleClicked.connect(lambda it: self.edit_list_item(self.ip_list, it, "ip"))

        left_v.addWidget(QLabel(LANG[self.lang]["sus_ports"]))
        self.port_list = QListWidget()
        self.port_list.setFixedHeight(90)
        left_v.addWidget(self.port_list)
        left_v.addLayout(self.plus_minus_bar(self.port_list, "port"))
        self.port_list.itemDoubleClicked.connect(lambda it: self.edit_list_item(self.port_list, it, "port"))

        left_v.addWidget(QLabel(LANG[self.lang]["sus_words"]))
        self.kw_list = QListWidget()
        self.kw_list.setFixedHeight(90)
        left_v.addWidget(self.kw_list)
        left_v.addLayout(self.plus_minus_bar(self.kw_list, "kw"))
        self.kw_list.itemDoubleClicked.connect(lambda it: self.edit_list_item(self.kw_list, it, "kw"))

        # Allowlist (Whitelist)
        left_v.addWidget(QLabel(LANG[self.lang]["allow_ips"]))
        self.allow_ip_list = QListWidget()
        self.allow_ip_list.setFixedHeight(80)
        left_v.addWidget(self.allow_ip_list)
        left_v.addLayout(self.plus_minus_bar(self.allow_ip_list, "allow_ip"))

        left_v.addWidget(QLabel(LANG[self.lang]["allow_ports"]))
        self.allow_port_list = QListWidget()
        self.allow_port_list.setFixedHeight(80)
        left_v.addWidget(self.allow_port_list)
        left_v.addLayout(self.plus_minus_bar(self.allow_port_list, "allow_port"))

        left_v.addWidget(QLabel(LANG[self.lang]["allow_words"]))
        self.allow_kw_list = QListWidget()
        self.allow_kw_list.setFixedHeight(80)
        left_v.addWidget(self.allow_kw_list)
        left_v.addLayout(self.plus_minus_bar(self.allow_kw_list, "allow_kw"))

        left_v.addStretch(1)
        left_wrap = QScrollArea()
        left_wrap.setWidgetResizable(True)
        left_wrap.setWidget(left_box)
        self.split_top.addWidget(left_wrap)

        # Right: Chart + Mini map
        right_box = QGroupBox(LANG[self.lang]["chart_box"])
        rc = QVBoxLayout(right_box)
        rc.setSpacing(8)
        rc.setContentsMargins(10, 14, 10, 10)

        if MPL_OK:
            self.chart = MplBarCanvas(parent=right_box, width=5.6, height=2.0, dpi=100)
            rc.addWidget(self.chart)
        else:
            self.chart = None
            msg = QLabel("matplotlib not installed -- chart disabled.")
            msg.setFixedHeight(40)
            msg.setAlignment(Qt.AlignCenter)
            rc.addWidget(msg)

        # Row: Mini-map (updated via folium) beside the chart area with improved positioning
        map_col = QVBoxLayout()
        map_col.setSpacing(6)
        map_info = QLabel(LANG[self.lang]["map_hint"])
        map_info.setFixedHeight(18)
        map_col.addWidget(map_info)
        map_frame = QFrame()
        map_v = QVBoxLayout(map_frame)
        map_v.setContentsMargins(0, 0, 0, 0)
        map_v.setSpacing(0)
        if WEB_OK:
            self.map_view = QWebEngineView()
            # ضبط أبعاد الخريطة مع تحسين التمركز (offset بسيط لليمين)
            self.map_view.setFixedSize(850, 250)
            self.map_view.setHtml("<html><body><center>{}</center></body></html>".format(LANG[self.lang]["map_disabled"]))
            map_v.addWidget(self.map_view)
        else:
            self.map_view = None
            map_v.addWidget(QLabel(LANG[self.lang]["map_disabled"]))
        map_col.addWidget(map_frame)
        rc.addLayout(map_col)

        right_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        right_box.setMaximumHeight(550)
        self.split_top.addWidget(right_box)

        self.split_top.setStretchFactor(0, 1)
        self.split_top.setStretchFactor(1, 1)

        # -------- Bottom: Results table
        bottom_box = QGroupBox(LANG[self.lang]["results_box"])
        self.split_main.addWidget(bottom_box)
        bl = QVBoxLayout(bottom_box)
        bl.setSpacing(6)
        # Disable updates during heavy table refresh for performance improvement
        self.table = QTableWidget(0, 11)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.itemDoubleClicked.connect(self.on_row_double_clicked)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setMinimumHeight(28 * 9 + 48)
        bl.addWidget(self.table)
        self.update_headers()

        self.split_main.setSizes([560, 600])
        self.split_top.setSizes([760, 760])

    # ---------- Menus / Theme / Language ----------
    def _build_menus(self, menubar):
        menubar.clear()
        m_file = menubar.addMenu(LANG[self.lang]["menu_file"])
        act_export = QAction(LANG[self.lang]["export"], self)
        act_export.triggered.connect(self.export_results)
        act_import = QAction(LANG[self.lang]["import"], self)
        act_import.triggered.connect(self.import_results)
        m_file.addAction(act_export)
        m_file.addAction(act_import)

        m_rules = menubar.addMenu(LANG[self.lang]["menu_rules"])
        act_save = QAction(LANG[self.lang]["save_rules"], self)
        act_save.triggered.connect(self.save_rules_as)
        act_load = QAction(LANG[self.lang]["load_rules"], self)
        act_load.triggered.connect(self.load_rules_from)
        m_rules.addAction(act_save)
        m_rules.addAction(act_load)

        m_view = menubar.addMenu(LANG[self.lang]["menu_view"])
        m_theme = m_view.addMenu(LANG[self.lang]["menu_theme"])
        for key, title in [
            ("aurora", LANG[self.lang]["theme_aurora"]),
            ("glass", LANG[self.lang]["theme_glass"]),
            ("cyber", LANG[self.lang]["theme_cyber"]),
            ("midnight", LANG[self.lang]["theme_midnight"]),
            ("royal", LANG[self.lang]["theme_royal"]),
            ("carbon", LANG[self.lang]["theme_carbon"]),
            ("neon", LANG[self.lang]["theme_neon"]),
        ]:
            act = QAction(title, self)
            act.triggered.connect(lambda _=False, k=key: self.switch_theme_preserving_layout(k))
            m_theme.addAction(act)

        m_lang = m_view.addMenu(LANG[self.lang]["menu_lang"])
        act_ar = QAction(LANG[self.lang]["lang_ar"], self)
        act_ar.triggered.connect(lambda: self.switch_lang_preserving_layout("ar"))
        act_en = QAction(LANG[self.lang]["lang_en"], self)
        act_en.triggered.connect(lambda: self.switch_lang_preserving_layout("en"))
        m_lang.addAction(act_ar)
        m_lang.addAction(act_en)

    def switch_theme_preserving_layout(self, theme_key):
        sizes_main = self.split_main.sizes()
        sizes_top = self.split_top.sizes()
        vscroll = self.table.verticalScrollBar().value()
        sel = self.table.currentRow()
        self.theme = theme_key
        self._apply_theme()
        self.split_main.setSizes(sizes_main)
        self.split_top.setSizes(sizes_top)
        self.table.verticalScrollBar().setValue(vscroll)
        if 0 <= sel < self.table.rowCount():
            self.table.selectRow(sel)

    def switch_lang_preserving_layout(self, lang_code):
        sizes_main = self.split_main.sizes()
        sizes_top = self.split_top.sizes()
        vscroll = self.table.verticalScrollBar().value()
        sel = self.table.currentRow()
        self.set_language(lang_code)
        self._translate()
        self.split_main.setSizes(sizes_main)
        self.split_top.setSizes(sizes_top)
        self.table.verticalScrollBar().setValue(vscroll)
        if 0 <= sel < self.table.rowCount():
            self.table.selectRow(sel)

    def set_language(self, lang_code):
        if lang_code not in LANG:
            return
        self.lang = lang_code

    def _translate(self):
        QApplication.setLayoutDirection(Qt.RightToLeft if self.lang=="ar" else Qt.LeftToRight)
        self.setWindowTitle(LANG[self.lang]["title"])
        self._build_menus(self.menubar)
        ip_tail = self.public_ip_label.text().split(":")[-1].strip()
        self.public_ip_label.setText(LANG[self.lang]["public_ip"].format(ip_tail))
        self.search_input.setPlaceholderText(LANG[self.lang]["quick_search"])
        self.start_btn.setText(LANG[self.lang]["start"])
        self.stop_btn.setText(LANG[self.lang]["stop"])
        self._set_group_title(self.split_top.widget(0).widget(), LANG[self.lang]["filters_box"])
        right_box = self.split_top.widget(1)
        if isinstance(right_box, QGroupBox):
            right_box.setTitle(LANG[self.lang]["chart_box"])
        self.update_headers()
        bottom_group = self.split_main.widget(1)
        if isinstance(bottom_group, QGroupBox):
            bottom_group.setTitle(LANG[self.lang]["results_box"])

    def _set_group_title(self, scroll_area, title):
        if isinstance(scroll_area, QScrollArea):
            w = scroll_area.widget()
            if isinstance(w, QGroupBox):
                w.setTitle(title)

    def _apply_theme(self):
        css_common = """
        QToolButton { padding: 8px 12px; border-radius: 10px; font-weight: 600; }
        QLineEdit, QComboBox, QSpinBox, QListWidget { border-radius: 10px; padding: 8px; }
        QGroupBox { border-radius: 16px; margin-top: 12px; padding-top: 12px; }
        QHeaderView::section { padding: 8px; }
        QTableWidget { gridline-color: rgba(0,0,0,0.1); }
        """
        if self.theme == "cyber":
            self.setStyleSheet(css_common + """
            QWidget { background-color:#0b0f0f; color:#c9ffe1; font-family:Consolas,'JetBrains Mono',monospace; }
            QGroupBox { border:1px solid #00ff99; background:#0d1313; }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:#0e1414; border:1px solid #00b386; color:#e0fff0; }
            QToolButton { background:#00b386; color:#072014; border:none; }
            QToolButton:hover { background:#00d4a5; }
            QTableWidget { background:#0e1414; border:1px solid #00ff99; }
            QHeaderView::section { background:#072014; color:#00ffcc; border:1px solid #005f46; }
            """)
        elif self.theme == "glass":
            self.setStyleSheet(css_common + """
            QWidget { background:#e6eef9; color:#102030; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid rgba(255,255,255,0.6); background:rgba(255,255,255,0.7); }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:rgba(255,255,255,0.95); border:1px solid rgba(255,255,255,0.8); }
            QToolButton { background:rgba(255,255,255,0.95); color:#102030; border:1px solid rgba(255,255,255,0.8); }
            QToolButton:hover { background:rgba(255,255,255,1.0); }
            QTableWidget { background:rgba(255,255,255,0.98); border:1px solid rgba(255,255,255,0.8); }
            QHeaderView::section { background:rgba(255,255,255,0.95); color:#102030; border:1px solid rgba(255,255,255,0.8); }
            """)
        elif self.theme == "midnight":
            self.setStyleSheet(css_common + """
            QWidget { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid #30363d; background:#161b22; }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:#0e1621; border:1px solid #30363d; color:#c9d1d9; }
            QToolButton { background:#238636; color:#fff; border:none; }
            QToolButton:hover { background:#2ea043; }
            QTableWidget { background:#0e1621; border:1px solid #30363d; }
            QHeaderView::section { background:#161b22; color:#c9d1d9; border:1px solid #30363d; }
            """)
        elif self.theme == "royal":
            self.setStyleSheet(css_common + """
            QWidget { background:#f7f5ff; color:#1f235a; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid #dcd6ff; background:#ffffff; }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:#ffffff; border:1px solid #c7bfff; color:#1f235a; }
            QToolButton { background:#6c5ce7; color:#fff; border:none; }
            QToolButton:hover { background:#5a4dd3; }
            QTableWidget { background:#ffffff; border:1px solid #e6e0ff; }
            QHeaderView::section { background:#eee9ff; color:#1f235a; border:1px solid #e6e0ff; }
            """)
        elif self.theme == "carbon":
            self.setStyleSheet(css_common + """
            QWidget { background:#171717; color:#eeeeee; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid #2a2a2a; background:#1f1f1f; }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:#1a1a1a; border:1px solid #2a2a2a; color:#eeeeee; }
            QToolButton { background:#3b82f6; color:#fff; border:none; }
            QToolButton:hover { background:#2563eb; }
            QTableWidget { background:#1a1a1a; border:1px solid #2a2a2a; }
            QHeaderView::section { background:#222; color:#e5e5e5; border:1px solid #2a2a2a; }
            """)
        elif self.theme == "neon":
            self.setStyleSheet(css_common + """
            QWidget { background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #0f0f1f, stop:1 #101033); color:#e2fbff; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid #7afcff; background:rgba(10,10,40,0.7); }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:rgba(20,20,60,0.8); border:1px solid #7afcff; color:#e2fbff; }
            QToolButton { background:#06d6a0; color:#002b36; border:none; }
            QToolButton:hover { background:#0eeab5; }
            QTableWidget { background:rgba(20,20,60,0.9); border:1px solid #7afcff; }
            QHeaderView::section { background:rgba(10,10,40,0.8); color:#e2fbff; border:1px solid #355a7a; }
            """)
        else:  # aurora default
            self.setStyleSheet(css_common + """
            QWidget { background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #f8fbff, stop:1 #ecf5ff); color:#1f2937; font-family:'Segoe UI',Arial; }
            QGroupBox { border:1px solid #e5efff; background:#ffffff; }
            QLineEdit,QComboBox,QSpinBox,QListWidget { background:#ffffff; border:1px solid #dbe7ff; color:#1f2937; }
            QToolButton { background:#3b82f6; color:#fff; border:none; }
            QToolButton:hover { background:#2563eb; }
            QTableWidget { background:#ffffff; border:1px solid #e5efff; }
            QHeaderView::section { background:#f1f6ff; color:#374151; border:1px solid #e5efff; }
            """)

    # ---------- Helpers ----------
    def plus_minus_bar(self, list_widget, kind):
        row = QHBoxLayout()
        btn_add = QToolButton()
        btn_add.setText(LANG[self.lang]["add"])
        btn_rm  = QToolButton()
        btn_rm.setText(LANG[self.lang]["remove"])
        btn_add.clicked.connect(lambda: self.add_rule(list_widget, kind))
        btn_rm.clicked.connect(lambda: self.remove_rule(list_widget, kind))
        row.addStretch(1)
        row.addWidget(btn_add)
        row.addWidget(btn_rm)
        return row

    def update_headers(self):
        t = LANG[self.lang]["table"]
        headers = [t["type"], t["proto"], t["laddr"], t["lport"], t["raddr"], t["rport"],
                   t["state"], t["exe"], t["bytes"], t["sig"], t["reason"]]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setStretchLastSection(True)

    # ---------- Start/Stop ----------
    def on_start_clicked(self):
        if self.refresh_timer.isActive():
            return
        self.progress.setVisible(True)
        self.progress.setMaximum(0)
        if self.divert_cb.isChecked() and pydivert is not None and platform.system().lower() == "windows":
            self.divert = DivertSniffer()
            self.divert.bytes_update.connect(self.on_divert_bytes)
            self.divert.start()
        else:
            self.divert = None
        # بدء الفاصل الزمني للتحديث كل 120 ثانية أو القيمة المختارة
        self.refresh_timer.start(self.interval_spin.value() * 1000)
        self.scan_once()

    def on_stop_clicked(self):
        self.refresh_timer.stop()
        if self.divert:
            self.divert.stop()
            self.divert.wait(1000)
            self.divert = None
        self.progress.setVisible(False)
        self.statusBar().showMessage("Stopped.")

    def on_interval_change(self, v):
        if self.refresh_timer.isActive():
            self.refresh_timer.setInterval(v * 1000)

    def on_divert_bytes(self, counters):
        self.divert_bytes = counters

    # ---------- Scanning ----------
    def scan_once(self):
        if self.scan_inflight or self.worker.isRunning():
            return
        self.scan_inflight = True
        filters = {
            "proto": self.proto_combo.currentText(),
            "atype": self.atype_combo.currentText(),
            "keywords": set([s.strip().lower() for s in self.kw_input.text().split(",") if s.strip()]),
            "min_sent": self.min_sent_mb.value() * 1024 * 1024,
            "min_recv": self.min_recv_mb.value() * 1024 * 1024,
            "only_susp": self.only_susp_cb.isChecked()
        }
        rules = {
            "ips": set(self._collect_list(self.ip_list)),
            "ports": set(int(x) for x in self._collect_list(self.port_list) if str(x).isdigit()),
            "keywords": set([x.strip().lower() for x in self._collect_list(self.kw_list) if x.strip()]),
            "allow_ips": set(self._collect_list(self.allow_ip_list)),
            "allow_ports": set(int(x) for x in self._collect_list(self.allow_port_list) if str(x).isdigit()),
            "allow_words": set([x.strip().lower() for x in self._collect_list(self.allow_kw_list) if x.strip()])
        }
        want_divert = bool(self.divert is not None)
        self.worker.configure(filters, rules, want_divert, self.divert_bytes)
        self.worker.finished.connect(self._scan_finished_once)
        self.worker.start()

    def _scan_finished_once(self):
        try:
            self.worker.finished.disconnect(self._scan_finished_once)
        except Exception:
            pass
        self.scan_inflight = False

    def on_scanned(self, rows, stats):
        # تحديث البطاقات الإحصائية
        allc = stats.get("ALL", 0)
        tcp = stats.get("TCP", 0)
        udp = stats.get("UDP", 0)
        lst = stats.get("LISTEN", 0)
        est = stats.get("ESTABLISHED", 0)
        self.cards["ALL"].setText(str(allc))
        self.cards["TCP"].setText(str(tcp))
        self.cards["UDP"].setText(str(udp))
        self.cards["LISTEN"].setText(str(lst))
        self.cards["ESTABLISHED"].setText(str(est))

        # تحديث الجدول مع تحسين الأداء عبر تعطيل التحديثات مؤقتا
        q = self.search_input.text().strip().lower()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        vbar = self.table.verticalScrollBar()
        old_scroll = vbar.value()
        sel = self.table.currentRow()
        self.table.setRowCount(0)
        for item in rows:
            if q:
                blob = " ".join(str(v) for v in item.values()).lower()
                if q not in blob:
                    continue
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(item["type"]))
            self.table.setItem(r, 1, QTableWidgetItem(item["proto"]))
            self.table.setItem(r, 2, QTableWidgetItem(item["laddr"]))
            self.table.setItem(r, 3, QTableWidgetItem(str(item["lport"])))
            self.table.setItem(r, 4, QTableWidgetItem(item["raddr"]))
            self.table.setItem(r, 5, QTableWidgetItem(str(item["rport"])))
            self.table.setItem(r, 6, QTableWidgetItem(item["state"]))
            self.table.setItem(r, 7, QTableWidgetItem(item["exe"]))
            self.table.setItem(r, 8, QTableWidgetItem(item["bytes"]))
            self.table.setItem(r, 9, QTableWidgetItem(item["sig"]))
            self.table.setItem(r, 10, QTableWidgetItem(item["reason"]))
        self.table.setUpdatesEnabled(True)
        self.table.setSortingEnabled(True)
        QTimer.singleShot(0, lambda: vbar.setValue(old_scroll))
        if 0 <= sel < self.table.rowCount():
            self.table.selectRow(sel)

        # تحديث الرسم البياني
        if self.chart and MPL_OK:
            labels = ["LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV"]
            counts = [0] * len(labels)
            for r in rows:
                if r["type"] in labels:
                    counts[labels.index(r["type"])] += 1
            self.chart.plot_counts(labels, counts)

        # تحديث الخريطة باستخدام folium بعد بدء الفحص مع تحسين التحريك إلى اليمين وإضافة popup لكل علامة
        if self.map_view:
            self.show_map_with_folium(rows)

    def show_map_with_folium(self, rows):
        markers = []
        for r in rows:
            ip = r.get("raddr")
            if ip:
                latlon = self.map_cache_get(ip)
                if latlon:
                    markers.append((ip, latlon))
        if markers:
            lats = [lat for _, (lat, lon) in markers]
            lons = [lon for _, (lat, lon) in markers]
            avg_lat = sum(lats) / len(lats)
            avg_lon = sum(lons) / len(lons)
            # إزاحة بسيطة لليمين بإضافة فرق بسيط في خط الطول
            offset = 0.5
            m = folium.Map(location=[avg_lat, avg_lon + offset], zoom_start=3)
            for ip, (lat, lon) in markers:
                folium.Marker(location=[lat, lon], popup=f"IP: {ip}").add_to(m)
        else:
            m = folium.Map(location=[24.7136, 46.6753], zoom_start=3)
        data = m._repr_html_()
        QTimer.singleShot(60, lambda: self.map_view.setHtml(data))

    def on_chip_clicked(self, key):
        if key in ("TCP", "UDP"):
            self.proto_combo.blockSignals(True)
            self.proto_combo.setCurrentText(key)
            self.proto_combo.blockSignals(False)
        elif key in ("LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV"):
            self.atype_combo.blockSignals(True)
            self.atype_combo.setCurrentText(key)
            self.atype_combo.blockSignals(False)
        elif key == "ALL":
            self.proto_combo.blockSignals(True)
            self.atype_combo.blockSignals(True)
            self.proto_combo.setCurrentIndex(0)
            self.atype_combo.setCurrentIndex(0)
            self.proto_combo.blockSignals(False)
            self.atype_combo.blockSignals(False)
        self.scan_once()

    def on_row_double_clicked(self, *_):
        r = self.table.currentRow()
        if r < 0:
            return
        g = lambda c: (self.table.item(r, c).text() if self.table.item(r, c) else "-")
        record = {
            "type": g(0), "proto": g(1),
            "laddr": g(2), "lport": g(3),
            "raddr": g(4), "rport": g(5),
            "state": g(6), "exe": g(7),
            "bytes": g(8), "sig": g(9),
            "reason": g(10),
        }
        dlg = DetailsDialog(LANG[self.lang], record, self)
        dlg.exec_()

    def apply_client_filter(self):
        self.scan_once()

    def add_rule(self, lw, kind):
        if kind in ("port", "allow_port"):
            title = "Port:" if self.lang == "en" else "رقم المنفذ:"
            val, ok = QInputDialog.getInt(self, "Add port", title, 0, 0, 65535, 1)
            if ok:
                lw.addItem(QListWidgetItem(str(val)))
        else:
            title = "Enter value" if self.lang == "en" else "أدخل قيمة"
            val, ok = QInputDialog.getText(self, title, "")
            if ok and val.strip():
                lw.addItem(QListWidgetItem(val.strip()))
        self.save_settings()
        self.scan_once()

    def remove_rule(self, lw, kind):
        for it in lw.selectedItems():
            lw.takeItem(lw.row(it))
        self.save_settings()
        self.scan_once()

    def edit_list_item(self, lw, item, kind):
        title = "Edit value" if self.lang == "en" else "تعديل القيمة"
        val, ok = QInputDialog.getText(self, title, text=item.text())
        if ok and val.strip():
            item.setText(val.strip())
            self.save_settings()
            self.scan_once()

    def export_results(self):
        filters = "XLSX (*.xlsx);;CSV (*.csv);;JSON (*.json)"
        path, sel = QFileDialog.getSaveFileName(self, "Export", "", filters)
        if not path:
            return
        data = []
        cols = self.table.columnCount()
        headers = [self.table.horizontalHeaderItem(i).text() for i in range(cols)]
        for r in range(self.table.rowCount()):
            data.append([self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(cols)])
        try:
            lower = path.lower()
            if lower.endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"headers": headers, "rows": data}, f, ensure_ascii=False, indent=2)
            elif lower.endswith(".xlsx"):
                if not XLSX_OK:
                    raise RuntimeError("openpyxl not installed")
                wb = Workbook()
                ws = wb.active
                ws.title = "NetActivity"
                ws.append(headers)
                for row in data:
                    ws.append(row)
                wb.save(path)
            else:
                import csv
                if not lower.endswith(".csv"):
                    path += ".csv"
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(headers)
                    w.writerows(data)
        except Exception as e:
            QMessageBox.warning(self, APP_NAME, f"Export error: {e}")

    def import_results(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import", "", "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        rows = []
        headers = None
        try:
            if path.lower().endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                headers = raw.get("headers")
                rows = raw.get("rows", [])
            else:
                import csv
                with open(path, "r", encoding="utf-8") as f:
                    r = csv.reader(f)
                    headers = next(r, None)
                    for line in r:
                        rows.append(line)
        except Exception as e:
            QMessageBox.warning(self, APP_NAME, f"Import error: {e}")
            return
        if headers and len(headers) == 11:
            self.table.setHorizontalHeaderLabels(headers)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for line in rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            for c, val in enumerate(line[:11]):
                self.table.setItem(i, c, QTableWidgetItem(str(val)))
        self.table.setSortingEnabled(True)

    def save_rules_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Rules", "", "JSON (*.json)")
        if not path:
            return
        rules = self._collect_all_rules()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False, indent=2)
        except Exception as e:
            QMessageBox.warning(self, APP_NAME, f"Save error: {e}")

    def load_rules_from(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Rules", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception as e:
            QMessageBox.warning(self, APP_NAME, f"Load error: {e}")
            return
        self._apply_rules_to_lists(rules)
        self.save_settings()
        self.scan_once()

    def _collect_list(self, lw):
        return [lw.item(i).text() for i in range(lw.count())]

    def _collect_all_rules(self):
        return {
            "ips": [self.ip_list.item(i).text() for i in range(self.ip_list.count())],
            "ports": [int(self.port_list.item(i).text()) for i in range(self.port_list.count()) if self.port_list.item(i).text().isdigit()],
            "keywords": [self.kw_list.item(i).text() for i in range(self.kw_list.count())],
            "allow_ips": [self.allow_ip_list.item(i).text() for i in range(self.allow_ip_list.count())],
            "allow_ports": [int(self.allow_port_list.item(i).text()) for i in range(self.allow_port_list.count()) if self.allow_port_list.item(i).text().isdigit()],
            "allow_words": [self.allow_kw_list.item(i).text() for i in range(self.allow_kw_list.count())],
        }

    def _apply_rules_to_lists(self, rules):
        self.ip_list.clear()
        self.port_list.clear()
        self.kw_list.clear()
        self.allow_ip_list.clear()
        self.allow_port_list.clear()
        self.allow_kw_list.clear()
        for ip in rules.get("ips", []):
            self.ip_list.addItem(QListWidgetItem(str(ip)))
        for p in rules.get("ports", []):
            self.port_list.addItem(QListWidgetItem(str(p)))
        for k in rules.get("keywords", []):
            self.kw_list.addItem(QListWidgetItem(str(k)))
        for ip in rules.get("allow_ips", []):
            self.allow_ip_list.addItem(QListWidgetItem(str(ip)))
        for p in rules.get("allow_ports", []):
            self.allow_port_list.addItem(QListWidgetItem(str(p)))
        for k in rules.get("allow_words", []):
            self.allow_kw_list.addItem(QListWidgetItem(str(k)))

    def load_settings(self):
        if not os.path.isfile(SETTINGS_FILE):
            return
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                s = json.load(f)
        except Exception:
            return
        self.lang = s.get("lang", self.lang)
        self.theme = s.get("theme", self.theme)
        self.interval_spin.setValue(s.get("interval", self.interval_spin.value()))
        self.proto_combo.setCurrentText(s.get("proto", self.proto_combo.currentText()))
        self.atype_combo.setCurrentText(s.get("atype", self.atype_combo.currentText()))
        self.only_susp_cb.setChecked(s.get("only_susp", False))
        self.kw_input.setText(s.get("kw_text", ""))
        self.min_sent_mb.setValue(s.get("min_sent_mb", self.min_sent_mb.value()))
        self.min_recv_mb.setValue(s.get("min_recv_mb", self.min_recv_mb.value()))
        lists = s.get("lists", {})
        self._apply_rules_to_lists(lists)

    def save_settings(self):
        s = {
            "lang": self.lang,
            "theme": self.theme,
            "interval": self.interval_spin.value(),
            "proto": self.proto_combo.currentText(),
            "atype": self.atype_combo.currentText(),
            "only_susp": self.only_susp_cb.isChecked(),
            "kw_text": self.kw_input.text(),
            "min_sent_mb": self.min_sent_mb.value(),
            "min_recv_mb": self.min_recv_mb.value(),
            "lists": self._collect_all_rules()
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(s, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def closeEvent(self, e):
        self.save_settings()
        super().closeEvent(e)

    def fetch_public_ip(self):
        ip = "--"
        try:
            if requests is not None:
                ip = requests.get("https://api.ipify.org", timeout=4).text.strip()
        except Exception:
            ip = "--"
        self.public_ip_label.setText(LANG[self.lang]["public_ip"].format(ip))

    def map_cache_get(self, ip):
        if ip in self.map_cache:
            return self.map_cache[ip]
        if requests is None:
            return None
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon", timeout=3)
            j = r.json()
            if j.get("status") == "success":
                lat, lon = j.get("lat"), j.get("lon")
                self.map_cache[ip] = (lat, lon)
                return lat, lon
        except Exception:
            return None
        return None

def main():
    app = QApplication(sys.argv)
    win = NetworkMonitorPro()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()