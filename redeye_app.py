#!/usr/bin/env python3
"""
RedEye — Cross-Platform Malicious Site & Web App Tray Monitor
Author: nelhorr (IOModule)
Supported Platforms:
  - Windows 10 / 11 (x64 / ARM64)
  - macOS Intel (x86_64) & Apple Silicon (M1 / M2 / M3 / M4 arm64)
  - Linux LMDE (Linux Mint Debian Edition) & all Debian/Ubuntu-based distributions
"""

import sys
import os
import re
import csv
import json
import time
import socket
import shutil
import platform
import threading
import subprocess
from datetime import datetime
from pathlib import Path

import psutil
import requests

from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QPropertyAnimation,
    QEasingCurve, QRect, QPoint, QPointF, QSize
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QSystemTrayIcon, QMenu, QGraphicsDropShadowEffect,
    QProgressBar, QMessageBox, QInputDialog
)
from PyQt6.QtGui import (
    QColor, QFont, QAction, QIcon, QPixmap, QPainter,
    QRadialGradient, QLinearGradient, QPen, QBrush, QPainterPath, QPolygonF
)

# Native macOS imports for Menu Bar (Clock) Accessory mode (Intel & Apple Silicon)
if platform.system() == "Darwin":
    try:
        from AppKit import (
            NSApplication,
            NSApplicationActivationPolicyAccessory
        )
        HAS_MACOS_APPKIT = True
    except ImportError:
        HAS_MACOS_APPKIT = False
else:
    HAS_MACOS_APPKIT = False

# --- Configuration ---
APP_NAME = "RedEye"
APP_VERSION = "1.0.0"
CHECK_INTERVAL = 1.5       # Seconds between browser/web-app connection scans
NOTIFICATION_MS = 5000     # 5 seconds notification display duration
MAX_MENU_HISTORY = 12

# Colors (Cyber Red Eye Theme)
CRIMSON_CORE = "#ff0033"
CRIMSON_GLOW = "#ff1a4b"
DARK_BG = "#0d0f14"
CARD_BG = "#141821"
BORDER_RED = "#ff2a55"
BORDER_WARN = "#ff9900"
TEXT_WHITE = "#f5f7fa"
TEXT_MUTED = "#9aa4b8"

# Known Browsers & Web App Runtimes across Windows, macOS, and Linux (LMDE/Debian)
BROWSER_PROCESS_KEYWORDS = (
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
    "safari", "webkit", "chromium", "arc", "waterfox", "librewolf",
    "tor", "palemoon", "epiphany", "midori", "falkon", "seamonkey",
    "webview2", "electron", "cef", "nwjs", "min", "floorp", "zen"
)

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}

# Built-in Baseline Malicious / Test Domains & Indicators (works 100% offline before feed sync)
BUILTIN_MALICIOUS_DOMAINS = {
    # Standard security test domains (safe to visit for testing RedEye)
    "malware.testing.google.test": ("Malware Test Site", 98),
    "testsafebrowsing.appspot.com": ("Phishing / Malware Test", 95),
    "amtso.org": ("Security Feature Check", 75),
    "wicar.org": ("Malware Exploit Test Suite", 92),
    "eicar.org": ("EICAR Antivirus Test Site", 88),
    "badssl.com": ("Untrusted TLS / Certificate Risk", 72),
    "expired.badssl.com": ("Expired SSL Certificate", 78),
    "self-signed.badssl.com": ("Self-Signed SSL Certificate", 80),
    "untrusted-root.badssl.com": ("Untrusted Root Certificate", 85),
    "revoked.badssl.com": ("Revoked SSL Certificate", 90),
    # High-risk phishing / malware lure domains
    "secure-login-update-account.com": ("Credential Phishing", 96),
    "verify-wallet-connect-sync.com": ("Crypto Drainer / Phishing", 99),
    "free-nitro-steam-gift.xyz": ("Scam / Phishing Lure", 94),
    "login-microsoft-online-auth.net": ("Account Takeover Phishing", 97),
    "apple-id-support-verify.com": ("Brand Impersonation Phishing", 96),
    "paypal-resolution-security.com": ("Financial Phishing", 98),
}

SUSPICIOUS_TLD_SCORES = {
    ".zip": ("High-Risk TLD (.zip file lure)", 72),
    ".mov": ("High-Risk TLD (.mov lure)", 68),
    ".top": ("High-Abuse TLD (.top)", 65),
    ".xyz": ("Elevated-Risk TLD (.xyz)", 60),
    ".tk": ("High-Abuse Freenom TLD (.tk)", 80),
    ".ml": ("High-Abuse Freenom TLD (.ml)", 80),
    ".ga": ("High-Abuse Freenom TLD (.ga)", 80),
    ".cf": ("High-Abuse Freenom TLD (.cf)", 80),
    ".gq": ("High-Abuse Freenom TLD (.gq)", 80),
    ".icu": ("High-Abuse TLD (.icu)", 70),
    ".buzz": ("High-Abuse TLD (.buzz)", 68),
    ".monster": ("High-Abuse TLD (.monster)", 68),
    ".click": ("Phishing-Prone TLD (.click)", 65),
    ".rest": ("Malware-Prone TLD (.rest)", 70),
    ".fit": ("Spam/Phishing TLD (.fit)", 62),
}

PHISHING_KEYWORDS = (
    "login-verify", "account-update", "secure-signin", "wallet-connect",
    "seed-phrase", "airdrop-claim", "verify-identity", "bank-security",
    "unlock-account", "password-reset-urgent", "crypto-giveaway", "free-gift"
)

SAFE_WHITELIST_SUFFIXES = (
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "1e100.net",
    "microsoft.com", "windows.com", "live.com", "office.com", "azure.com",
    "apple.com", "icloud.com", "mzstatic.com", "akadns.net", "akamai.net",
    "akamaitechnologies.com", "cloudflare.com", "cloudflare-dns.com",
    "github.com", "githubusercontent.com", "gitlab.com",
    "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com",
    "ubuntu.com", "debian.org", "linuxmint.com",
    "amazonaws.com", "cloudfront.net", "fastly.net", "digicert.com",
    "letsencrypt.org", "ocsp.int-x3.letsencrypt.org", "ip-api.com",
    "abuse.ch", "feodotracker.abuse.ch", "urlhaus.abuse.ch", "openphish.com",
    "bing.com", "msn.com", " edgeservices.bing.com", "Nel.measure.office.net",
    "trafficmanager.net", "edge.microsoft.com", "msedge.net", "virtualearth.net"
)

TRUSTED_ISP_KEYWORDS = (
    "microsoft", "google", "cloudflare", "akamai", "fastly", "amazon",
    "apple", "meta", "facebook", "github", "mozilla", "edgecast",
    "verisign", "digicert", "let's encrypt", "quad9", "cisco", "opendns"
)

SYSTEM_IGNORE_PROCESSES = (
    "svchost.exe", "system", "idle", "services.exe", "lsass.exe",
    "onedrive.exe", "searchhost.exe", "backgroundtaskhost.exe", "redeye.exe",
    "rclone.exe", "rclone"
)


# --- Custom Red Eye Icon Generator ---

def create_red_eye_Pixmap(size: int = 64, alert_active: bool = False) -> QPixmap:
    """
    Draws a crisp, high-DPI Cybernetic Red Eye icon near the system clock.
    Works across Windows taskbar, macOS Menu Bar (Intel & M-Chip), and Linux system trays.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    cx, cy = size / 2.0, size / 2.0

    # 1. Outer Dark Shield / Circle Background
    bg_grad = QRadialGradient(QPointF(cx, cy), size * 0.48)
    if alert_active:
        bg_grad.setColorAt(0.0, QColor("#450512"))
        bg_grad.setColorAt(0.7, QColor("#1f0308"))
        bg_grad.setColorAt(1.0, QColor("#ff0033"))
    else:
        bg_grad.setColorAt(0.0, QColor("#1c060b"))
        bg_grad.setColorAt(0.8, QColor("#0d0e12"))
        bg_grad.setColorAt(1.0, QColor("#2a0810"))

    painter.setBrush(QBrush(bg_grad))
    border_color = QColor("#ff0033") if alert_active else QColor("#cc0029")
    painter.setPen(QPen(border_color, max(1.5, size * 0.035)))
    margin = size * 0.05
    painter.drawEllipse(QPointF(cx, cy), size * 0.45, size * 0.45)

    # 2. Eye Almond / Sclera Contour Path
    eye_w = size * 0.76
    eye_h = size * 0.44
    left_pt = QPointF(cx - eye_w / 2.0, cy)
    right_pt = QPointF(cx + eye_w / 2.0, cy)

    eye_path = QPainterPath()
    eye_path.moveTo(left_pt)
    eye_path.cubicTo(
        QPointF(cx - eye_w * 0.22, cy - eye_h * 0.68),
        QPointF(cx + eye_w * 0.22, cy - eye_h * 0.68),
        right_pt
    )
    eye_path.cubicTo(
        QPointF(cx + eye_w * 0.22, cy + eye_h * 0.68),
        QPointF(cx - eye_w * 0.22, cy + eye_h * 0.68),
        left_pt
    )
    eye_path.closeSubpath()

    # Sclera dark crimson glow
    sclera_grad = QLinearGradient(left_pt, right_pt)
    sclera_grad.setColorAt(0.0, QColor("#2b0008"))
    sclera_grad.setColorAt(0.5, QColor("#590012"))
    sclera_grad.setColorAt(1.0, QColor("#2b0008"))
    painter.setBrush(QBrush(sclera_grad))
    painter.setPen(QPen(QColor("#ff1a4b"), max(1.8, size * 0.04)))
    painter.drawPath(eye_path)

    # 3. Glowing Red Iris
    iris_r = size * 0.20
    iris_grad = QRadialGradient(QPointF(cx, cy), iris_r)
    iris_grad.setColorAt(0.0, QColor("#ff4d6d"))
    iris_grad.setColorAt(0.45, QColor("#ff0033"))
    iris_grad.setColorAt(0.85, QColor("#b30024"))
    iris_grad.setColorAt(1.0, QColor("#4d000f"))

    painter.setBrush(QBrush(iris_grad))
    painter.setPen(QPen(QColor("#ff6680"), max(1.0, size * 0.02)))
    painter.drawEllipse(QPointF(cx, cy), iris_r, iris_r)

    # 4. Vertical Cyber Slit Pupil
    pupil_w = size * 0.075
    pupil_h = size * 0.27
    pupil_path = QPainterPath()
    pupil_path.moveTo(QPointF(cx, cy - pupil_h / 2.0))
    pupil_path.quadTo(QPointF(cx + pupil_w, cy), QPointF(cx, cy + pupil_h / 2.0))
    pupil_path.quadTo(QPointF(cx - pupil_w, cy), QPointF(cx, cy - pupil_h / 2.0))
    painter.setBrush(QBrush(QColor("#070204")))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawPath(pupil_path)

    # 5. Crisp Specular Catchlight
    glint_r = size * 0.045
    painter.setBrush(QBrush(QColor(255, 255, 255, 230)))
    painter.drawEllipse(QPointF(cx - iris_r * 0.38, cy - iris_r * 0.35), glint_r, glint_r)

    painter.end()
    return pixmap


def create_red_eye_icon(alert_active: bool = False) -> QIcon:
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128):
        icon.addPixmap(create_red_eye_Pixmap(sz, alert_active=alert_active))
    return icon


# --- Helper Utilities: DNS Cache, Reverse Lookup, Active Browser Inspection ---

class DomainResolver:
    """Resolves connected IPs to domain names using OS DNS cache + reverse DNS."""

    def __init__(self):
        self.ip_to_domain = {}
        self.last_cache_refresh = 0.0
        self.lock = threading.Lock()

    def resolve_ip(self, ip: str) -> str:
        with self.lock:
            if ip in self.ip_to_domain:
                return self.ip_to_domain[ip]

        # Refresh OS DNS cache periodically
        now = time.time()
        if now - self.last_cache_refresh > 4.0:
            self.refresh_os_dns_cache()

        with self.lock:
            if ip in self.ip_to_domain:
                return self.ip_to_domain[ip]

        # Fallback: PTR reverse DNS lookup with short timeout
        domain = ""
        try:
            socket.setdefaulttimeout(1.5)
            host, _, _ = socket.gethostbyaddr(ip)
            if host and host != ip:
                domain = host.lower().strip(".")
        except Exception:
            domain = ""

        if domain:
            with self.lock:
                self.ip_to_domain[ip] = domain
        return domain

    def refresh_os_dns_cache(self):
        self.last_cache_refresh = time.time()
        sys_name = platform.system()
        if sys_name == "Windows":
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                res = subprocess.run(
                    ["ipconfig", "/displaydns"],
                    capture_output=True, text=True, timeout=2,
                    startupinfo=startupinfo, errors="ignore"
                )
                current_record = None
                for raw_line in res.stdout.splitlines():
                    line = raw_line.strip()
                    if "Record Name" in line and ":" in line:
                        current_record = line.split(":", 1)[1].strip().lower().strip(".")
                    elif ("A (Host) Record" in line or "AAAA Record" in line) and ":" in line and current_record:
                        ip_val = line.split(":", 1)[1].strip()
                        if ip_val:
                            with self.lock:
                                self.ip_to_domain[ip_val] = current_record
            except Exception:
                pass


def get_active_browser_context(proc_name: str, pid: int) -> str:
    """
    Attempts to read the active window title or tab URL of the browser
    across Windows, macOS (Intel & M-chip), and Linux (LMDE/Debian)
    to identify the exact site/web-app opened by the user.
    """
    sys_name = platform.system()
    pname = (proc_name or "").lower()

    if sys_name == "Darwin":
        # macOS AppleScript for Safari / Chrome / Brave / Edge / Arc
        try:
            if "safari" in pname:
                script = 'tell application "Safari" to if (count of documents) > 0 then get URL of front document'
            elif "chrome" in pname:
                script = 'tell application "Google Chrome" to if (count of windows) > 0 then get URL of active tab of front window'
            elif "brave" in pname:
                script = 'tell application "Brave Browser" to if (count of windows) > 0 then get URL of active tab of front window'
            elif "edge" in pname:
                script = 'tell application "Microsoft Edge" to if (count of windows) > 0 then get URL of active tab of front window'
            else:
                script = None
            if script:
                res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=1.2)
                url = res.stdout.strip()
                if url.startswith("http"):
                    host = url.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
                    return host
        except Exception:
            pass

    elif sys_name == "Windows":
        # Inspect window titles belonging to the browser PID using ctypes Win32 API (zero external deps)
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            titles = []

            WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            def enum_cb(hwnd, _):
                if user32.IsWindowVisible(hwnd):
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buf = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buf, length + 1)
                        title = buf.value.strip()
                        if title:
                            titles.append(title)
                return True

            user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
            domain_regex = re.compile(r"\b([a-zA-Z0-9-]+\.(?:com|net|org|io|xyz|top|tk|ml|ga|cf|gq|icu|zip|mov|ru|cn|info|biz|test|local|co|me|app|dev))\b", re.I)
            for t in titles:
                m = domain_regex.search(t)
                if m:
                    return m.group(1).lower()
        except Exception:
            pass

    elif sys_name == "Linux":
        # Linux LMDE / Debian: try xdotool / xprop if available
        try:
            if shutil.which("xdotool"):
                res = subprocess.run(["xdotool", "getactivewindow", "getwindowname"], capture_output=True, text=True, timeout=1.0)
                title = res.stdout.strip()
                domain_regex = re.compile(r"\b([a-zA-Z0-9-]+\.(?:com|net|org|io|xyz|top|tk|ml|ga|cf|gq|icu|zip|mov|ru|cn|info|biz|test))\b", re.I)
                m = domain_regex.search(title)
                if m:
                    return m.group(1).lower()
        except Exception:
            pass

    return ""


def get_ip_geo_and_isp(ip: str) -> dict:
    """Fetches geographic location, ISP/Org, and hosting/proxy flags for an IP."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting"
        resp = requests.get(url, timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                city = data.get("city") or "Unknown City"
                country = data.get("country") or "Unknown Country"
                return {
                    "location": f"{city}, {country}",
                    "org": data.get("org") or data.get("isp") or "Unknown ISP",
                    "asn": data.get("as") or "",
                    "is_proxy": bool(data.get("proxy", False)),
                    "is_hosting": bool(data.get("hosting", False)),
                }
    except Exception:
        pass
    return {
        "location": "Unknown Location",
        "org": "Unknown ISP",
        "asn": "",
        "is_proxy": False,
        "is_hosting": False,
    }


# --- Threat Intelligence Engine ---

class ThreatIntelligenceEngine:
    """
    Combines live open-source threat feeds (URLhaus, OpenPhish, Feodo Tracker, IPsum),
    local blocklists, and heuristic domain/IP scoring to detect malicious sites & web apps.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.feed_cache_file = self.data_dir / "threat_feeds_cache.json"
        self.blocked_file = self.data_dir / "blocked_sites.json"

        self.malicious_domains = dict(BUILTIN_MALICIOUS_DOMAINS)
        self.malicious_ips = {
            # Feodo / known test C2 indicators
            "185.220.101.1": ("Tor Exit / Suspicious Relay", 78),
            "185.220.101.4": ("Known Malicious Relay IP", 88),
            "45.95.147.226": ("Malware C2 Server (Feodo)", 96),
            "193.142.146.35": ("Botnet C2 Node", 94),
        }
        self.user_blocked_domains = set()
        self.user_blocked_ips = set()

        self.load_blocked_sites()
        self.load_cached_feeds()

    def load_blocked_sites(self):
        if self.blocked_file.exists():
            try:
                data = json.loads(self.blocked_file.read_text(encoding="utf-8"))
                self.user_blocked_domains = set(data.get("domains", []))
                self.user_blocked_ips = set(data.get("ips", []))
            except Exception as e:
                print(f"[RedEye] Failed to load blocked sites: {e}")

    def save_blocked_sites(self):
        try:
            payload = {
                "domains": sorted(list(self.user_blocked_domains)),
                "ips": sorted(list(self.user_blocked_ips)),
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.blocked_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[RedEye] Failed to save blocked sites: {e}")

    def add_to_blocklist(self, domain: str, ip: str) -> bool:
        if domain and domain != "Unknown Domain":
            self.user_blocked_domains.add(domain.lower().strip())
        if ip and ip != "0.0.0.0":
            self.user_blocked_ips.add(ip.strip())
        self.save_blocked_sites()
        return self.try_apply_system_hosts_block(domain)

    def remove_from_blocklist(self, target: str):
        t = target.lower().strip()
        self.user_blocked_domains.discard(t)
        self.user_blocked_ips.discard(t)
        self.save_blocked_sites()

    def try_apply_system_hosts_block(self, domain: str) -> bool:
        """
        Attempts to append `0.0.0.0 <domain>` to the OS hosts file if privileges allow.
        Even without root/admin privileges, RedEye enforces its own active process/tab blocklist!
        """
        if not domain or domain == "Unknown Domain" or re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return False
        hosts_path = (
            Path(r"C:\Windows\System32\drivers\etc\hosts")
            if platform.system() == "Windows"
            else Path("/etc/hosts")
        )
        try:
            if hosts_path.exists() and os.access(hosts_path, os.W_OK):
                content = hosts_path.read_text(encoding="utf-8", errors="ignore")
                entry = f"0.0.0.0 {domain} # Blocked by RedEye\n"
                if domain not in content:
                    with open(hosts_path, "a", encoding="utf-8") as f:
                        f.write(f"\n{entry}")
                return True
        except Exception:
            pass
        return False

    def load_cached_feeds(self):
        if self.feed_cache_file.exists():
            try:
                data = json.loads(self.feed_cache_file.read_text(encoding="utf-8"))
                for d in data.get("domains", []):
                    if d not in self.malicious_domains:
                        self.malicious_domains[d] = ("Live Threat Feed (Malware/Phishing)", 92)
                for ip in data.get("ips", []):
                    if ip not in self.malicious_ips:
                        self.malicious_ips[ip] = ("Live Threat Feed C2/Botnet IP", 90)
            except Exception:
                pass

    def update_threat_feeds_async(self, on_done_callback=None):
        """Fetches fresh indicators from Abuse.ch URLhaus, OpenPhish, and Feodo Tracker in background."""
        def worker():
            new_domains = set()
            new_ips = set()
            try:
                # 1. Abuse.ch Feodo Tracker Botnet C2 IP Blocklist
                r1 = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", timeout=6)
                if r1.status_code == 200:
                    for line in r1.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                            new_ips.add(line)

                # 2. OpenPhish Community Active Phishing URLs
                r2 = requests.get("https://openphish.com/feed.txt", timeout=6)
                if r2.status_code == 200:
                    for line in r2.text.splitlines():
                        line = line.strip()
                        if line.startswith("http"):
                            host = line.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
                            if host:
                                new_domains.add(host)

                # 3. Abuse.ch URLhaus Recent Online Malware URLs
                r3 = requests.get("https://urlhaus.abuse.ch/downloads/text_online/", timeout=6)
                if r3.status_code == 200:
                    for line in r3.text.splitlines():
                        line = line.strip()
                        if line.startswith("http"):
                            host = line.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
                            if host:
                                new_domains.add(host)
            except Exception as e:
                print(f"[RedEye] Feed update warning: {e}")

            for d in new_domains:
                self.malicious_domains[d] = ("URLhaus / OpenPhish Verified Threat", 95)
            for ip in new_ips:
                self.malicious_ips[ip] = ("Abuse.ch Feodo C2 IP", 94)

            try:
                cache_data = {
                    "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "domains": list(new_domains)[:8000],
                    "ips": list(new_ips)[:5000]
                }
                self.feed_cache_file.write_text(json.dumps(cache_data), encoding="utf-8")
            except Exception:
                pass

            if on_done_callback:
                on_done_callback(len(self.malicious_domains), len(self.malicious_ips))

        threading.Thread(target=worker, daemon=True).start()

    def evaluate_site(self, domain: str, ip: str, geo_info: dict, port: int = 443) -> dict:
        """
        Evaluates a domain + IP accessed by a browser or web app.
        Returns a rating dictionary:
          - is_malicious: bool
          - risk_score: int (0-100)
          - stars: str (e.g. '★☆☆☆☆ (1/5) - CRITICAL')
          - category: str
          - previously_blocked: bool
        """
        d = (domain or "").lower().strip(".")
        ip_str = (ip or "").strip()

        # 1. Check User Blocklist first
        if (d and d in self.user_blocked_domains) or (ip_str and ip_str in self.user_blocked_ips):
            return {
                "is_malicious": True,
                "previously_blocked": True,
                "risk_score": 100,
                "stars": "★☆☆☆☆ (1/5) — BLOCKED SITE",
                "severity": "BLOCKED",
                "category": "Blocked by User Policy"
            }

        # Check parent domains in user blocklist
        if d:
            for blocked_d in self.user_blocked_domains:
                if d == blocked_d or d.endswith("." + blocked_d):
                    return {
                        "is_malicious": True,
                        "previously_blocked": True,
                        "risk_score": 100,
                        "stars": "★☆☆☆☆ (1/5) — BLOCKED SITE",
                        "severity": "BLOCKED",
                        "category": f"Blocked Domain ({blocked_d})"
                    }

        # 2. Check Known Safe Whitelist & Trusted Cloud/Browser Infrastructure (e.g., Bing/Edge 150.171.x.x)
        if d:
            for safe_sfx in SAFE_WHITELIST_SUFFIXES:
                if d == safe_sfx or d.endswith("." + safe_sfx):
                    return {
                        "is_malicious": False,
                        "previously_blocked": False,
                        "risk_score": 5,
                        "stars": "★★★★★ (5/5) — TRUSTED",
                        "severity": "SAFE",
                        "category": "Verified Trusted Service"
                    }

        # 3. Check Malicious Domain Database & Threat Feeds
        if d:
            if d in self.malicious_domains:
                reason, score = self.malicious_domains[d]
                return self._format_threat(score, reason)
            for mal_d, (reason, score) in self.malicious_domains.items():
                if d.endswith("." + mal_d):
                    return self._format_threat(score, reason)

        # 4. Check Malicious IP Database
        if ip_str in self.malicious_ips:
            reason, score = self.malicious_ips[ip_str]
            return self._format_threat(score, reason)

        # If IP belongs to a trusted major browser/CDN vendor (Microsoft Edge/Bing, Google, Cloudflare, Apple, etc.)
        # and did not match any malicious domain/IP feed above, treat as safe infrastructure.
        org_lower = (geo_info.get("org", "") + " " + geo_info.get("asn", "")).lower()
        is_trusted_isp = any(k in org_lower for k in TRUSTED_ISP_KEYWORDS)
        if is_trusted_isp and (not d or d == ip_str):
            return {
                "is_malicious": False,
                "previously_blocked": False,
                "risk_score": 5,
                "stars": "★★★★★ (5/5) — TRUSTED CDN/CLOUD",
                "severity": "SAFE",
                "category": f"Trusted Infrastructure ({geo_info.get('org', 'Cloud')})"
            }

        # 5. Heuristic Scoring for Phishing / Suspicious Web Apps
        score = 10
        reasons = []

        if d and d != ip_str:
            # Punycode IDN homograph attack check
            if "xn--" in d:
                score += 65
                reasons.append("IDN Homograph / Punycode Spoofing")

            # Phishing lure keywords
            for kw in PHISHING_KEYWORDS:
                if kw in d:
                    score += 70
                    reasons.append(f"Phishing Lure Pattern ({kw})")
                    break

            # Suspicious high-abuse TLDs
            for tld, (tld_reason, tld_score) in SUSPICIOUS_TLD_SCORES.items():
                if d.endswith(tld):
                    score = max(score, tld_score)
                    reasons.append(tld_reason)
                    break

            # Excessive subdomains or long random hostnames typical of DGA / phishing kits
            if d.count(".") >= 4 and len(d) > 42 and not is_trusted_isp:
                score += 35
                reasons.append("Suspicious Multi-Subdomain Structure")

        # Only add proxy/unencrypted penalties when combined with a suspicious domain or non-trusted ISP
        if not is_trusted_isp:
            if port == 80 and score >= 40:
                score += 20
                reasons.append("Unencrypted HTTP Connection")
            elif port not in (80, 443) and score >= 40:
                score += 25
                reasons.append(f"Non-Standard Web Port ({port})")

            if geo_info.get("is_proxy") and score >= 40:
                score += 30
                reasons.append("Anonymizer / Proxy Relay")

        score = min(99, score)
        if score >= 60:
            reason_str = " + ".join(reasons) if reasons else "Suspicious Site Heuristics"
            return self._format_threat(score, reason_str)

        return {
            "is_malicious": False,
            "previously_blocked": False,
            "risk_score": score,
            "stars": "★★★★☆ (4/5) — NORMAL" if score >= 25 else "★★★★★ (5/5) — SAFE",
            "severity": "SAFE",
            "category": "Normal Web Traffic"
        }

    @staticmethod
    def _format_threat(score: int, reason: str) -> dict:
        if score >= 85:
            stars = "★☆☆☆☆ (1/5) — CRITICAL THREAT"
            severity = "CRITICAL"
        elif score >= 70:
            stars = "★★☆☆☆ (2/5) — HIGH RISK"
            severity = "HIGH RISK"
        else:
            stars = "★★☆☆☆ (2/5) — SUSPICIOUS"
            severity = "SUSPICIOUS"
        return {
            "is_malicious": True,
            "previously_blocked": False,
            "risk_score": score,
            "stars": stars,
            "severity": severity,
            "category": reason
        }


# --- Browser & Web App Action Controller (Close Site / Block Site) ---

def close_browser_or_site(pid: int, proc_name: str, domain: str = "") -> str:
    """
    Closes the malicious site in the browser or terminates the offending browser/web-app process.
    Works across Windows, macOS (Intel & M-chip), and Linux (LMDE/Debian).
    """
    sys_name = platform.system()
    pname = (proc_name or "").lower()

    # 1. On macOS, try closing the specific malicious tab first via AppleScript before killing the whole browser
    if sys_name == "Darwin" and domain:
        try:
            for app_label in ("Google Chrome", "Brave Browser", "Microsoft Edge"):
                if app_label.split()[0].lower() in pname:
                    script = f'''
                    tell application "{app_label}"
                        repeat with w in windows
                            set tabIndex to 1
                            repeat with t in tabs of w
                                if (URL of t contains "{domain}") then
                                    close t
                                    return "Closed malicious tab in {app_label}"
                                end if
                                set tabIndex to tabIndex + 1
                            end repeat
                        end repeat
                        if (count of windows) > 0 then
                            close active tab of front window
                            return "Closed active tab in {app_label}"
                        end if
                    end tell
                    '''
                    res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=2)
                    if res.returncode == 0 and res.stdout.strip():
                        return res.stdout.strip()
        except Exception:
            pass

    # 2. Terminate the browser / web app process tree via psutil (reliable on Windows, macOS, and Linux)
    if pid and pid > 0:
        try:
            proc = psutil.Process(pid)
            actual_name = proc.name()
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                proc.kill()
            return f"Closed {actual_name} (PID {pid})"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 3. Fallback by process name if PID already rotated
    if proc_name and proc_name not in ("System Test", "Unknown"):
        closed_count = 0
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == pname:
                    p.terminate()
                    closed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if closed_count > 0:
            return f"Closed {proc_name} ({closed_count} process(es))"

    return "Closed site session"


# --- 5-Second Interactive On-Screen Notification Popup ---

class ThreatNotificationPopup(QWidget):
    """
    Sleek 5-second on-screen alert near the system clock with:
      - Site / Domain, Browser/Web App, Threat Rating & Score
      - [ ✕ Close Site ] and [ 🚫 Block Site ] interactive buttons
      - Live 5-second countdown bar (pauses if hovered so the user can click comfortably)
    """
    action_triggered = pyqtSignal(str, dict)  # ("closed" | "blocked", event_data)

    def __init__(self, event_data: dict, duration_ms: int = NOTIFICATION_MS):
        super().__init__(None)
        self.event_data = event_data
        self.duration_ms = duration_ms
        self.remaining_ms = duration_ms
        self.is_hovered = False

        # Frameless, always-on-top tool notification window that does not steal keyboard focus
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedSize(455, 220)

        self._build_ui()
        self._position_near_clock()

        # 5-second countdown timer (ticks every 50ms for smooth progress bar)
        self.tick_interval = 50
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_tick)
        self.timer.start(self.tick_interval)

    def _build_ui(self):
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)

        self.card = QWidget(self)
        self.card.setObjectName("RedEyeCard")
        is_mal = self.event_data.get("is_malicious", True)
        border_col = BORDER_RED if is_mal else "#00d2ff"

        self.card.setStyleSheet(f"""
            QWidget#RedEyeCard {{
                background-color: {CARD_BG};
                border: 2px solid {border_col};
                border-radius: 12px;
            }}
            QLabel {{
                color: {TEXT_WHITE};
                background: transparent;
                border: none;
            }}
        """)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(24)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(255, 0, 51, 110) if is_mal else QColor(0, 0, 0, 160))
        self.card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(6)

        # Row 1: Red Eye Icon + Alert Header + Severity Badge + Dismiss '×'
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        eye_lbl = QLabel()
        eye_lbl.setPixmap(create_red_eye_Pixmap(28, alert_active=is_mal))
        eye_lbl.setFixedSize(28, 28)
        header_row.addWidget(eye_lbl)

        severity = self.event_data.get("severity", "HIGH RISK")
        header_title = "MALICIOUS SITE DETECTED" if is_mal else "SITE RATING CHECK"
        title_lbl = QLabel(f"<b>{header_title}</b>")
        title_lbl.setStyleSheet(f"color: {'#ff3355' if is_mal else '#00e5ff'}; font-size: 13px; letter-spacing: 0.5px;")
        header_row.addWidget(title_lbl)

        header_row.addStretch()

        badge_lbl = QLabel(f" {severity} ({self.event_data.get('risk_score', 90)}/100) ")
        badge_lbl.setStyleSheet(
            f"background-color: {'#4d0011' if is_mal else '#003344'}; "
            f"color: {'#ff6680' if is_mal else '#66f0ff'}; "
            f"border: 1px solid {border_col}; border-radius: 5px; "
            f"font-size: 10px; font-weight: bold; padding: 2px 5px;"
        )
        header_row.addWidget(badge_lbl)

        dismiss_btn = QPushButton("✕")
        dismiss_btn.setFixedSize(20, 20)
        dismiss_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        dismiss_btn.setStyleSheet("""
            QPushButton {
                background: transparent; color: #8b95a5; border: none; font-size: 13px; font-weight: bold;
            }
            QPushButton:hover { color: #ffffff; }
        """)
        dismiss_btn.clicked.connect(self.close)
        header_row.addWidget(dismiss_btn)

        card_layout.addLayout(header_row)

        # Row 2: Domain / Site & IP
        domain_display = self.event_data.get("domain") or self.event_data.get("ip", "Unknown Site")
        ip_display = self.event_data.get("ip", "")
        site_text = f"{domain_display}  [{ip_display}]" if domain_display != ip_display else domain_display
        site_lbl = QLabel(site_text)
        site_lbl.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold;")
        site_lbl.setWordWrap(True)
        card_layout.addWidget(site_lbl)

        # Row 3: Rating & Threat Category + Browser/Web App
        stars = self.event_data.get("stars", "★☆☆☆☆ (1/5)")
        category = self.event_data.get("category", "Suspicious Web Activity")
        browser = self.event_data.get("process", "Browser")
        location = self.event_data.get("location", "Unknown Location")

        rating_lbl = QLabel(f"Rating: <b style='color:#ffcc00;'>{stars}</b>")
        rating_lbl.setStyleSheet("font-size: 11.5px; color: #e2e8f0;")
        card_layout.addWidget(rating_lbl)

        details_lbl = QLabel(f"Reason: {category}\nApp: {browser} (PID {self.event_data.get('pid', '-')}) • {location}")
        details_lbl.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED};")
        card_layout.addWidget(details_lbl)

        card_layout.addStretch()

        # Row 4: Action Buttons — [ ✕ Close Site ] and [ 🚫 Block Site ]
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.close_site_btn = QPushButton("✕  Close Site (Kill Browser)")
        self.close_site_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_site_btn.setFixedHeight(32)
        self.close_site_btn.setStyleSheet("""
            QPushButton {
                background-color: #262c3a;
                color: #ffffff;
                border: 1px solid #ff9900;
                border-radius: 6px;
                font-size: 11.5px;
                font-weight: bold;
                padding: 4px 10px;
            }
            QPushButton:hover {
                background-color: #ff9900;
                color: #0d0f14;
            }
        """)
        self.close_site_btn.clicked.connect(self._handle_close_site)
        btn_row.addWidget(self.close_site_btn)

        self.block_site_btn = QPushButton("🚫  Block && Close Site")
        self.block_site_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.block_site_btn.setFixedHeight(32)
        self.block_site_btn.setStyleSheet("""
            QPushButton {
                background-color: #cc0029;
                color: #ffffff;
                border: 1px solid #ff3355;
                border-radius: 6px;
                font-size: 11.5px;
                font-weight: bold;
                padding: 4px 10px;
            }
            QPushButton:hover {
                background-color: #ff0033;
                border-color: #ffffff;
            }
        """)
        self.block_site_btn.clicked.connect(self._handle_block_site)
        btn_row.addWidget(self.block_site_btn)

        card_layout.addLayout(btn_row)

        # Row 5: 5-Second Countdown Progress Bar
        self.progress = QProgressBar()
        self.progress.setRange(0, self.duration_ms)
        self.progress.setValue(self.duration_ms)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: #1e2430;
                border-radius: 2px;
                border: none;
            }}
            QProgressBar::chunk {{
                background-color: {border_col};
                border-radius: 2px;
            }}
        """)
        card_layout.addWidget(self.progress)

        outer_layout.addWidget(self.card)

    def _position_near_clock(self):
        """Positions the notification popup right near the system clock across Windows, macOS, and Linux."""
        screen = QApplication.primaryScreen()
        if not screen:
            return
        avail = screen.availableGeometry()
        margin = 14

        # On macOS, the clock is in the top-right menu bar.
        # On Windows and most Linux desktops (LMDE Cinnamon/MATE), the clock is bottom-right (or top-right).
        if platform.system() == "Darwin":
            x = avail.right() - self.width() - margin
            y = avail.top() + margin
        else:
            x = avail.right() - self.width() - margin
            y = avail.bottom() - self.height() - margin

        self.move(max(0, x), max(0, y))

    def enterEvent(self, event):
        self.is_hovered = True
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.is_hovered = False
        super().leaveEvent(event)

    def _on_tick(self):
        if self.is_hovered:
            return
        self.remaining_ms -= self.tick_interval
        if self.remaining_ms <= 0:
            self.timer.stop()
            self.close()
        else:
            self.progress.setValue(self.remaining_ms)

    def _handle_close_site(self):
        self.timer.stop()
        self.action_triggered.emit("closed", self.event_data)
        self.close()

    def _handle_block_site(self):
        self.timer.stop()
        self.action_triggered.emit("blocked", self.event_data)
        self.close()


# --- Background Browser & Web App Connection Monitor ---

class BrowserSiteMonitor(QThread):
    site_detected = pyqtSignal(dict)

    def __init__(self, intel_engine: ThreatIntelligenceEngine):
        super().__init__()
        self.intel = intel_engine
        self.resolver = DomainResolver()
        self.seen_sessions = {}   # (ip, pid) -> timestamp
        self.running = True

    def run(self):
        # Initial silent baseline scan
        self.scan_connections(initial=True)
        while self.running:
            self.scan_connections(initial=False)
            time.sleep(CHECK_INTERVAL)

    @staticmethod
    def is_browser_or_webapp(proc_name: str, remote_port: int) -> bool:
        if not proc_name:
            return False
        pname = proc_name.lower()
        if pname in SYSTEM_IGNORE_PROCESSES:
            return False
        if any(k in pname for k in BROWSER_PROCESS_KEYWORDS):
            return True
        return False

    def scan_connections(self, initial: bool = False):
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return

        my_pid = os.getpid()
        now = time.time()
        # Expire seen sessions older than 90 seconds so revisiting a malicious site warns again
        expired = [k for k, ts in self.seen_sessions.items() if now - ts > 90.0]
        for k in expired:
            self.seen_sessions.pop(k, None)

        for conn in connections:
            try:
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                ip = conn.raddr.ip
                rport = conn.raddr.port
                pid = conn.pid or 0

                if pid == my_pid:
                    continue

                if not ip or ip in ("*", "0.0.0.0", "::1") or ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                    continue
                # Filter RFC1918 172.16.0.0/12 private range
                if ip.startswith("172."):
                    parts = ip.split(".")
                    if len(parts) == 4 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                        continue

                proc_name = "Web App"
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                if not self.is_browser_or_webapp(proc_name, rport):
                    continue

                session_key = (ip, pid)
                if session_key in self.seen_sessions:
                    continue
                self.seen_sessions[session_key] = now

                if not initial:
                    threading.Thread(
                        target=self.inspect_connection,
                        args=(ip, rport, pid, proc_name),
                        daemon=True
                    ).start()
            except Exception:
                continue

    def inspect_connection(self, ip: str, rport: int, pid: int, proc_name: str):
        domain = self.resolver.resolve_ip(ip)
        geo = get_ip_geo_and_isp(ip)
        rating = self.intel.evaluate_site(domain, ip, geo, port=rport)

        event_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time": datetime.now().strftime("%H:%M:%S"),
            "domain": domain or ip,
            "ip": ip,
            "port": rport,
            "pid": pid,
            "process": proc_name,
            "location": geo["location"],
            "org": geo["org"],
            "is_malicious": rating["is_malicious"],
            "previously_blocked": rating["previously_blocked"],
            "risk_score": rating["risk_score"],
            "stars": rating["stars"],
            "severity": rating["severity"],
            "category": rating["category"],
            "action_taken": "Auto-Blocked" if rating["previously_blocked"] else "Warned (5s Notification)"
        }
        self.site_detected.emit(event_data)


# --- Main RedEye System Tray Application ---

class RedEyeApp(QApplication):
    def __init__(self, args):
        super().__init__(args)

        # Hide Dock icon on macOS (Intel & Apple Silicon M-series) so RedEye sits silently near the clock
        if HAS_MACOS_APPKIT:
            try:
                ns_app = NSApplication.sharedApplication()
                ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
            except Exception as e:
                print(f"[RedEye] macOS ActivationPolicy warning: {e}")

        self.setApplicationName(APP_NAME)
        self.setApplicationVersion(APP_VERSION)
        self.setQuitOnLastWindowClosed(False)

        # Paths
        self.app_dir = Path(__file__).resolve().parent
        self.data_dir = Path.home() / ".redeye"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # CSV log path (both in user home and app folder for convenience)
        self.csv_log_file = Path.home() / "redeye_malicious_sites.csv"
        self.local_csv_copy = self.app_dir / "redeye_malicious_sites.csv"

        # Save icon files for OS shortcuts/launchers
        self._export_icon_assets()

        # Threat Intelligence Engine
        self.intel = ThreatIntelligenceEngine(self.data_dir)
        self.intel.update_threat_feeds_async(on_done_callback=self._on_feeds_updated)

        # State
        self.malicious_only_mode = True   # Silent mode: only warn when malicious/suspicious site is opened
        self.history = []
        self.active_popups = []

        # Ensure CSV has header row ready
        self._ensure_csv_header()

        # System Tray Setup (Red Eye icon near the clock)
        self.tray = QSystemTrayIcon(self)
        self.normal_icon = create_red_eye_icon(alert_active=False)
        self.alert_icon = create_red_eye_icon(alert_active=True)
        self.setWindowIcon(self.normal_icon)
        self.tray.setIcon(self.normal_icon)
        self.tray.setToolTip("RedEye — Malicious Site & Web App Shield (Silent Mode)")

        self.menu = QMenu()
        self.update_tray_menu()
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        # Start Background Browser & Web App Monitor
        self.monitor = BrowserSiteMonitor(self.intel)
        self.monitor.site_detected.connect(self.handle_site_detected)
        self.monitor.start()

        print(f"[RedEye] Running silently near the system clock. CSV Log: {self.csv_log_file}")

        # Optional CLI flag `--test` to pop up a 5-second demonstration alert 1.5s after launch
        if "--test" in args:
            QTimer.singleShot(1500, self.trigger_test_malicious_alert)

    def _export_icon_assets(self):
        try:
            png_path = self.app_dir / "redeye_icon.png"
            ico_path = self.app_dir / "redeye.ico"
            pix = create_red_eye_Pixmap(128, alert_active=False)
            pix.save(str(png_path), "PNG")
            pix.save(str(ico_path), "ICO")
        except Exception:
            pass

    def _on_feeds_updated(self, domain_count: int, ip_count: int):
        print(f"[RedEye] Threat feeds ready: {domain_count} malicious domains, {ip_count} malicious IPs indexed.")

    def _ensure_csv_header(self):
        headers = [
            "Timestamp", "Site_Domain", "IP_Address", "Browser_WebApp",
            "PID", "Threat_Rating", "Risk_Score", "Category_Reason",
            "Location", "ISP_Org", "Action_Taken"
        ]
        for path in (self.csv_log_file, self.local_csv_copy):
            try:
                if not path.exists():
                    with open(path, mode="w", newline="", encoding="utf-8") as f:
                        csv.writer(f).writerow(headers)
            except Exception:
                pass

    def log_malicious_site_to_csv(self, data: dict):
        """Records every accessed malicious site and user action into the CSV log."""
        row = [
            data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            data.get("domain", "Unknown"),
            data.get("ip", "Unknown"),
            data.get("process", "Browser"),
            data.get("pid", 0),
            data.get("stars", "★☆☆☆☆ (1/5)"),
            f"{data.get('risk_score', 90)}/100",
            data.get("category", "Malicious Site"),
            data.get("location", "Unknown"),
            data.get("org", "Unknown ISP"),
            data.get("action_taken", "Warned")
        ]
        for path in (self.csv_log_file, self.local_csv_copy):
            try:
                with open(path, mode="a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow(row)
            except Exception as e:
                print(f"[RedEye] CSV write error ({path}): {e}")
        self.sync_to_cloud()

    def sync_to_cloud(self):
        """Syncs the malicious sites CSV log to rclone remote (Duo_2026-09-10:redeye/)."""
        def sync_task():
            try:
                if shutil.which("rclone"):
                    subprocess.run(
                        ["rclone", "copy", str(self.csv_log_file), "Duo_2026-09-10:redeye/"],
                        check=False, timeout=15
                    )
            except Exception as e:
                print(f"[RedEye] rclone sync warning: {e}")

        threading.Thread(target=sync_task, daemon=True).start()

    def handle_site_detected(self, data: dict):
        is_mal = data.get("is_malicious", False)

        # If previously blocked by the user, immediately close the site & notify
        if data.get("previously_blocked"):
            close_msg = close_browser_or_site(data.get("pid", 0), data.get("process", ""), data.get("domain", ""))
            data["action_taken"] = f"Auto-Blocked & {close_msg}"

        # In silent mode (default), ignore safe sites completely and only warn/log on malicious sites
        if self.malicious_only_mode and not is_mal:
            return

        if is_mal:
            # 1. Record to CSV Log
            self.log_malicious_site_to_csv(data)

            # 2. Add to Tray Menu History
            self.history.insert(0, data)
            if len(self.history) > MAX_MENU_HISTORY:
                self.history.pop()
            self.update_tray_menu()

            # 3. Pulse Red Eye tray icon
            self.tray.setIcon(self.alert_icon)
            QTimer.singleShot(NOTIFICATION_MS, lambda: self.tray.setIcon(self.normal_icon))

        # 4. Show 5-Second On-Screen Notification with Rating + [Close Site] & [Block Site] buttons
        self.show_5s_notification(data)

    def show_5s_notification(self, data: dict):
        popup = ThreatNotificationPopup(data, duration_ms=NOTIFICATION_MS)
        popup.action_triggered.connect(self.handle_notification_action)
        popup.destroyed.connect(lambda: self._cleanup_popup(popup))
        self.active_popups.append(popup)
        popup.show()

    def _cleanup_popup(self, popup):
        if popup in self.active_popups:
            self.active_popups.remove(popup)

    def handle_notification_action(self, action: str, data: dict):
        domain = data.get("domain", "")
        ip = data.get("ip", "")
        pid = data.get("pid", 0)
        proc_name = data.get("process", "")

        if action == "closed":
            result_msg = close_browser_or_site(pid, proc_name, domain)
            data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data["action_taken"] = f"USER CLOSED SITE ({result_msg})"
            self.log_malicious_site_to_csv(data)
            self.tray.showMessage(
                "RedEye — Site Closed",
                f"Closed {domain} ({result_msg})",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )

        elif action == "blocked":
            hosts_applied = self.intel.add_to_blocklist(domain, ip)
            result_msg = close_browser_or_site(pid, proc_name, domain)
            hosts_note = " + System Hosts Blocked" if hosts_applied else " + Added to RedEye Blocklist"
            data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data["action_taken"] = f"USER BLOCKED & CLOSED ({result_msg}{hosts_note})"
            self.log_malicious_site_to_csv(data)
            self.update_tray_menu()
            self.tray.showMessage(
                "RedEye — Site Permanently Blocked",
                f"Blocked {domain} [{ip}] and closed browser ({result_msg}).",
                QSystemTrayIcon.MessageIcon.Warning,
                4000
            )

    def trigger_test_malicious_alert(self):
        """Simulates accessing a malicious phishing site so the user can test the 5s popup and buttons."""
        sample_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time": datetime.now().strftime("%H:%M:%S"),
            "domain": "verify-wallet-connect-sync.com",
            "ip": "185.220.101.4",
            "port": 443,
            "pid": 0,
            "process": "Browser Simulation (Test)",
            "location": "Frankfurt, Germany",
            "org": "Bulletproof Hosting ASN",
            "is_malicious": True,
            "previously_blocked": False,
            "risk_score": 96,
            "stars": "★☆☆☆☆ (1/5) — CRITICAL THREAT",
            "severity": "CRITICAL",
            "category": "Phishing / Malware Distribution",
            "action_taken": "Warned (Test Alert)"
        }
        self.handle_site_detected(sample_data)

    def update_tray_menu(self):
        self.menu.clear()

        header = self.menu.addAction("👁️ REDEYE MALICIOUS SITE SHIELD")
        header.setEnabled(False)
        self.menu.addSeparator()

        # Test 5-Second Alert Button
        test_action = self.menu.addAction("🚨 Test 5s Malicious Site Alert")
        test_action.triggered.connect(self.trigger_test_malicious_alert)

        # View CSV Log
        csv_action = self.menu.addAction("📂 View Malicious Sites Log (CSV)")
        csv_action.triggered.connect(self.open_csv_log)

        # Mode Toggle
        mode_action = self.menu.addAction("🔇 Silent Mode (Malicious Sites Only)")
        mode_action.setCheckable(True)
        mode_action.setChecked(self.malicious_only_mode)
        mode_action.triggered.connect(self.toggle_silent_mode)

        # Blocked Sites Submenu
        block_menu = self.menu.addMenu(
            f"🚫 Blocked Sites ({len(self.intel.user_blocked_domains) + len(self.intel.user_blocked_ips)})"
        )
        add_block_act = block_menu.addAction("➕ Block a Domain or IP Manually...")
        add_block_act.triggered.connect(self.prompt_manual_block)
        block_menu.addSeparator()

        all_blocked = sorted(list(self.intel.user_blocked_domains)) + sorted(list(self.intel.user_blocked_ips))
        if not all_blocked:
            empty_b = block_menu.addAction("No custom blocked sites yet")
            empty_b.setEnabled(False)
        else:
            for item in all_blocked[:25]:
                unblock_act = block_menu.addAction(f"🔓 Unblock {item}")
                unblock_act.triggered.connect(lambda checked=False, target=item: self.unblock_site(target))

        # Refresh Threat Feeds
        refresh_action = self.menu.addAction("🔄 Update Threat Intelligence Feeds")
        refresh_action.triggered.connect(
            lambda: self.intel.update_threat_feeds_async(on_done_callback=self._on_feeds_updated)
        )

        self.menu.addSeparator()
        hist_header = self.menu.addAction("RECENT MALICIOUS DETECTIONS")
        hist_header.setEnabled(False)

        if not self.history:
            none_act = self.menu.addAction("✓ No malicious sites detected")
            none_act.setEnabled(False)
        else:
            for item in self.history:
                label = (
                    f"⚠️ [{item['time']}] {item['domain']} "
                    f"({item['risk_score']}/100) — {item['process']}"
                )
                act = self.menu.addAction(label)
                act.triggered.connect(lambda checked=False, d=item: self.show_5s_notification(d))

        self.menu.addSeparator()
        quit_action = self.menu.addAction("Quit RedEye")
        quit_action.triggered.connect(self.quit_app)

    def toggle_silent_mode(self, checked: bool):
        self.malicious_only_mode = checked
        mode_label = "Silent Mode (Malicious Sites Only)" if checked else "All Sites Rating Mode"
        self.tray.setToolTip(f"RedEye — {mode_label}")

    def prompt_manual_block(self):
        text, ok = QInputDialog.getText(
            None,
            "RedEye — Block Malicious Site",
            "Enter a domain (e.g. badsite.xyz) or IP address to block permanently:"
        )
        if ok and text.strip():
            target = text.strip().lower()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                self.intel.add_to_blocklist("", target)
            else:
                self.intel.add_to_blocklist(target, "")
            self.update_tray_menu()

    def unblock_site(self, target: str):
        self.intel.remove_from_blocklist(target)
        self.update_tray_menu()

    def open_csv_log(self):
        self._ensure_csv_header()
        target = self.csv_log_file if self.csv_log_file.exists() else self.local_csv_copy
        try:
            sys_name = platform.system()
            if sys_name == "Windows":
                os.startfile(str(target))
            elif sys_name == "Darwin":
                subprocess.run(["open", str(target)], check=False)
            else:
                subprocess.run(["xdg-open", str(target)], check=False)
        except Exception as e:
            print(f"[RedEye] Could not open CSV log: {e}")

    def quit_app(self):
        self.monitor.running = False
        self.monitor.wait(1500)
        super().quit()


if __name__ == "__main__":
    app = RedEyeApp(sys.argv)
    sys.exit(app.exec())
