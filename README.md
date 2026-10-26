# 👁️ RedEye — Cross-Platform Malicious Site & Web App Shield

**Author:** `nelhorr` (`IOModule`)

**RedEye** is a lightweight, silent system-tray security monitor (inspired by `xcon`) that sits quietly near your system clock with a **Red Eye icon** and monitors browser & web-app traffic ausschließlich for **malicious websites, phishing lures, and untrusted web apps**.

---

## ✨ Key Features

- **👁️ Custom Glowing Red Eye Tray Icon**: Sits silently near the system clock (Windows Taskbar, macOS Menu Bar on Intel & Apple Silicon M-series without a Dock icon, and Linux LMDE / Debian system tray).
- **🔇 Silent Operation**: Runs quietly in the background and only alerts you when a malicious or high-risk website / web app is opened (or toggle *"All Sites Rating Mode"* from the tray menu).
- **⏱️ 5-Second Interactive On-Screen Notification**:
  - Displays the **Site / Domain & IP**, **Browser / Web App**, and **Threat Rating** (`★☆☆☆☆ (1/5) — CRITICAL`, Risk Score `0–100`).
  - Features a live **5-second countdown bar** (automatically pauses while your mouse hovers over the alert so you never miss clicking a button).
  - **`[ ✕ Close Site (Kill Browser) ]`**: Immediately closes the malicious tab or terminates the browser/web-app process.
  - **`[ 🚫 Block & Close Site ]`**: Permanently adds the domain & IP to the RedEye Blocklist (and OS `hosts` file when permitted) and immediately closes the site.
- **📄 Automatic CSV Audit Log (`~/redeye_malicious_sites.csv`)**:
  - Records every malicious site accessed along with `Timestamp`, `Site_Domain`, `IP_Address`, `Browser_WebApp`, `PID`, `Threat_Rating`, `Risk_Score`, `Category_Reason`, `Location`, `ISP_Org`, and `Action_Taken`.
- **🛡️ Multi-Source Threat Intelligence**:
  - Combines live feeds (**Abuse.ch URLhaus**, **OpenPhish**, **Feodo Tracker**) with heuristic phishing/homograph/TLD analysis and instant offline caching.

---

## 🚀 Platform Setup & Usage

### 1. Windows (Windows 10 / 11)
- **Quick Start**: Double-click `Launch_RedEye.bat` (or run `python redeye_app.py --test`).
- **Build Standalone `.exe`**: Run `build_windows.bat` to generate `windows-build\RedEye.exe`.

### 2. macOS (Intel `x86_64` & Apple Silicon `M1 / M2 / M3 / M4 arm64`)
```bash
chmod +x install_macos.sh redeye
./install_macos.sh
```
Or launch manually anytime:
```bash
./redeye --test
```

### 3. Linux (LMDE — Linux Mint Debian Edition & all Debian / Ubuntu-based OS)
```bash
chmod +x install_linux_debian.sh redeye
./install_linux_debian.sh
```
Or launch manually anytime:
```bash
./redeye --test
```
