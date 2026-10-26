#!/usr/bin/env bash
# RedEye Installer for Linux LMDE (Linux Mint Debian Edition) and all Debian/Ubuntu-based OS
set -e

DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "==================================================================="
echo "  Installing RedEye for Linux (LMDE / Debian / Ubuntu / Mint)"
echo "==================================================================="

if command -v apt-get >/dev/null 2>&1; then
    echo "📦 Installing required Debian/LMDE system packages for PyQt6 & System Tray..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        python3 \
        python3-venv \
        python3-pip \
        python3-pyqt6 \
        libxcb-cursor0 \
        xdotool \
        xdg-utils
fi

VENV_PATH="$DIR/.redeye_venv"
# Use --system-site-packages so Debian's native python3-pyqt6 works on all architectures (x86_64, arm64)
python3 -m venv --system-site-packages "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip
"$VENV_PATH/bin/pip" install psutil requests PyQt6 || "$VENV_PATH/bin/pip" install psutil requests

chmod +x "$DIR/redeye"
chmod +x "$DIR/redeye_app.py"

# Generate icon for Desktop entry
"$VENV_PATH/bin/python3" -c "import sys; sys.path.insert(0, '$DIR'); import redeye_app; from PyQt6.QtWidgets import QApplication; app = QApplication([]); redeye_app.create_red_eye_Pixmap(128).save('$DIR/redeye_icon.png', 'PNG')" 2>/dev/null || true

# Create XDG Autostart & Application Launcher for Cinnamon (LMDE), MATE, XFCE, GNOME, KDE
AUTOSTART_DIR="$HOME/.config/autostart"
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$AUTOSTART_DIR" "$APPS_DIR"

DESKTOP_CONTENT="[Desktop Entry]
Type=Application
Name=RedEye Web Shield
Comment=Silent Malicious Site & Web App Monitor near the system clock
Exec=$DIR/redeye
Icon=$DIR/redeye_icon.png
Terminal=false
Categories=Security;Network;Utility;
StartupNotify=false
X-GNOME-Autostart-enabled=true
"

echo "$DESKTOP_CONTENT" > "$AUTOSTART_DIR/redeye.desktop"
echo "$DESKTOP_CONTENT" > "$APPS_DIR/redeye.desktop"
chmod +x "$AUTOSTART_DIR/redeye.desktop" "$APPS_DIR/redeye.desktop"

# Start RedEye with a 5s test alert
"$DIR/redeye" --test

echo "✅ RedEye is now installed and running near your system clock on Linux!"
