#!/usr/bin/env bash
# RedEye Installer for macOS (Supports both Intel x86_64 and Apple Silicon M1/M2/M3/M4 arm64)
set -e

DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ARCH="$(uname -m)"
echo "=========================================================="
echo "  Installing RedEye on macOS ($ARCH Architecture)"
echo "=========================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python 3 is required. Install via Homebrew (brew install python) or python.org."
    exit 1
fi

VENV_PATH="$DIR/.redeye_venv"
python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip
"$VENV_PATH/bin/pip" install -r "$DIR/requirements.txt"

chmod +x "$DIR/redeye"
chmod +x "$DIR/redeye_app.py"

# Create macOS LaunchAgent so RedEye starts automatically near the Menu Bar clock
PLIST_DIR="$HOME/Library/LaunchAgents"
mkdir -p "$PLIST_DIR"
PLIST_FILE="$PLIST_DIR/com.nelhorr.redeye.plist"

cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nelhorr.redeye</string>
    <key>ProgramArguments</key>
    <array>
        <string>$VENV_PATH/bin/python3</string>
        <string>$DIR/redeye_app.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>$HOME/redeye.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/redeye.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_FILE" 2>/dev/null || true
launchctl load "$PLIST_FILE"

echo "✅ RedEye installed and running in your macOS Menu Bar ($ARCH)!"
echo "👉 Run '$DIR/redeye --test' anytime to test the 5-second malicious site alert."
