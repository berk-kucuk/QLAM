#!/usr/bin/env bash
# Qlam Uninstaller
set -euo pipefail

INSTALL_DIR="$HOME/.local/share/Qlam"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"

echo "Removing Qlam..."
rm -rf "$INSTALL_DIR"
rm -f  "$BIN_DIR/qlam"
rm -f  "$DESKTOP_DIR/qlam.desktop"
rm -f  "$ICON_DIR/qlam.png"
rm -f  "$HOME/.local/share/pixmaps/qlam.png"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
echo "Qlam removed."
