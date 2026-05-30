#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Qlam Installer — Arch, Debian/Ubuntu, Fedora/RHEL, openSUSE
# ─────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/share/Qlam"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[Qlam]${NC} $*"; }
ok()      { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect distro ─────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID_LIKE:-$ID}"
    elif command -v pacman &>/dev/null; then echo "arch"
    elif command -v apt-get &>/dev/null; then echo "debian"
    elif command -v dnf    &>/dev/null; then echo "fedora"
    else echo "unknown"; fi
}

# ── Install system deps ───────────────────────────────────────
install_system_deps() {
    local distro
    distro=$(detect_distro)
    info "Detected distro family: $distro"

    case "$distro" in
        *arch*)
            info "Installing system packages via pacman..."
            sudo pacman -Sy --needed --noconfirm python python-pip clamav polkit 2>/dev/null \
                || warn "Some packages may already be installed."
            ;;
        *debian*|*ubuntu*)
            info "Installing system packages via apt..."
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv \
                clamav clamav-freshclam policykit-1 \
                libgl1 libxcb-xinerama0 libxcb-cursor0 2>/dev/null \
                || warn "Some packages may already be installed."
            ;;
        *fedora*|*rhel*|*centos*)
            info "Installing system packages via dnf..."
            sudo dnf install -y python3 python3-pip clamav clamav-update \
                polkit mesa-libGL xcb-util-cursor 2>/dev/null \
                || warn "Some packages may already be installed."
            ;;
        *suse*|*opensuse*)
            info "Installing system packages via zypper..."
            sudo zypper install -y python3 python3-pip clamav polkit \
                libGL1 libxcb-cursor0 2>/dev/null \
                || warn "Some packages may already be installed."
            ;;
        *)
            warn "Unknown distro — skipping system package install."
            warn "Make sure python3, clamav and polkit are installed."
            ;;
    esac
}

# ── Find Python 3.10+ ──────────────────────────────────────────
find_python() {
    local candidates=(python3 python3.14 python3.13 python3.12 python3.11 python3.10 python)
    local bin ver major minor
    for bin in "${candidates[@]}"; do
        bin=$(command -v "$bin" 2>/dev/null) || continue
        ver=$("$bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || continue
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            # Print ONLY the path — callers capture this
            echo "$bin"
            return 0
        fi
    done
    return 1
}

# ── Create venv + install packages ────────────────────────────
setup_venv() {
    local python="$1"
    local venv="$INSTALL_DIR/venv"
    info "Creating virtual environment..."
    "$python" -m venv "$venv"
    info "Upgrading pip..."
    "$venv/bin/pip" install --upgrade pip -q
    info "Installing Python packages (PyQt6, pyclamd, watchdog, qtawesome)..."
    "$venv/bin/pip" install PyQt6 pyclamd watchdog qtawesome -q
    ok "Virtual environment ready."
}

# ── Copy app files ─────────────────────────────────────────────
copy_files() {
    info "Copying application files..."
    mkdir -p "$INSTALL_DIR"
    if command -v rsync &>/dev/null; then
        rsync -a \
            --exclude='venv/' \
            --exclude='__pycache__/' \
            --exclude='.git/' \
            --exclude='*.pyc' \
            --exclude='install.sh' \
            --exclude='uninstall.sh' \
            "$APP_DIR/" "$INSTALL_DIR/"
    else
        for item in main.py core ui resources Logos data; do
            [ -e "$APP_DIR/$item" ] && cp -r "$APP_DIR/$item" "$INSTALL_DIR/"
        done
    fi
    ok "Files copied."
}

# ── Launcher script ────────────────────────────────────────────
create_launcher() {
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/qlam" << LAUNCHER
#!/usr/bin/env bash
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/main.py" "\$@"
LAUNCHER
    chmod +x "$BIN_DIR/qlam"
    ok "Launcher: $BIN_DIR/qlam"
}

# ── Desktop entry + icon ───────────────────────────────────────
create_desktop() {
    local logo="$INSTALL_DIR/Logos/qlam.png"
    if [ -f "$logo" ]; then
        mkdir -p "$ICON_DIR" "$HOME/.local/share/pixmaps"
        cp "$logo" "$ICON_DIR/qlam.png"
        cp "$logo" "$HOME/.local/share/pixmaps/qlam.png"
        ok "Icon installed."
    fi

    mkdir -p "$DESKTOP_DIR"
    cat > "$DESKTOP_DIR/qlam.desktop" << DESKTOP
[Desktop Entry]
Name=Qlam
GenericName=Antivirus
Comment=ClamAV-powered antivirus
Exec=$BIN_DIR/qlam
Icon=qlam
Terminal=false
Type=Application
Categories=System;Security;
Keywords=antivirus;clamav;security;scan;
StartupNotify=true
StartupWMClass=Qlam
DESKTOP
    chmod +x "$DESKTOP_DIR/qlam.desktop"
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
    ok "Desktop entry created."
}

# ── PATH check ─────────────────────────────────────────────────
check_path() {
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "$BIN_DIR is not in your PATH."
        echo "  Add to ~/.bashrc or ~/.zshrc:"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# ── Main ──────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Qlam Antivirus — Installer      ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════╝${NC}"
    echo ""
    echo -e "Install location: ${CYAN}$INSTALL_DIR${NC}"
    if [ -t 0 ]; then
        read -rp "Continue? [Y/n] " confirm
        confirm="${confirm:-Y}"
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
        echo ""
    fi

    info "Step 1/5 — System dependencies..."
    install_system_deps

    info "Step 2/5 — Checking Python..."
    PYTHON_BIN=$(find_python) || die "Python 3.10+ not found. Install it first."
    PYTHON_VER=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    ok "Python $PYTHON_VER → $PYTHON_BIN"

    info "Step 3/5 — Copying application files..."
    copy_files

    info "Step 4/5 — Setting up virtual environment..."
    setup_venv "$PYTHON_BIN"

    info "Step 5/5 — Launcher & desktop entry..."
    create_launcher
    create_desktop
    check_path

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Qlam installed successfully!        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Run:  ${CYAN}qlam${NC}"
    echo -e "  Or open ${CYAN}Qlam${NC} from your app launcher"
    echo ""
}

main "$@"
