#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Qlam Installer — works on Arch, Debian/Ubuntu, Fedora/RHEL
# ─────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="Qlam"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/share/Qlam"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[Qlam]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect distro ─────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${ID_LIKE:-$ID}"
    elif command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v dnf &>/dev/null; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

# ── Install system dependencies ───────────────────────────────
install_system_deps() {
    local distro
    distro=$(detect_distro)
    info "Detected distro family: $distro"

    case "$distro" in
        *arch*)
            info "Installing dependencies via pacman..."
            sudo pacman -Sy --needed --noconfirm \
                python python-pip clamav qt6-base \
                2>/dev/null || warn "Some packages may already be installed."
            ;;
        *debian*|*ubuntu*)
            info "Installing dependencies via apt..."
            sudo apt-get update -qq
            sudo apt-get install -y \
                python3 python3-pip python3-venv \
                clamav clamav-freshclam \
                libgl1 libxcb-xinerama0 libxcb-cursor0 \
                2>/dev/null || warn "Some packages may already be installed."
            ;;
        *fedora*|*rhel*|*centos*)
            info "Installing dependencies via dnf..."
            sudo dnf install -y \
                python3 python3-pip \
                clamav clamav-update \
                mesa-libGL xcb-util-cursor \
                2>/dev/null || warn "Some packages may already be installed."
            ;;
        *suse*|*opensuse*)
            info "Installing dependencies via zypper..."
            sudo zypper install -y \
                python3 python3-pip \
                clamav \
                libGL1 libxcb-cursor0 \
                2>/dev/null || warn "Some packages may already be installed."
            ;;
        *)
            warn "Unknown distro. Skipping system package installation."
            warn "Please ensure python3, pip, clamav are installed manually."
            ;;
    esac
}

# ── Check Python ──────────────────────────────────────────────
check_python() {
    local python_bin
    python_bin=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
    if [ -z "$python_bin" ]; then
        error "python3 not found. Please install Python 3.10 or newer."
    fi

    local version
    version=$("$python_bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 10 ]; }; then
        error "Python 3.10+ required (found $version)."
    fi
    success "Python $version found at $python_bin"
    echo "$python_bin"
}

# ── Set up venv ────────────────────────────────────────────────
setup_venv() {
    local python_bin="$1"
    local venv_dir="$INSTALL_DIR/venv"

    info "Creating virtual environment at $venv_dir ..."
    mkdir -p "$INSTALL_DIR"
    "$python_bin" -m venv "$venv_dir"
    success "Virtual environment created."

    info "Upgrading pip..."
    "$venv_dir/bin/pip" install --upgrade pip -q

    info "Installing Python dependencies..."
    "$venv_dir/bin/pip" install PyQt6 pyclamd watchdog qtawesome -q
    success "Python packages installed."

    echo "$venv_dir"
}

# ── Copy app files ─────────────────────────────────────────────
copy_files() {
    info "Copying application files to $INSTALL_DIR ..."
    mkdir -p "$INSTALL_DIR"

    # Copy everything except venv, __pycache__, .git
    rsync -a --exclude='venv' --exclude='__pycache__' \
              --exclude='.git' --exclude='*.pyc' \
              --exclude='install.sh' --exclude='uninstall.sh' \
              "$APP_DIR/" "$INSTALL_DIR/" \
        2>/dev/null || {
        # rsync not available — use cp
        cp -r "$APP_DIR"/{main.py,core,ui,resources,Logos,data} "$INSTALL_DIR/" 2>/dev/null || true
    }
    success "Files copied."
}

# ── Create launcher script ────────────────────────────────────
create_launcher() {
    local venv_dir="$1"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/qlam" << EOF
#!/usr/bin/env bash
# Qlam launcher
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/main.py" "\$@"
EOF
    chmod +x "$BIN_DIR/qlam"
    success "Launcher created at $BIN_DIR/qlam"
}

# ── Install icon ───────────────────────────────────────────────
install_icon() {
    local logo="$INSTALL_DIR/Logos/qlam.png"
    if [ -f "$logo" ]; then
        mkdir -p "$ICON_DIR"
        cp "$logo" "$ICON_DIR/qlam.png"
        # Also place in pixmaps for broader compatibility
        mkdir -p "$HOME/.local/share/pixmaps"
        cp "$logo" "$HOME/.local/share/pixmaps/qlam.png"
        success "Icon installed."
    else
        warn "Logo not found, skipping icon installation."
    fi
}

# ── Create .desktop file ──────────────────────────────────────
create_desktop_entry() {
    mkdir -p "$DESKTOP_DIR"
    cat > "$DESKTOP_DIR/qlam.desktop" << EOF
[Desktop Entry]
Name=Qlam
GenericName=Antivirus
Comment=ClamAV-powered antivirus with a modern interface
Exec=$BIN_DIR/qlam
Icon=qlam
Terminal=false
Type=Application
Categories=System;Security;
Keywords=antivirus;virus;malware;clamav;security;scan;
StartupNotify=true
StartupWMClass=Qlam
EOF
    chmod +x "$DESKTOP_DIR/qlam.desktop"
    success "Desktop entry created."

    # Update desktop database if available
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    # Update icon cache
    gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
}

# ── Add ~/.local/bin to PATH if needed ───────────────────────
ensure_path() {
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "$BIN_DIR is not in your PATH."
        warn "Add this to your ~/.bashrc or ~/.zshrc:"
        warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# ── Main ──────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Qlam Antivirus — Installer    ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════╝${NC}"
    echo ""

    # Ask for confirmation if not running non-interactively
    if [ -t 0 ]; then
        echo -e "This will install Qlam to ${CYAN}$INSTALL_DIR${NC}"
        read -rp "Continue? [Y/n] " confirm
        confirm=${confirm:-Y}
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
        echo ""
    fi

    info "Step 1/6 — Installing system dependencies..."
    install_system_deps

    info "Step 2/6 — Checking Python..."
    PYTHON_BIN=$(check_python)

    info "Step 3/6 — Setting up virtual environment..."
    VENV_DIR=$(setup_venv "$PYTHON_BIN")

    info "Step 4/6 — Copying application files..."
    copy_files

    # venv is inside INSTALL_DIR now, set it up again there
    if [ "$APP_DIR" != "$INSTALL_DIR" ]; then
        info "Setting up venv in install directory..."
        setup_venv "$PYTHON_BIN" > /dev/null
    fi

    info "Step 5/6 — Creating launcher and desktop entry..."
    create_launcher "$VENV_DIR"
    install_icon
    create_desktop_entry

    info "Step 6/6 — Final checks..."
    ensure_path

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Qlam installed successfully!        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Run:     ${CYAN}qlam${NC}"
    echo -e "  Or find: ${CYAN}Qlam${NC} in your application launcher"
    echo ""
}

main "$@"
