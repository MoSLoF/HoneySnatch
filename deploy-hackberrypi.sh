#!/usr/bin/env bash
# =============================================================================
# deploy-hackberrypi.sh
# FlyingHoneySnitch — HackberryPi CM5 Deployment Script
#
# Target hardware: HackberryPi CM5 (ZitaoTech / Elecrow)
#   CPU : Raspberry Pi CM5, Quad-core Cortex-A76 ARMv8 64-bit @ 2.4 GHz
#   RAM : 4 / 8 / 16 GB
#   OS  : Kali Linux ARM64 (recommended) or Raspberry Pi OS 64-bit (Bookworm)
#   USB : 2x USB 3.0 (host only)
#   WiFi: On-board CYW43455 (2.4/5 GHz) — NO native monitor mode
#   M.2 : 2242 slot (NVMe SSD or Hailo AI card)
#   Disp: 4" 720x720 multitouch
#   Batt: 5000 mAh, ~3-4 hrs active scanning
#
# IMPORTANT CONSTRAINTS (read before running):
#   1. On-board WiFi CANNOT do monitor mode — you MUST plug in an external
#      USB monitor-mode adapter (e.g. Alfa AWUS036ACH, AWUS036ACHM, or
#      similar RTL8812AU / MT7612U chipset).
#   2. You only have 2 USB-A ports. Isolation testing (2 NICs) requires
#      a USB hub or two adapters (one per port).
#   3. gr-gsm and srsran packages may not be available as ARM64 debs —
#      this script will attempt apt first, then offer to build from source.
#   4. The 720x720 display needs a custom Qt scaling config for the GUI.
#   5. Run this script as root or with sudo.
#
# Usage:
#   chmod +x deploy-hackberrypi.sh
#   sudo ./deploy-hackberrypi.sh [--skip-apt] [--skip-python] [--skip-hostap]
#
# Options:
#   --skip-apt      Skip system package installation (already done)
#   --skip-python   Skip Python venv + pip install (already done)
#   --skip-hostap   Skip hostap build (no isolation testing needed)
#   --gui           Configure Qt display scaling for 720x720 screen
#   --dry-run       Print commands without executing
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

info()  { echo -e "${CYN}[FHS]${RST} $*"; }
ok()    { echo -e "${GRN}[OK ]${RST} $*"; }
warn()  { echo -e "${YEL}[WRN]${RST} $*"; }
error() { echo -e "${RED}[ERR]${RST} $*" >&2; }
die()   { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SKIP_APT=false
SKIP_PYTHON=false
SKIP_HOSTAP=false
CONFIGURE_GUI=false
DRY_RUN=false

for arg in "$@"; do
    case $arg in
        --skip-apt)    SKIP_APT=true ;;
        --skip-python) SKIP_PYTHON=true ;;
        --skip-hostap) SKIP_HOSTAP=true ;;
        --gui)         CONFIGURE_GUI=true ;;
        --dry-run)     DRY_RUN=true; warn "DRY RUN — commands will be printed, not executed" ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

run() {
    if $DRY_RUN; then
        echo -e "  ${YEL}CMD${RST}: $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "FlyingHoneySnitch — HackberryPi CM5 Deployment"
echo

[[ $EUID -eq 0 ]] || die "Must run as root (sudo ./deploy-hackberrypi.sh)"

# Confirm ARM64
ARCH=$(uname -m)
[[ "$ARCH" == "aarch64" ]] || warn "Expected aarch64 but got ${ARCH}. Continuing anyway."
ok "Architecture: ${ARCH}"

# Confirm OS
if grep -qi "kali" /etc/os-release 2>/dev/null; then
    OS_NAME="Kali Linux"
elif grep -qi "debian\|raspbian\|ubuntu" /etc/os-release 2>/dev/null; then
    OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
else
    OS_NAME="Unknown"
    warn "Unrecognised OS — continuing but apt packages may differ"
fi
ok "OS: ${OS_NAME}"

# Script must run from the repo root
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${REPO_DIR}/pyproject.toml" ]] || \
    die "Run this script from the FlyingHoneySnitch repo root"
ok "Repo root: ${REPO_DIR}"

# ---------------------------------------------------------------------------
# Step 1 — System packages
# ---------------------------------------------------------------------------
if ! $SKIP_APT; then
    info "Step 1 — Installing system packages"

    run apt-get update -qq

    # ---- Core scanning dependencies ----
    info "  Installing core wireless tools..."
    run apt-get install -y --no-install-recommends \
        iw rfkill wireless-tools net-tools aircrack-ng \
        build-essential pkg-config git curl wget \
        python3 python3-venv python3-dev python3-pip \
        libssl-dev libffi-dev

    # ---- Isolation testing (hostap build deps) ----
    info "  Installing hostap build dependencies..."
    run apt-get install -y --no-install-recommends \
        libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
        libdbus-1-dev macchanger dnsmasq tcpdump

    # ---- Bluetooth ----
    info "  Installing Bluetooth stack..."
    run apt-get install -y --no-install-recommends \
        bluetooth bluez libbluetooth-dev

    # ---- GPS ----
    info "  Installing gpsd..."
    run apt-get install -y --no-install-recommends \
        gpsd gpsd-clients python3-gps

    # ---- Kali-specific kernel headers ----
    # On Kali ARM64 for Pi, linux-headers-$(uname -r) does NOT work.
    # The correct packages are rpi-2712 (CM5/Pi5) and rpi-v8 (generic arm64).
    info "  Installing Raspberry Pi kernel headers..."
    KVER=$(uname -r)
    if apt-cache show linux-headers-rpi-2712 &>/dev/null; then
        run apt-get install -y linux-headers-rpi-2712 linux-headers-rpi-v8
        ok "Installed Kali ARM64 kernel headers (rpi-2712)"
    elif apt-cache show "linux-headers-${KVER}" &>/dev/null; then
        run apt-get install -y "linux-headers-${KVER}"
        ok "Installed kernel headers: ${KVER}"
    else
        warn "Could not find kernel headers — hostap build and DKMS drivers may fail"
        warn "Try: sudo apt install linux-headers-rpi-2712 linux-headers-rpi-v8"
    fi

    # ---- Cellular (apt — may not be available on ARM64) ----
    info "  Attempting cellular SDR packages (apt, may not be available on ARM64)..."
    CELLULAR_PKGS="hackrf rtl-sdr"
    for pkg in $CELLULAR_PKGS; do
        if apt-cache show "$pkg" &>/dev/null; then
            run apt-get install -y "$pkg"
            ok "  Installed: $pkg"
        else
            warn "  Not available via apt: $pkg (may need manual install)"
        fi
    done

    # gr-gsm and srsran often not packaged for ARM64 — warn and continue
    for pkg in gr-gsm srsran; do
        if apt-cache show "$pkg" &>/dev/null; then
            run apt-get install -y "$pkg"
            ok "  Installed: $pkg"
        else
            warn "  ${pkg} not available via apt on this ARM64 platform."
            warn "  CellGuard GSM/LTE scanning will require building from source."
            warn "  See: https://github.com/MoSLoF/FlyingHoneySnitch/wiki/ARM64-CellGuard"
        fi
    done

    # ---- Capability introspection ----
    run apt-get install -y --no-install-recommends libcap2-bin
    ok "Step 1 complete"
else
    info "Step 1 — Skipped (--skip-apt)"
fi

# ---------------------------------------------------------------------------
# Step 2 — Python virtual environment
# ---------------------------------------------------------------------------
if ! $SKIP_PYTHON; then
    info "Step 2 — Python environment"

    VENV_DIR="${REPO_DIR}/.venv"

    if [[ ! -d "$VENV_DIR" ]]; then
        info "  Creating virtual environment at ${VENV_DIR}..."
        run python3 -m venv "${VENV_DIR}"
    else
        ok "  Virtual environment already exists: ${VENV_DIR}"
    fi

    # Activate for the remainder of this script
    # shellcheck source=/dev/null
    if ! $DRY_RUN; then
        source "${VENV_DIR}/bin/activate"
    fi
    PYTHON="${VENV_DIR}/bin/python3"
    PIP="${VENV_DIR}/bin/pip"

    info "  Upgrading pip and setuptools..."
    run "${PYTHON}" -m pip install --upgrade pip setuptools wheel

    info "  Installing core requirements..."
    run "${PIP}" install -r "${REPO_DIR}/requirements.txt"

    info "  Installing optional requirements (GPS, Bluetooth, IMU)..."
    # Skip PyBluez on ARM64 — often fails to build; fall back to HCI tools
    run "${PIP}" install gpsd-py3 pyserial || warn "Some optional packages failed — continuing"

    # pyubertooth may need to be installed from source on ARM64
    if "${PIP}" install pyubertooth 2>/dev/null; then
        ok "  pyubertooth installed"
    else
        warn "  pyubertooth pip install failed — BlueScout will use HCI fallback"
        warn "  To build from source: git clone https://github.com/mikeryan/ubertooth && cd ubertooth/host/python && pip install -e ."
    fi

    info "  Installing FlyingHoneySnitch in editable mode..."
    run "${PIP}" install -e "${REPO_DIR}"

    ok "Step 2 complete"
else
    info "Step 2 — Skipped (--skip-python)"
    PYTHON="${REPO_DIR}/.venv/bin/python3"
fi

# ---------------------------------------------------------------------------
# Step 3 — Build hostap (AirSnitch isolation testing)
# ---------------------------------------------------------------------------
if ! $SKIP_HOSTAP; then
    info "Step 3 — Building hostap binaries (wpa_supplicant + hostapd)"

    VENDOR_DIR="${REPO_DIR}/vendor"
    HOSTAP_DIR="${VENDOR_DIR}/hostap_2_10"

    if [[ ! -d "$HOSTAP_DIR" ]]; then
        warn "  ${HOSTAP_DIR} not found — pulling git submodules first"
        run git -C "${REPO_DIR}" submodule init
        run git -C "${REPO_DIR}" submodule update
    fi

    WPA_BIN="${HOSTAP_DIR}/wpa_supplicant/wpa_supplicant"
    HOSTAPD_BIN="${HOSTAP_DIR}/hostapd/hostapd"

    if [[ -f "$WPA_BIN" && -f "$HOSTAPD_BIN" ]]; then
        ok "  Hostap binaries already built — skipping build"
        ok "    wpa_supplicant: ${WPA_BIN}"
        ok "    hostapd:        ${HOSTAPD_BIN}"
    else
        info "  Building in ${HOSTAP_DIR} (this takes ~3-5 mins on CM5)..."
        # Limit to 2 jobs to avoid thermal throttling the CM5 under load
        run bash "${VENDOR_DIR}/build.sh" hostap_2_10
        ok "  Build complete"
    fi

    if [[ -f "$WPA_BIN" ]] || $DRY_RUN; then
        ok "Step 3 complete"
    else
        error "Step 3 FAILED — isolation testing will not work"
        error "Check build output above. Common fix: sudo apt install libnl-3-dev libnl-genl-3-dev libdbus-1-dev"
    fi
else
    info "Step 3 — Skipped (--skip-hostap)"
fi

# ---------------------------------------------------------------------------
# Step 4 — External USB WiFi adapter check
# ---------------------------------------------------------------------------
info "Step 4 — WiFi adapter detection"
echo
warn "  ╔══════════════════════════════════════════════════════════════════╗"
warn "  ║  IMPORTANT: HackberryPi CM5 on-board WiFi CANNOT do monitor    ║"
warn "  ║  mode. You NEED an external USB WiFi adapter for fhs scan.     ║"
warn "  ║                                                                 ║"
warn "  ║  Recommended adapters (RTL8812AU / MT7612U chipset):           ║"
warn "  ║    • Alfa AWUS036ACH   (RTL8812AU — dual band, best for Pi)   ║"
warn "  ║    • Alfa AWUS036ACHM  (MT7612U  — good ARM64 driver support) ║"
warn "  ║    • Panda PAU09        (RT5572   — 2.4+5GHz, solid support)  ║"
warn "  ║                                                                 ║"
warn "  ║  For isolation testing (2 NICs): use a USB hub or plug both   ║"
warn "  ║  adapters into the two USB-A ports directly.                  ║"
warn "  ╚══════════════════════════════════════════════════════════════════╝"
echo

# List current wireless interfaces
info "  Current wireless interfaces:"
if ! $DRY_RUN; then
    if command -v iw &>/dev/null; then
        iw dev 2>/dev/null | grep -E "Interface|type" | sed 's/^/    /' || true
    fi
fi

# Check for monitor-capable external adapters
if ! $DRY_RUN; then
    USBREG=$(lsusb 2>/dev/null)
    if echo "$USBREG" | grep -qi "realtek\|ralink\|mediatek\|alfa"; then
        ok "  External USB WiFi adapter detected"
    else
        warn "  No recognised external USB WiFi adapter found"
        warn "  Passive scanning and isolation testing will not work without one"
    fi
fi

ok "Step 4 complete"

# ---------------------------------------------------------------------------
# Step 5 — Display configuration for 720x720 screen
# ---------------------------------------------------------------------------
if $CONFIGURE_GUI; then
    info "Step 5 — Configuring Qt display scaling for 720x720 screen"

    # Create Qt environment profile
    QT_ENV_FILE="/etc/profile.d/fhs-qt-display.sh"
    cat > "$QT_ENV_FILE" << 'EOF'
# FlyingHoneySnitch — Qt display config for HackberryPi CM5 (720x720)
export QT_SCALE_FACTOR=1.0
export QT_AUTO_SCREEN_SCALE_FACTOR=0
export QT_SCREEN_SCALE_FACTORS=1
export QT_FONT_DPI=120
# Force X11 backend (Wayland has issues with some Qt6 widgets on Pi)
export QT_QPA_PLATFORM=xcb
EOF
    ok "  Qt environment written to ${QT_ENV_FILE}"

    # Create a desktop launcher
    DESKTOP_DIR="/usr/share/applications"
    cat > "${DESKTOP_DIR}/fhs-gui.desktop" << EOF
[Desktop Entry]
Type=Application
Name=FlyingHoneySnitch
Comment=Wireless Discovery & Assessment Suite
Exec=bash -c 'source /etc/profile.d/fhs-qt-display.sh && ${REPO_DIR}/.venv/bin/fhs gui'
Icon=network-wireless
Terminal=false
Categories=Network;Security;
EOF
    ok "  Desktop launcher created: ${DESKTOP_DIR}/fhs-gui.desktop"
    ok "Step 5 complete"
else
    info "Step 5 — Skipped (pass --gui to configure 720x720 display scaling)"
fi

# ---------------------------------------------------------------------------
# Step 6 — sudoers rule for fhs (CAP_NET_RAW without full sudo)
# ---------------------------------------------------------------------------
info "Step 6 — Permissions"

FHS_BIN="${REPO_DIR}/.venv/bin/fhs"
PYTHON_BIN="${REPO_DIR}/.venv/bin/python3"

if ! $DRY_RUN && [[ -f "$PYTHON_BIN" ]]; then
    # Grant CAP_NET_RAW + CAP_NET_ADMIN to Python in the venv
    # This lets fhs scan run without full root on Kali
    if command -v setcap &>/dev/null; then
        setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" && \
            ok "  Set CAP_NET_RAW+CAP_NET_ADMIN on ${PYTHON_BIN}" || \
            warn "  setcap failed — fhs scan will require sudo"
    fi
else
    $DRY_RUN && run setcap cap_net_raw,cap_net_admin=eip "${PYTHON_BIN}"
fi

ok "Step 6 complete"

# ---------------------------------------------------------------------------
# Step 7 — Smoke test
# ---------------------------------------------------------------------------
info "Step 7 — Smoke test"

if ! $DRY_RUN && [[ -f "${REPO_DIR}/.venv/bin/python3" ]]; then
    info "  Running python smoke_test.py (no hardware needed)..."
    if "${REPO_DIR}/.venv/bin/python3" "${REPO_DIR}/smoke_test.py"; then
        ok "  Smoke test PASSED"
    else
        error "  Smoke test FAILED — check output above"
        warn "  The install may still be usable; some failures are expected without hardware"
    fi
else
    if $DRY_RUN; then
        run "${REPO_DIR}/.venv/bin/python3" "${REPO_DIR}/smoke_test.py"
    else
        warn "  .venv not found — skipping smoke test (run --skip-apt --skip-hostap first)"
    fi
fi

ok "Step 7 complete"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo -e "${BLD}${GRN}════════════════════════════════════════════════════════════════${RST}"
echo -e "${BLD}${GRN}  FlyingHoneySnitch — HackberryPi CM5 Deployment Complete${RST}"
echo -e "${BLD}${GRN}════════════════════════════════════════════════════════════════${RST}"
echo
echo -e "  ${BLD}Activate venv:${RST}   source ${REPO_DIR}/.venv/bin/activate"
echo -e "  ${BLD}System status:${RST}   fhs info"
echo -e "  ${BLD}WiFi scan:${RST}       sudo fhs scan start -i wlan1mon --5ghz"
echo -e "  ${BLD}BT scan:${RST}         sudo fhs bluetooth scan"
echo -e "  ${BLD}Simulate isolat:${RST} fhs isolation run-all -i wlan0 -j wlan1 --simulate"
echo -e "  ${BLD}Live isolation:${RST}  sudo fhs isolation run-all -i wlan1 -j wlan2 \\"
echo -e "                      --config ${REPO_DIR}/data/isolation/client.conf"
if $CONFIGURE_GUI; then
echo -e "  ${BLD}GUI:${RST}             source /etc/profile.d/fhs-qt-display.sh && fhs gui"
fi
echo
echo -e "  ${YEL}NOTE: wlan0 = on-board CM5 WiFi (no monitor mode)${RST}"
echo -e "  ${YEL}      wlan1 = first external USB adapter (monitor mode)${RST}"
echo -e "  ${YEL}      wlan2 = second USB adapter (isolation testing only)${RST}"
echo
echo -e "  ${CYN}Thermal tip: sustained scanning heats the CM5 quickly.${RST}"
echo -e "  ${CYN}Ensure the passive heatsink is seated and consider:${RST}"
echo -e "  ${CYN}  echo 'arm_freq=2000' >> /boot/config.txt   (gentle throttle)${RST}"
echo -e "  ${CYN}  watch -n1 vcgencmd measure_temp             (monitor temp)${RST}"
echo
