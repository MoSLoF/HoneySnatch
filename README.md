# FlyingHoneySnitch

Wireless Discovery, Assessment & Isolation Testing Suite.

**FlyingHoneyBadger** (passive wireless discovery) + **AirSnitch** (active client isolation testing) = **FlyingHoneySnitch**.

> **Origin:** A cross between FlyingHoneyBadger (DoD GOTS FlyingSquirrel lineage) and
> [AirSnitch](https://github.com/vanhoefm/airsnitch) (Mathy Vanhoef, NDSS '26).
> Built by [HoneyBadger Vanguard LLC](https://ihbv.io). `$global:Intent = 'Purple'`

---

## Components

| Module | Codename | Description |
|--------|----------|-------------|
| WiFi Scanner | **HoneyBadger Core** | Passive 802.11 packet capture, channel hopping, hidden SSID detection |
| RF Mapping | **WarrenMap** | Signal heatmaps, Folium/Leaflet maps, KML/Google Earth export |
| Analysis | **HoneyView** | Evil twin detection, pattern analysis, HTML reports |
| Monitoring | **SentryWeb** | Continuous rogue AP detection, encryption downgrade alerts, policy engine |
| Positioning | **BadgerTrack** | Indoor positioning via GPS + IMU sensor fusion |
| Bluetooth | **BlueScout** | Passive BT/BLE scanning — iBeacon, Eddystone, FindMy, RSSI proximity |
| Cellular | **CellGuard** | GSM/LTE/5G NR tower detection, IMSI catcher detection, rogue base station analysis |
| Isolation | **AirSnitch** | Client isolation vulnerability testing (GTK abuse, gateway bouncing, port stealing, broadcast reflection) |

---

## Installation

### 1. System packages (Linux — required for wireless operations)

```bash
# Core — WiFi scanning and isolation testing
sudo apt update
sudo apt install iw rfkill wireless-tools net-tools aircrack-ng \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
    libdbus-1-dev pkg-config build-essential macchanger dnsmasq tcpdump

# Cellular scanning (CellGuard)
sudo apt install gr-gsm rtl-sdr srsran hackrf modemmanager

# Bluetooth scanning (BlueScout)
sudo apt install bluetooth libbluetooth-dev ubertooth

# GPS (BadgerTrack)
sudo apt install gpsd gpsd-clients

# Encrypted database (optional)
sudo apt install libsqlcipher-dev
```

> See `requirements-linux.txt` for a full annotated list of every system package,
> grouped by module, with install-all one-liner.

---

### 2. Clone the repository

```bash
git clone https://github.com/MoSLoF/FlyingHoneySnitch.git
cd FlyingHoneySnitch
```

> **Note:** The repository uses Git submodules for `vendor/libwifi`.
> Pull them immediately after cloning:
>
> ```bash
> git submodule init
> git submodule update
> ```

---

### 3. Python environment

Requires **Python 3.10+**.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\Activate.ps1       # Windows (PowerShell)
```

---

### 4. Install Python dependencies

#### Minimal (WiFi scanning + isolation only):

```bash
pip install -r requirements.txt
```

#### Full (all modules — GUI, GPS, Bluetooth, Cellular, IMU):

```bash
pip install -r requirements.txt -r requirements-optional.txt
```

#### Editable install from pyproject.toml (equivalent to full):

```bash
pip install -e ".[all]"
```

#### Development (adds pytest, ruff, mypy):

```bash
pip install -e ".[dev,all]"
# or
pip install -r requirements.txt -r requirements-optional.txt -r requirements-dev.txt
```

> **Optional dependency groups** (install only what you need):
>
> | Group | Install | Requires |
> |-------|---------|---------|
> | `gui` | `pip install -e ".[gui]"` | — |
> | `gps` | `pip install -e ".[gps]"` | gpsd running |
> | `bluetooth` | `pip install -e ".[bluetooth]"` | libbluetooth-dev |
> | `cellular` | `pip install -e ".[cellular]"` | gr-gsm, srsran, hackrf |
> | `imu` | `pip install -e ".[imu]"` | /dev/ttyUSB0 accessible |
> | `encrypted_db` | `pip install -e ".[encrypted_db]"` | libsqlcipher-dev |

---

### 5. Build AirSnitch hostap binaries (isolation testing only)

The AirSnitch isolation tests require a modified hostapd / wpa_supplicant built from
`vendor/hostap_2_10/`. This step is only needed if you intend to run **live** isolation
tests against real wireless hardware. Simulation mode (`--simulate`) works without this.

```bash
cd vendor
bash build.sh            # defaults to hostap_2_10
# or explicitly:
bash build.sh hostap_2_10
```

Prerequisites: `build-essential libssl-dev libnl-3-dev libnl-genl-3-dev libdbus-1-dev`
(already covered by the apt install above).

---

### 6. Validate the installation

```bash
# Smoke test — runs entirely without hardware (no root needed)
python smoke_test.py

# CLI self-check
fhs --version
fhs info
```

A clean install produces output like:

```
=== 1. Core Imports ===
  PASS  __app_name__
  PASS  __version__
  ...
==================================================
  SMOKE TEST: 97 passed, 0 failed
==================================================
```

---

## Quick Start

```bash
# Passive WiFi scan (requires monitor-mode adapter + root/CAP_NET_RAW)
sudo fhs scan start -i wlan0mon --5ghz

# Bluetooth scan (Ubertooth or HCI fallback)
sudo fhs bluetooth scan

# Cellular tower detection
sudo fhs cellular scan --duration 60

# Rogue base station detection with baseline
sudo fhs cellular baseline baseline.json --duration 120
sudo fhs cellular detect --baseline baseline.json --duration 300

# Client isolation testing — simulate mode (no hardware)
fhs isolation run-all -i wlan0 -j wlan1 --simulate

# Client isolation testing — live (requires hostap build + two adapters + root)
sudo fhs isolation run-all -i wlan0 -j wlan1 --config data/isolation/client.conf

# Individual isolation tests
sudo fhs isolation test    -i wlan0 --config data/isolation/client.conf
sudo fhs isolation c2c     -i wlan0 -j wlan1 --mode ip
sudo fhs isolation c2c     -i wlan0 -j wlan1 --mode gw-bounce
sudo fhs isolation c2c     -i wlan0 -j wlan1 --mode port-steal-down
sudo fhs isolation c2m     -i wlan0 --monitor-interface wlan1mon

# Export and analysis
fhs export csv session.db -o results.csv
fhs export json session.db -o results.json --encrypt
fhs analyze report session.db

# Audit log
fhs audit verify
fhs audit show -n 20

# Launch desktop GUI
fhs gui

# System status
fhs info
```

---

## Deployment on Specific Hardware

| Platform | Guide |
|---|---|
| HackberryPi CM5 | [DEPLOY.md](DEPLOY.md) — includes deploy scripts, ARM64 notes, thermal tips |

**HackberryPi CM5 quick deploy from iHBV-TUF:**
```powershell
# Windows PowerShell — push repo and run deploy script in one step
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local -Deploy
```

---

## System Requirements

- **OS:** Linux (Debian/Ubuntu 22.04+ recommended). WiFi operations require Linux.
  CLI, analysis, and simulation mode work on macOS and Windows.
- **Python:** 3.10+
- **Privileges:** Root or `CAP_NET_RAW` + `CAP_NET_ADMIN` for wireless operations.
  Simulation mode, database operations, and analysis run without elevated privileges.
- **WiFi adapter:** Monitor-mode capable (one for passive scanning, two for isolation testing).

### Optional Hardware

| Device | Purpose | Module |
|--------|---------|--------|
| Any monitor-mode WiFi adapter | WiFi scanning | HoneyBadger Core |
| Second monitor-mode adapter | Isolation attack testing | AirSnitch |
| NooElec NESDR Nano 3 (RTL-SDR) | GSM tower scanning | CellGuard |
| PortaPack H4M / HackRF One | LTE / 5G NR cell search | CellGuard |
| Ubertooth One | Passive Bluetooth/BLE sniffing | BlueScout |
| USB GPS (via gpsd) | Geolocation, RF heatmaps | WarrenMap / BadgerTrack |
| Serial IMU sensor (/dev/ttyUSB0) | Indoor dead-reckoning | BadgerTrack |

---

## Project Structure

```
FlyingHoneySnitch/
├── flyinghoneysnitch/
│   ├── core/           # 802.11 packet capture, parsing, scanner engine
│   ├── analysis/       # Post-hoc analytics, pattern detection, HTML reports
│   ├── bluetooth/      # BlueScout — BLE/BT scanning, ad parser, classifier
│   ├── cellular/       # CellGuard — GSM/LTE/5G scanning, rogue detection
│   ├── db/             # SQLAlchemy ORM, migrations, session persistence
│   ├── gui/            # PyQt6 desktop application
│   ├── isolation/      # AirSnitch — isolation attacks, hostap wiring, libwifi
│   │   ├── attacks/    # GTK, C2C, C2M, port-steal, gw-bounce, bcast-reflect
│   │   ├── framework/  # Trigger/action station framework (library-style)
│   │   └── libwifi/    # Scapy frame building, CCMP crypto, monitor sockets
│   ├── mapping/        # Folium maps, RF heatmaps, KML export, GIS utils
│   ├── monitoring/     # SentryWeb — alerting, policy engine, sensor manager
│   ├── positioning/    # GPS client, IMU reader, sensor fusion
│   ├── utils/          # Config, logging, AES-256-GCM crypto, HMAC audit log
│   └── cli/            # Click CLI subcommands (fhs)
├── data/
│   ├── isolation/      # wpa_supplicant / hostapd config files
│   ├── mccmnc.csv      # MCC/MNC operator database
│   └── oui.csv         # IEEE OUI vendor database
├── vendor/
│   ├── hostap_2_10/    # Modified hostapd + wpa_supplicant (build with build.sh)
│   └── build.sh        # Hostap build script
├── tests/              # pytest test suite
├── smoke_test.py              # Dependency-free validation script (no hardware needed)
├── deploy-hackberrypi.sh      # HackberryPi CM5 deploy script (run on device)
├── Prepare-HackberryPi.ps1   # Pre-flight push script (run on iHBV-TUF)
├── DEPLOY.md                  # Hardware deployment guide
├── requirements.txt           # Core Python packages
├── requirements-optional.txt  # Hardware/feature optional packages
├── requirements-dev.txt       # Dev/test tooling
├── requirements-linux.txt     # System apt packages (annotated)
└── pyproject.toml             # Package metadata and build config
```

---

## Testing

```bash
# Full pytest suite
python -m pytest tests/ -v

# With coverage report
python -m pytest tests/ --cov=flyinghoneysnitch --cov-report=term-missing

# Smoke test (fast, no hardware, no root)
python smoke_test.py

# Specific module
python -m pytest tests/cellular/test_detector.py -v
python -m pytest tests/isolation/ -v
```

---

## License

MIT — see [LICENSE](LICENSE)

---

## Links

- **Homepage:** https://ihbv.io
- **Repository:** https://github.com/MoSLoF/FlyingHoneySnitch
- **HackberryPi CM5 deployment:** [DEPLOY.md](DEPLOY.md)
- **AirSnitch paper:** Mathy Vanhoef, NDSS 2026 — https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
