# FlyingHoneySnitch

Wireless Discovery, Assessment & Isolation Testing Suite.

**FlyingHoneyBadger** (passive wireless discovery) + **AirSnitch** (active client isolation testing) = **FlyingHoneySnitch**.

## Components

- **HoneyBadger Core** - Passive WiFi discovery & 802.11 protocol analysis
- **WarrenMap** - Real-time RF visualization & signal heatmaps
- **HoneyView** - Post-hoc visual analytics & reporting
- **SentryWeb** - Continuous wireless security monitoring
- **BadgerTrack** - GPS/IMU indoor positioning & sensor fusion
- **BlueScout** - Passive Bluetooth/BLE scanning (Ubertooth)
- **CellGuard** - Cellular tower detection & IMSI catcher identification
- **AirSnitch** - Client isolation vulnerability testing (GTK abuse, gateway bouncing, port stealing, broadcast reflection)

## Installation

```bash
git clone https://github.com/flyinghoneysnitch/flyinghoneysnitch.git
cd FlyingHoneySnitch
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,all]"
```

### Building AirSnitch Dependencies (Linux only)

```bash
cd vendor
bash build.sh
```

## Usage

```bash
# Passive WiFi scanning
fhs scan start -i wlan0mon --5ghz

# Bluetooth scanning
fhs bluetooth scan

# Cellular tower detection
fhs cellular scan --duration 60

# Client isolation testing
fhs isolation test -i wlan0 -c data/isolation/client.conf
fhs isolation c2c -i wlan0 -j wlan1 --mode ip
fhs isolation run-all -i wlan0 -j wlan1

# Export & analysis
fhs export csv session.db -o results.csv
fhs analyze report session.db

# Launch GUI
fhs gui

# System info
fhs info
```

## System Requirements

- Python 3.10+
- Linux (for wireless operations)
- Root or CAP_NET_RAW/CAP_NET_ADMIN
- Monitor-mode capable WiFi adapter(s)

### Optional Hardware

| Device | Purpose |
|--------|---------|
| NooElec NESDR Nano 3 (RTL-SDR) | GSM tower scanning |
| PortaPack H4M (HackRF One) | LTE/5G detection |
| Ubertooth One | Bluetooth scanning |
| USB GPS | Geolocation |

## License

MIT
