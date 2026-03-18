# Changelog

All notable changes to honeysnatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-03-17

### Added

- **HoneyBadger Core** - Passive WiFi discovery engine with 802.11 packet parsing, channel hopping, and monitor mode support
- **WarrenMap** - RF signal visualization with Folium heatmaps and KML/Google Earth export
- **HoneyView** - Post-hoc analysis with pattern detection, evil twin identification, and HTML report generation
- **SentryWeb** - Continuous monitoring with rogue AP detection, encryption downgrade alerts, and configurable policy engine
- **BadgerTrack** - Indoor positioning via GPS/IMU sensor fusion
- **BlueScout** - Passive Bluetooth/BLE scanning via Ubertooth
- **CellGuard** - Cellular base station detection (GSM/LTE/5G NR) with rogue tower / IMSI catcher detection via SDR
- **Encrypted storage** - AES-256-GCM file encryption and optional SQLCipher database encryption
- **Tamper-evident audit logging** - HMAC-SHA256 chained append-only audit trail
- **PyQt6 desktop GUI** with tabbed panels for all modules
- **Click CLI** (`fhs`) with subcommands for scanning, analysis, monitoring, export, and audit
- **Export formats** - CSV, JSON, KML with optional encryption
- **MCC/MNC operator database** for cellular carrier identification
- **OUI vendor database** for MAC address manufacturer lookup

### Hardware Support

- RTL-SDR (NooElec NESDR Nano 3) for GSM scanning via gr-gsm
- HackRF One (PortaPack H4M) for LTE/5G cell search via srsRAN
- Ubertooth One for Bluetooth scanning
- Any Linux-supported WiFi adapter with monitor mode
- GPS via gpsd
- Raspberry Pi CM5 deployment target
