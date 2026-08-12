# honeysnatch — HackberryPi CM5 Deployment Guide

> Platform notes for running FHS on the **HackberryPi CM5**
> (ZitaoTech / Elecrow, Raspberry Pi Compute Module 5)

---

## Hardware Reality Check

Before you spend 20 minutes wondering why `fhs scan` isn't capturing packets — read this.

| Fact | Impact on FHS |
|---|---|
| **On-board WiFi is CYW43455** | Cannot do monitor mode. `fhs scan` won't work on `wlan0`. |
| **2x USB-A ports only** | Passive scanning needs 1 external adapter. Isolation testing needs 2 (or a hub). |
| **M.2 2242 slot is for SSD/AI card** | No second NIC from M.2. USB only for extra adapters. |
| **Passive heatsink, no fan** | CPU thermal-throttles under sustained load. Watch `vcgencmd measure_temp`. |
| **`gr-gsm` / `srsran` not ARM64 packaged** | CellGuard GSM/LTE needs source build or AppImage. |
| **Kali headers are `rpi-2712`, not `$(uname -r)`** | DKMS drivers fail if you use the wrong header package name. |

---

## Recommended Hardware

### WiFi Adapter (mandatory for scanning)

You need a USB adapter with **monitor mode** + **injection** support on ARM64 Linux.

| Adapter | Chipset | ARM64 Driver | Notes |
|---|---|---|---|
| **Alfa AWUS036ACH** | RTL8812AU | DKMS (morrownr repo) | Best dual-band option for Pi |
| **Alfa AWUS036ACHM** | MT7612U | In-kernel (`mt7612u`) | No DKMS needed, just plug in |
| Panda PAU09 | RT5572 | In-kernel | 2.4+5GHz, solid |
| TP-Link TL-WN722N v1 | AR9271 | In-kernel (`ath9k_htc`) | 2.4GHz only |

**For the Alfa AWUS036ACH on Kali ARM64:**
```bash
sudo apt install dkms git
git clone https://github.com/morrownr/8812au-20210629
cd 8812au-20210629
sudo bash install-driver.sh
```

### For Isolation Testing (2 NICs)

Plug both adapters directly into the two USB-A ports, or use a powered USB hub.
The on-board `wlan0` cannot be the victim NIC — it has no monitor mode / injection.
Use `wlan1` (first USB adapter) and `wlan2` (second USB adapter).

---

## Quick Deploy from iHBV-TUF (Windows / PowerShell)

```powershell
# From H:\Development\Projects\honeysnatch on iHBV-TUF:

# 1. Test connectivity and push repo (no deploy yet)
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local

# 2. Push AND run the full deploy script automatically
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local -Deploy

# 3. Push + deploy, skip hostap build (simulation mode only)
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local -Deploy -SkipHostap

# 4. Push only (re-sync after code changes)
.\Prepare-HackberryPi.ps1 -DeviceHost 192.168.1.42

# 5. Dry run to see what would happen
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local -Deploy -DryRun
```

---

## Manual Deploy on the HackberryPi

SSH in (default Kali creds: `kali`/`kali` — change immediately):

```bash
ssh kali@hackberrypi.local
```

Then on the device:

```bash
# Full deploy (WiFi scanning + Bluetooth + GPS + isolation testing)
cd ~/honeysnatch
sudo bash deploy-hackberrypi.sh

# With Qt display config for the 720x720 touchscreen
sudo bash deploy-hackberrypi.sh --gui

# Skip hostap build (no live isolation testing — simulation mode still works)
sudo bash deploy-hackberrypi.sh --skip-hostap
```

---

## Capabilities (running without sudo)

Wireless scanning requires `CAP_NET_RAW` and `CAP_NET_ADMIN`. The obvious
`sudo setcap … $(which python3)` recipe is **incorrect** — it grants
network-raw capability to every Python process on the box for every user.
Use the scoped helper instead, which copies the venv's Python interpreter
to `.venv/bin/python-net`, applies setcap to that copy only, and leaves
the system Python untouched:

```bash
source ~/honeysnatch/.venv/bin/activate
sudo ~/honeysnatch/bin/grant-capabilities.sh
# then run scans through the elevated interpreter:
.venv/bin/python-net -m honeysnatch scan start -i wlan1mon
```

To revoke, just `rm .venv/bin/python-net`. Deleting the venv also removes
the elevated binary — no lingering system-wide capability. See
`bin/grant-capabilities.sh` for the full rationale.

If you'd rather keep using `sudo`, that's also fine — every `sudo fhs …`
example in this guide works unchanged.

---

## First Use

```bash
# Activate venv
source ~/honeysnatch/.venv/bin/activate

# Check system status and interface detection
fhs info

# Unblock WiFi radio
sudo rfkill unblock wifi

# Enable monitor mode on external USB adapter (wlan1 = first USB adapter)
sudo airmon-ng start wlan1
# or:
sudo ip link set wlan1 down
sudo iw wlan1 set monitor none
sudo ip link set wlan1 up

# Passive WiFi scan
sudo fhs scan start -i wlan1mon --5ghz

# Bluetooth scan (Ubertooth or HCI fallback)
sudo fhs bluetooth scan

# Isolation testing — simulate mode (no hardware, works anywhere)
fhs isolation run-all -i wlan0 -j wlan1 --simulate

# Isolation testing — live (needs 2 USB adapters + hostap build)
sudo fhs isolation run-all -i wlan1 -j wlan2 \
    --config ~/honeysnatch/data/isolation/client.conf
```

---

## Interface Naming

| Interface | What it is |
|---|---|
| `wlan0` | On-board CM5 WiFi (CYW43455) — **no monitor mode** — use for internet/hotspot |
| `wlan1` | First external USB adapter — use for passive scanning |
| `wlan1mon` | Monitor-mode virtual interface on wlan1 |
| `wlan2` | Second USB adapter — used as attacker NIC in isolation tests |

---

## Thermal Management

The CM5 passively cooled under sustained scanning. If you see performance drops:

```bash
# Check current temp
watch -n1 vcgencmd measure_temp

# Gentle clock reduction (add to /boot/firmware/config.txt)
echo 'arm_freq=2000' | sudo tee -a /boot/firmware/config.txt

# Check throttle status (0x0 = no throttling)
vcgencmd get_throttled
```

For field ops, active airflow across the aluminum case helps significantly.
The MagSafe mount on the back doubles as a heat spreader if attached to a metal surface.

---

## ARM64-Specific Package Notes

### Kernel Headers

On Kali ARM64 for Raspberry Pi, the standard `linux-headers-$(uname -r)` does **not** work.
Use these instead:

```bash
sudo apt install linux-headers-rpi-2712 linux-headers-rpi-v8
```

### gr-gsm (GSM scanning)

Not available as a prebuilt ARM64 package on most distros. Build from source:

```bash
sudo apt install cmake libboost-all-dev libcppunit-dev swig \
    gnuradio-dev gr-osmosdr
git clone https://github.com/ptrkrysik/gr-gsm
cd gr-gsm && mkdir build && cd build
cmake .. && make -j2 && sudo make install
sudo ldconfig
```

### srsRAN (LTE/5G scanning)

```bash
sudo apt install cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev \
    libconfig++-dev libsctp-dev
git clone https://github.com/srsRAN/srsRAN_4G
cd srsRAN_4G && mkdir build && cd build
cmake .. && make cell_search -j2
sudo cp apps/cell_search /usr/local/bin/
```

> Both builds take ~20-30 mins on the CM5. Limit to `-j2` to avoid thermal throttling.

---

## Sync Changes from iHBV-TUF

As you develop on `iHBV-TUF`, push changes to the HackberryPi without full redeploy:

```powershell
# From iHBV-TUF PowerShell:
.\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local
# (skips apt and hostap by default when they're already done)
```

Or from the HackberryPi directly if you've set up SSH key auth to GitHub:

```bash
cd ~/honeysnatch
git pull origin main
pip install -e .       # picks up any new dependencies
```

---

## Ratel MQTT Integration

To feed scan events into iHBV-RATEL's MQTT broker from the HackberryPi:

```bash
# Install mosquitto client
sudo apt install mosquitto-clients

# Test connectivity to RATEL broker
mosquitto_pub -h mqtt.ihbv.io -p 9001 \
    -t "hbv/hackberrypi/status" \
    -m '{"node":"hackberrypi","status":"online"}'
```

The FHS `SentryWeb` monitoring module will be wired to publish `alert` events to
`hbv/fhs/alerts` in a future update. Watch this space. 🦡
