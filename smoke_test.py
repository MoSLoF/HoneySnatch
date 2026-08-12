"""honeysnatch comprehensive smoke test."""
import sys
import os
import tempfile
import shutil

passed = 0
failed = 0


def assert_eq(a, b):
    assert a == b, f"{a!r} != {b!r}"


def check(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        failed += 1


# === 1. Core Imports ===
print("=== 1. Core Imports ===")
import honeysnatch
check("__app_name__", lambda: assert_eq(honeysnatch.__app_name__, "honeysnatch"))
check("__version__", lambda: assert_eq(honeysnatch.__version__, "0.1.8"))
check("core.models", lambda: __import__("honeysnatch.core.models"))
check("db.schema", lambda: __import__("honeysnatch.db.schema"))
check("db.database", lambda: __import__("honeysnatch.db.database"))
check("utils.config", lambda: __import__("honeysnatch.utils.config"))
check("utils.crypto", lambda: __import__("honeysnatch.utils.crypto"))
check("utils.logger", lambda: __import__("honeysnatch.utils.logger"))
check("analysis", lambda: __import__("honeysnatch.analysis"))
check("mapping", lambda: __import__("honeysnatch.mapping"))
check("monitoring", lambda: __import__("honeysnatch.monitoring"))
check("cellular", lambda: __import__("honeysnatch.cellular"))
check("bluetooth", lambda: __import__("honeysnatch.bluetooth"))
check("cli.main", lambda: __import__("honeysnatch.cli.main"))
check("cli.isolation", lambda: __import__("honeysnatch.cli.isolation"))

# === 2. Isolation Package Imports ===
print("\n=== 2. Isolation Package Imports ===")
check("isolation", lambda: __import__("honeysnatch.isolation"))
check("isolation.config", lambda: __import__("honeysnatch.isolation.config"))
check("isolation.models", lambda: __import__("honeysnatch.isolation.models"))
check("isolation.runner", lambda: __import__("honeysnatch.isolation.runner"))
check("isolation.daemon", lambda: __import__("honeysnatch.isolation.daemon"))
check("isolation.monitor", lambda: __import__("honeysnatch.isolation.monitor"))
check("isolation.supplicant", lambda: __import__("honeysnatch.isolation.supplicant"))
check("isolation.attacks", lambda: __import__("honeysnatch.isolation.attacks"))
check("isolation.attacks.base", lambda: __import__("honeysnatch.isolation.attacks.base"))
check("isolation.attacks.gtk_abuse", lambda: __import__("honeysnatch.isolation.attacks.gtk_abuse"))
check("isolation.attacks.client2client", lambda: __import__("honeysnatch.isolation.attacks.client2client"))
check("isolation.attacks.client2monitor", lambda: __import__("honeysnatch.isolation.attacks.client2monitor"))
check("isolation.attacks.port_steal", lambda: __import__("honeysnatch.isolation.attacks.port_steal"))
check("isolation.attacks.broadcast_reflection", lambda: __import__("honeysnatch.isolation.attacks.broadcast_reflection"))
check("isolation.attacks.gateway_bounce", lambda: __import__("honeysnatch.isolation.attacks.gateway_bounce"))
check("isolation.libwifi", lambda: __import__("honeysnatch.isolation.libwifi"))
check("isolation.libwifi.crypto", lambda: __import__("honeysnatch.isolation.libwifi.crypto"))
check("isolation.framework", lambda: __import__("honeysnatch.isolation.framework"))
check("isolation.framework.testcase", lambda: __import__("honeysnatch.isolation.framework.testcase"))
check("isolation.framework.daemon", lambda: __import__("honeysnatch.isolation.framework.daemon"))
check("isolation.framework.station", lambda: __import__("honeysnatch.isolation.framework.station"))
check("isolation.port_restoration", lambda: __import__("honeysnatch.isolation.port_restoration"))

# === 3. Config System ===
print("\n=== 3. Config System ===")
from honeysnatch.utils.config import AppConfig
cfg = AppConfig()
check("AppConfig has isolation", lambda: assert_eq(hasattr(cfg, "isolation"), True))
check("IsolationConfig.enabled (off by default)", lambda: assert_eq(cfg.isolation.enabled, False))
check("IsolationConfig.test_timeout", lambda: assert_eq(cfg.isolation.test_timeout, 30))
check("ScanConfig.hop_interval", lambda: assert_eq(cfg.scan.hop_interval, 0.5))
check("GuiConfig.theme", lambda: assert_eq(cfg.gui.theme, "dark"))
check("CellularConfig.scan_gsm", lambda: assert_eq(cfg.cellular.scan_gsm, True))
check("SecurityConfig.audit_enabled", lambda: assert_eq(cfg.security.audit_enabled, True))

# === 4. Database CRUD ===
print("\n=== 4. Database CRUD ===")
tmpdir = tempfile.mkdtemp()
try:
    from honeysnatch.db.database import DatabaseManager
    from honeysnatch.core.models import AccessPoint, Client, EncryptionType, GeoPosition

    db_path = os.path.join(tmpdir, "smoke_test.db")
    db = DatabaseManager(db_path)

    sid = db.create_scan_session(name="Smoke Test", interface="wlan0", channels=[1, 6, 11])
    check("create_scan_session", lambda: assert_eq(len(sid), 16))

    sessions = db.list_sessions()
    check("list_sessions", lambda: assert_eq(len(sessions), 1))
    check("session name", lambda: assert_eq(sessions[0]["name"], "Smoke Test"))

    ap = AccessPoint(
        bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet", channel=6,
        rssi=-42, encryption=EncryptionType.WPA2,
    )
    db.save_access_point(sid, ap)
    loaded = db.load_scan_session(sid)
    check("save+load AP", lambda: assert_eq(len(loaded.access_points), 1))
    check("AP SSID", lambda: assert_eq(loaded.access_points["AA:BB:CC:DD:EE:FF"].ssid, "TestNet"))
    check("AP encryption", lambda: assert_eq(loaded.access_points["AA:BB:CC:DD:EE:FF"].encryption, EncryptionType.WPA2))

    client = Client(mac="11:22:33:44:55:66", bssid="AA:BB:CC:DD:EE:FF", rssi=-55)
    db.save_client(sid, client)
    loaded2 = db.load_scan_session(sid)
    check("save+load Client", lambda: assert_eq(len(loaded2.clients), 1))
    check("client MAC", lambda: assert_eq("11:22:33:44:55:66" in loaded2.clients, True))

    db.save_alert("rogue_ap", "Rogue AP detected", severity="critical", bssid="AA:BB:CC:DD:EE:FF")
    check("save_alert (no crash)", lambda: None)

    pos = GeoPosition(latitude=40.7128, longitude=-74.0060)
    db.save_position(sid, pos)
    check("save_position (no crash)", lambda: None)

    db.save_signal("AA:BB:CC:DD:EE:FF", -38, pos)
    check("save_signal (no crash)", lambda: None)

    db.end_scan_session(sid)
    check("end_scan_session", lambda: None)

    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(db.engine)
    tables = inspector.get_table_names()
    check("isolation_sessions table exists", lambda: assert_eq("isolation_sessions" in tables, True))
    check("isolation_results table exists", lambda: assert_eq("isolation_results" in tables, True))
    check("cell_towers table exists", lambda: assert_eq("cell_towers" in tables, True))
    check("bluetooth_devices table exists", lambda: assert_eq("bluetooth_devices" in tables, True))
    check("all core tables exist", lambda: (
        assert_eq("sessions" in tables, True),
        assert_eq("access_points" in tables, True),
        assert_eq("clients" in tables, True),
        assert_eq("positions" in tables, True),
        assert_eq("signals" in tables, True),
        assert_eq("alerts" in tables, True),
    ))

    db.close()
finally:
    shutil.rmtree(tmpdir)

# === 5. Isolation Models & Attacks ===
print("\n=== 5. Isolation Models & Attacks ===")
from honeysnatch.isolation.attacks.base import AttackType, AttackOutcome, AttackResult
from honeysnatch.isolation.models import IsolationTestSession

check("AttackType has 13 types", lambda: assert_eq(len(AttackType), 13))
check("AttackOutcome values", lambda: (
    AttackOutcome.VULNERABLE,
    AttackOutcome.SECURE,
    AttackOutcome.INCONCLUSIVE,
    AttackOutcome.ERROR,
))

result = AttackResult(
    attack_type=AttackType.GTK_SHARED,
    outcome=AttackOutcome.VULNERABLE,
    details="GTK is shared between clients",
)
check("AttackResult creation", lambda: assert_eq(result.outcome, AttackOutcome.VULNERABLE))
check("AttackResult.attack_type", lambda: assert_eq(result.attack_type, AttackType.GTK_SHARED))

session = IsolationTestSession(
    session_id="test123", target_ssid="TestNet", target_bssid="AA:BB:CC:DD:EE:FF",
)
session.add_result(result)
session.add_result(AttackResult(attack_type=AttackType.CLIENT_TO_CLIENT_ARP, outcome=AttackOutcome.SECURE))
session.add_result(AttackResult(attack_type=AttackType.PORT_STEAL_DOWNLINK, outcome=AttackOutcome.INCONCLUSIVE))
check("total_count", lambda: assert_eq(session.total_count, 3))
check("vulnerable_count", lambda: assert_eq(session.vulnerable_count, 1))
check("secure_count", lambda: assert_eq(session.secure_count, 1))
session.finish()
check("session.finish()", lambda: assert_eq(session.end_time is not None, True))

from honeysnatch.isolation.attacks.gtk_abuse import check_gtk_shared
from honeysnatch.isolation.attacks.broadcast_reflection import create_broadcast_reflection_result
from honeysnatch.isolation.attacks.gateway_bounce import create_gateway_bounce_result
from honeysnatch.isolation.attacks.port_steal import create_port_steal_result
from honeysnatch.isolation.attacks.client2client import create_c2c_result
from honeysnatch.isolation.attacks.client2monitor import create_c2m_result

r1 = check_gtk_shared(b"aabbccdd", b"aabbccdd", 1, 1)
check("check_gtk_shared (shared)", lambda: assert_eq(r1.outcome, AttackOutcome.VULNERABLE))
r2 = check_gtk_shared(b"aabbccdd", b"11223344", 1, 2)
check("check_gtk_shared (unique)", lambda: assert_eq(r2.outcome, AttackOutcome.SECURE))
r3 = create_broadcast_reflection_result(True)
check("broadcast_reflection (vuln)", lambda: assert_eq(r3.outcome, AttackOutcome.VULNERABLE))
r4 = create_gateway_bounce_result(False)
check("gateway_bounce (secure)", lambda: assert_eq(r4.outcome, AttackOutcome.SECURE))
r5 = create_port_steal_result("downlink", True)
check("port_steal downlink", lambda: assert_eq(r5.attack_type, AttackType.PORT_STEAL_DOWNLINK))
r6 = create_port_steal_result("uplink", True)
check("port_steal uplink", lambda: assert_eq(r6.attack_type, AttackType.PORT_STEAL_UPLINK))
r7 = create_c2c_result("arp", True)
check("c2c_arp", lambda: assert_eq(r7.attack_type, AttackType.CLIENT_TO_CLIENT_ARP))
r8 = create_c2m_result(True)
check("c2m", lambda: assert_eq(r8.attack_type, AttackType.CLIENT_TO_MONITOR))

# === 6. Isolation Runner (simulate) ===
print("\n=== 6. Isolation Runner (simulate) ===")
from honeysnatch.isolation.runner import IsolationTestRunner

runner_sim = IsolationTestRunner(interface="wlan0", simulate=True)
check("IsolationTestRunner (simulate) creation", lambda: assert_eq(runner_sim is not None, True))

r_gtk  = runner_sim.run_gtk_check("wlan1")
check("simulate GTK → INCONCLUSIVE", lambda: assert_eq(r_gtk.outcome, AttackOutcome.INCONCLUSIVE))
check("simulate GTK attack_type", lambda: assert_eq(r_gtk.attack_type, AttackType.GTK_SHARED))

r_c2c  = runner_sim.run_client2client("wlan1", mode="ip")
check("simulate C2C-IP → INCONCLUSIVE", lambda: assert_eq(r_c2c.outcome, AttackOutcome.INCONCLUSIVE))

r_c2c2 = runner_sim.run_client2client("wlan1", mode="broadcast")
check("simulate C2C-broadcast → INCONCLUSIVE", lambda: assert_eq(r_c2c2.outcome, AttackOutcome.INCONCLUSIVE))

r_ps_d = runner_sim.run_port_steal("wlan1", direction="downlink")
check("simulate port-steal-down → INCONCLUSIVE", lambda: assert_eq(r_ps_d.outcome, AttackOutcome.INCONCLUSIVE))
check("simulate port-steal-down type", lambda: assert_eq(r_ps_d.attack_type, AttackType.PORT_STEAL_DOWNLINK))

r_ps_u = runner_sim.run_port_steal("wlan1", direction="uplink")
check("simulate port-steal-up type", lambda: assert_eq(r_ps_u.attack_type, AttackType.PORT_STEAL_UPLINK))

r_gw   = runner_sim.run_gateway_bounce("wlan1")
check("simulate GW bounce → INCONCLUSIVE", lambda: assert_eq(r_gw.outcome, AttackOutcome.INCONCLUSIVE))
check("simulate GW bounce type", lambda: assert_eq(r_gw.attack_type, AttackType.GATEWAY_BOUNCE))

r_br   = runner_sim.run_broadcast_reflection("wlan1")
check("simulate bcast reflect type", lambda: assert_eq(r_br.attack_type, AttackType.BROADCAST_REFLECTION))

r_c2m  = runner_sim.run_client2monitor("wlan1mon")
check("simulate C2M type", lambda: assert_eq(r_c2m.attack_type, AttackType.CLIENT_TO_MONITOR))

sess_all = runner_sim.run_all("wlan1")
check("run_all returns session", lambda: assert_eq(isinstance(sess_all, IsolationTestSession), True))
check("run_all 8 results", lambda: assert_eq(sess_all.total_count, 8))
check("run_all 0 vulnerable (simulate)", lambda: assert_eq(sess_all.vulnerable_count, 0))
check("run_all end_time set", lambda: assert_eq(sess_all.end_time is not None, True))

# === 7. CLI Registration ===
print("\n=== 7. CLI Registration ===")
from click.testing import CliRunner
from honeysnatch.cli.main import cli
cli_runner = CliRunner()

result_ver = cli_runner.invoke(cli, ["--version"])
check("fhs --version", lambda: assert_eq("0.1.8" in result_ver.output, True))

result_help = cli_runner.invoke(cli, ["--help"])
for cmd in ["scan", "analyze", "export", "monitor", "bluetooth", "cellular", "isolation", "gui", "info", "audit"]:
    check(f"CLI has '{cmd}'", lambda c=cmd: assert_eq(c in result_help.output, True))

result_iso = cli_runner.invoke(cli, ["isolation", "--help"])
for sub in ["test", "c2c", "c2m", "run-all", "setup", "build"]:
    check(f"isolation has '{sub}'", lambda s=sub: assert_eq(s in result_iso.output, True))

# CLI simulate path
result_iso_all = cli_runner.invoke(
    cli, ["isolation", "run-all", "-i", "wlan0", "-j", "wlan1", "--simulate"],
)
check("CLI isolation run-all --simulate exit 0",
      lambda: assert_eq(result_iso_all.exit_code, 0))
check("CLI isolation run-all output has INCONCLUSIVE",
      lambda: assert_eq("INCONCLUSIVE" in result_iso_all.output, True))

# === 8. Crypto (FHS magic) ===
print("\n=== 8. Crypto (FHS magic) ===")
from honeysnatch.utils.crypto import MAGIC, encrypt_file, decrypt_file, is_encrypted_file
check("MAGIC == FHS\\x01", lambda: assert_eq(MAGIC, b"FHS\x01"))

tmpdir2 = tempfile.mkdtemp()
try:
    src = os.path.join(tmpdir2, "plain.txt")
    enc = os.path.join(tmpdir2, "encrypted.fhs")
    dec = os.path.join(tmpdir2, "decrypted.txt")
    with open(src, "w") as f:
        f.write("honeysnatch smoke test data")
    encrypt_file(src, enc, "testpass123")
    check("encrypt_file creates file", lambda: assert_eq(os.path.exists(enc), True))
    check("is_encrypted_file", lambda: assert_eq(is_encrypted_file(enc), True))
    check("plain file not encrypted", lambda: assert_eq(is_encrypted_file(src), False))
    decrypt_file(enc, dec, "testpass123")
    with open(dec) as f:
        content = f.read()
    check("decrypt roundtrip matches", lambda: assert_eq(content, "honeysnatch smoke test data"))
finally:
    shutil.rmtree(tmpdir2)

# === 9. libwifi CCMP Crypto ===
print("\n=== 9. libwifi CCMP Crypto ===")
from honeysnatch.isolation.libwifi.crypto import encrypt_ccmp, decrypt_ccmp, aes_wrap_key
check("encrypt_ccmp callable", lambda: assert_eq(callable(encrypt_ccmp), True))
check("decrypt_ccmp callable", lambda: assert_eq(callable(decrypt_ccmp), True))
check("aes_wrap_key callable", lambda: assert_eq(callable(aes_wrap_key), True))

# === 10. Data Files ===
# HS-05: data/ moved into the package as honeysnatch/data/ so it ships in
# the wheel. The smoke test checks BOTH the on-disk location (installed
# or source-checkout) and the importlib.resources path.
print("\n=== 10. Data Files ===")
import importlib.resources as _res
_pkg_data = _res.files("honeysnatch.data")
check("honeysnatch.data package resolvable", lambda: assert_eq(_pkg_data.is_dir(), True))
check("default_config.yaml exists (packaged)",
      lambda: assert_eq((_pkg_data / "default_config.yaml").is_file(), True))
check("mccmnc.csv exists (packaged)",
      lambda: assert_eq((_pkg_data / "mccmnc.csv").is_file(), True))
_pkg_iso = _res.files("honeysnatch.data.isolation")
check("honeysnatch.data.isolation package resolvable",
      lambda: assert_eq(_pkg_iso.is_dir(), True))
iso_files = [p.name for p in _pkg_iso.iterdir() if p.name.endswith(".conf")]
check("isolation configs present", lambda: assert_eq(len(iso_files) > 5, True))

# === 11. Vendor Directory ===
print("\n=== 11. Vendor Directory ===")
vendor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
check("vendor/ dir exists", lambda: assert_eq(os.path.isdir(vendor_dir), True))
check("vendor/build.sh exists", lambda: assert_eq(os.path.isfile(os.path.join(vendor_dir, "build.sh")), True))
check("vendor/hostap_2_10/ exists", lambda: assert_eq(os.path.isdir(os.path.join(vendor_dir, "hostap_2_10")), True))

# === 12. BlueScout (Track 1) ===
print("\n=== 12. BlueScout ===")
from honeysnatch.bluetooth import (
    BluetoothDevice, BluetoothDeviceType, BleAdvertisement, BleAdvType,
    parse_ble_advertisement, classify_bt_device, summarise_device,
    BluetoothScanner,
)
from honeysnatch.bluetooth.models import classify_cod, lookup_company

# iBeacon AD payload (hand-crafted)
IBEACON_AD = bytes([
    0x02, 0x01, 0x06,            # Flags: LE General Discoverable, BR/EDR Not Supported
    0x1a, 0xff,                  # Mfr specific, 26 bytes payload follows
    0x4c, 0x00,                  # Apple company ID (little-endian 0x004C)
    0x02, 0x15,                  # iBeacon subtype=0x02, length=0x15
] + [0xde, 0xad, 0xbe, 0xef] * 4 +  # UUID (16 bytes)
[0x00, 0x01,                    # major = 1
 0x00, 0x02,                    # minor = 2
 0xc5])                         # measured tx power = -59 dBm signed
adv = parse_ble_advertisement(IBEACON_AD)
check("BLE parser: flags=0x06", lambda: assert_eq(adv.flags, 0x06))
check("BLE parser: manufacturer_id Apple", lambda: assert_eq(adv.manufacturer_id, 0x004C))
check("BLE parser: is_ibeacon", lambda: assert_eq(adv.is_ibeacon, True))
check("BLE parser: iBeacon uuid present", lambda: assert_eq("uuid" in adv.beacon_meta, True))
check("BLE parser: iBeacon major=1", lambda: assert_eq(adv.beacon_meta["major"], 1))
check("BLE parser: iBeacon minor=2", lambda: assert_eq(adv.beacon_meta["minor"], 2))

# CoD classification. Value 0x20020C decodes per BT SIG assigned numbers as:
#   bits  2- 7 (minor) = 3 → Smartphone
#   bits  8-12 (major) = 2 → Phone
#   bits 13-23 (service) = 1 → Positioning
# The pre-remediation constant 0x200404 decoded correctly to Audio/Video +
# Headset, not Phone + Smartphone — the constant was the bug, not the
# classifier (review finding F-10).
major, minor = classify_cod(0x20020C)
check("CoD major=Phone", lambda: assert_eq(major, "Phone"))
check("CoD minor=Smartphone", lambda: assert_eq(minor, "Smartphone"))

# Company lookup
check("lookup_company Apple", lambda: assert_eq(lookup_company(0x004C), "Apple"))
check("lookup_company unknown 0xFFFF", lambda: assert_eq(lookup_company(0xFFFF), ""))

# Device classify + risk
dev = BluetoothDevice(
    address="aa:bb:cc:dd:ee:ff",
    device_type=BluetoothDeviceType.BLE,
    rssi=-45,
    advertisement=adv,
)
classify_bt_device(dev)
check("classify: iBeacon close range → risk medium/high",
      lambda: assert_eq(dev.risk in ("medium", "high"), True))
summary = summarise_device(dev)
check("summarise_device beacon_type=iBeacon",
      lambda: assert_eq(summary["beacon_type"], "iBeacon"))
check("summarise_device proximity=immediate",
      lambda: assert_eq(summary["proximity"], "immediate"))

# Eddystone-URL AD payload
EDDY_AD = bytes([
    0x03, 0x03, 0xaa, 0xfe,     # 16-bit UUID list: 0xFEAA (Eddystone)
    0x0d, 0x16, 0xaa, 0xfe,     # Service data for 0xFEAA, 13 bytes
    0x10,                        # Eddystone frame type: URL
    0xf3,                        # tx_power signed byte (-13)
    0x03,                        # URL scheme: https://
    ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
    0x07,                        # URL expansion: .com
])
adv2 = parse_ble_advertisement(EDDY_AD)
check("Eddystone: is_eddystone", lambda: assert_eq(adv2.is_eddystone, True))
check("Eddystone-URL type", lambda: assert_eq(adv2.beacon_meta.get("type"), "Eddystone-URL"))
check("Eddystone-URL url contains example",
      lambda: assert_eq("example" in adv2.beacon_meta.get("url", ""), True))

# BluetoothScanner lifecycle (no hardware)
scanner = BluetoothScanner()
check("BluetoothScanner not running", lambda: assert_eq(scanner.is_running, False))
check("BluetoothScanner device_count=0", lambda: assert_eq(scanner.device_count, 0))
check("BluetoothScanner packet_count=0", lambda: assert_eq(scanner.packet_count, 0))

# === 13. CellGuard (Track 2) ===
print("\n=== 13. CellGuard ===")
from honeysnatch.cellular import (
    CellTower, CellularScanner, RogueBaseStationDetector,
    NrScanner, nrarfcn_to_freq, freq_to_nr_band,
    arfcn_to_freq, earfcn_to_freq, earfcn_to_band, classify_cell_tower,
)

# NR-ARFCN math
freq_n78 = nrarfcn_to_freq(634_240)
check("NR-ARFCN n78 → 3400–3700 MHz", lambda: assert_eq(3400 < freq_n78 < 3700, True))
freq_n71 = nrarfcn_to_freq(123_400)
check("NR-ARFCN n71 → 500–700 MHz", lambda: assert_eq(500 < freq_n71 < 700, True))
check("freq_to_nr_band 3500 → n77/n78",
      lambda: assert_eq("n7" in freq_to_nr_band(3500), True))
check("freq_to_nr_band 630 → n71",
      lambda: assert_eq("n71" in freq_to_nr_band(630), True))

# GSM ARFCN math
check("arfcn_to_freq ch1 → 935.2 MHz",
      lambda: assert_eq(abs(arfcn_to_freq(1) - 935.2) < 0.01, True))

# LTE EARFCN math. Per 3GPP TS 36.101 Table 5.7.3-1:
#   Fdl(MHz) = Fdl_low + 0.1 * (EARFCN - Ndl_offset)
# Band 2: Ndl_offset=600, Fdl_low=1930.0 → EARFCN 600 = 1930 MHz start.
# The pre-remediation test used EARFCN 900, which correctly resolves to
# 1960 MHz — not "~1930". The math was right; the constant was wrong
# (review finding F-11).
check("earfcn_to_freq band2 start → ~1930 MHz",
      lambda: assert_eq(abs(earfcn_to_freq(600) - 1930.0) < 0.1, True))
check("earfcn_to_freq band2 mid EARFCN 900 → 1960 MHz",
      lambda: assert_eq(abs(earfcn_to_freq(900) - 1960.0) < 0.1, True))
check("earfcn_to_band 5095 → 12",
      lambda: assert_eq(earfcn_to_band(5095), 12))

# CellTower model
lte_tower = CellTower(
    cell_id="123", technology="LTE",
    mcc="310", mnc="260", tac=1234,
    earfcn=5095, frequency_mhz=729.5, rssi=-75,
    band="Band 12", operator="T-Mobile US",
)
check("CellTower.plmn", lambda: assert_eq(lte_tower.plmn, "310-260"))
check("CellTower.unique_id format",
      lambda: assert_eq("LTE:310-260:123" in lte_tower.unique_id, True))

# Classifier
cls = classify_cell_tower(lte_tower)
check("classify_cell_tower returns dict", lambda: assert_eq(isinstance(cls, dict), True))
check("classify_cell_tower technology", lambda: assert_eq(cls["technology"], "LTE"))

# Rogue detector — LAC change
baseline_tower = CellTower(
    cell_id="456", technology="GSM", mcc="310", mnc="410",
    lac=100, arfcn=60, frequency_mhz=948.0, rssi=-80, operator="AT&T",
)
rogue_tower = CellTower(
    cell_id="456", technology="GSM", mcc="310", mnc="410",
    lac=999, arfcn=60, frequency_mhz=948.0, rssi=-80, operator="AT&T",
)
detector = RogueBaseStationDetector()
detector.load_baseline([baseline_tower])
alerts = detector.check_tower(rogue_tower)
check("Rogue detector LAC change → alert", lambda: assert_eq(len(alerts) > 0, True))
check("Rogue alert severity=critical", lambda: assert_eq(alerts[0].severity, "critical"))
check("Rogue alert type=lac_change", lambda: assert_eq(alerts[0].alert_type, "lac_change"))
check("RogueAlert.to_dict has type key",
      lambda: assert_eq("type" in alerts[0].to_dict(), True))

# Signal anomaly
strong_tower = CellTower(
    cell_id="789", technology="LTE", mcc="310", mnc="260",
    rssi=-30, frequency_mhz=729.5,
)
anomaly_alerts = detector.check_tower(strong_tower)
check("Strong signal → strong_signal alert",
      lambda: assert_eq(any(a.alert_type == "strong_signal" for a in anomaly_alerts), True))

# Rapid appearance (new tower not in baseline or previous scan)
new_tower = CellTower(
    cell_id="999", technology="GSM", mcc="310", mnc="410",
    lac=100, arfcn=42, frequency_mhz=935.4, rssi=-55,
)
detector.update_previous_scan([baseline_tower])  # previous scan didn't have 999
rapid_alerts = detector.check_tower(new_tower)
check("Rapid appearance → alert",
      lambda: assert_eq(any(a.alert_type == "rapid_appearance" for a in rapid_alerts), True))

# CellularScanner lifecycle
cs = CellularScanner(scan_gsm=False, scan_lte=False, scan_5g=False)
check("CellularScanner not running", lambda: assert_eq(cs.is_running, False))
check("CellularScanner tower_count=0", lambda: assert_eq(cs.tower_count, 0))

# NrScanner lifecycle
nr = NrScanner()
check("NrScanner instantiates", lambda: assert_eq(nr is not None, True))

# === 14. DB — Cell / BT / Rogue tables (Track 2) ===
print("\n=== 14. DB Cell/BT/Rogue tables ===")
from honeysnatch.db.schema import (
    CellTowerRecord, CellRogueAlertRecord, BluetoothDeviceRecord,
)
check("CellTowerRecord tablename",
      lambda: assert_eq(CellTowerRecord.__tablename__, "cell_towers"))
check("CellRogueAlertRecord tablename",
      lambda: assert_eq(CellRogueAlertRecord.__tablename__, "cell_rogue_alerts"))
check("BluetoothDeviceRecord tablename",
      lambda: assert_eq(BluetoothDeviceRecord.__tablename__, "bluetooth_devices"))

tmpdir3 = tempfile.mkdtemp()
try:
    from honeysnatch.db.database import DatabaseManager as DM2
    db2 = DM2(os.path.join(tmpdir3, "fhs_ct_bt.db"))
    sid2 = db2.create_scan_session(name="ct-bt-test", interface="wlan0")

    # Cell tower
    db2.save_cell_tower(sid2, lte_tower)
    towers_list = db2.list_cell_towers(sid2)
    check("save_cell_tower count=1", lambda: assert_eq(len(towers_list), 1))
    check("cell_tower cell_id persisted",
          lambda: assert_eq(towers_list[0]["cell_id"], "123"))
    check("cell_tower operator persisted",
          lambda: assert_eq(towers_list[0]["operator"], "T-Mobile US"))

    # Bluetooth device
    db2.save_bt_device(sid2, dev)
    bt_list = db2.list_bt_devices(sid2)
    check("save_bt_device count=1", lambda: assert_eq(len(bt_list), 1))
    check("bt_device address persisted",
          lambda: assert_eq(bt_list[0]["address"], "aa:bb:cc:dd:ee:ff"))
    check("bt_device beacon_type persisted",
          lambda: assert_eq(bt_list[0]["beacon_type"], "iBeacon"))

    # Rogue alert
    db2.save_cell_rogue_alert(alerts[0].to_dict())
    check("save_cell_rogue_alert no exception", lambda: assert_eq(True, True))

    # Session listing includes new counts
    sessions2 = db2.list_sessions()
    check("list_sessions tower_count=1",
          lambda: assert_eq(sessions2[0]["tower_count"], 1))
    check("list_sessions bt_count=1",
          lambda: assert_eq(sessions2[0]["bt_count"], 1))

    db2.close()
finally:
    shutil.rmtree(tmpdir3)

# === 15. Isolation runner — full simulate battery (Track 3) ===
print("\n=== 15. Isolation runner full battery (simulate) ===")
runner_full = IsolationTestRunner(interface="wlan0", simulate=True)
full_session = runner_full.run_all("wlan1")
check("run_all returns IsolationTestSession",
      lambda: assert_eq(isinstance(full_session, IsolationTestSession), True))
check("run_all 8 results",
      lambda: assert_eq(full_session.total_count, 8))
check("run_all 0 vulnerable in simulate",
      lambda: assert_eq(full_session.vulnerable_count, 0))
check("run_all end_time set",
      lambda: assert_eq(full_session.end_time is not None, True))

# Verify each attack type is represented
result_types = {r.attack_type for r in full_session.results}
check("GTK_SHARED in results",
      lambda: assert_eq(AttackType.GTK_SHARED in result_types, True))
check("GATEWAY_BOUNCE in results",
      lambda: assert_eq(AttackType.GATEWAY_BOUNCE in result_types, True))
check("BROADCAST_REFLECTION in results",
      lambda: assert_eq(AttackType.BROADCAST_REFLECTION in result_types, True))
check("PORT_STEAL_DOWNLINK in results",
      lambda: assert_eq(AttackType.PORT_STEAL_DOWNLINK in result_types, True))
check("PORT_STEAL_UPLINK in results",
      lambda: assert_eq(AttackType.PORT_STEAL_UPLINK in result_types, True))

# Persist simulate session to DB
tmpdir4 = tempfile.mkdtemp()
try:
    from honeysnatch.db.database import DatabaseManager as DM3
    db3 = DM3(os.path.join(tmpdir4, "fhs_iso.db"))
    from honeysnatch.cli.isolation import _persist_isolation_session
    _persist_isolation_session(db3, full_session)
    check("_persist_isolation_session no exception", lambda: assert_eq(True, True))
    from sqlalchemy import inspect as sa3
    iso_tables = sa3(db3.engine).get_table_names()
    check("isolation_sessions persisted",
          lambda: assert_eq("isolation_sessions" in iso_tables, True))
    db3.close()
finally:
    shutil.rmtree(tmpdir4)

# === Summary ===
print()
print("=" * 50)
print(f"  SMOKE TEST: {passed} passed, {failed} failed")
print("=" * 50)
sys.exit(1 if failed else 0)
