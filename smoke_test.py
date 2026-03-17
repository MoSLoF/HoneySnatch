"""FlyingHoneySnitch comprehensive smoke test."""
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
import flyinghoneysnitch
check("__app_name__", lambda: assert_eq(flyinghoneysnitch.__app_name__, "FlyingHoneySnitch"))
check("__version__", lambda: assert_eq(flyinghoneysnitch.__version__, "0.1.0"))
check("core.models", lambda: __import__("flyinghoneysnitch.core.models"))
check("db.schema", lambda: __import__("flyinghoneysnitch.db.schema"))
check("db.database", lambda: __import__("flyinghoneysnitch.db.database"))
check("utils.config", lambda: __import__("flyinghoneysnitch.utils.config"))
check("utils.crypto", lambda: __import__("flyinghoneysnitch.utils.crypto"))
check("utils.logger", lambda: __import__("flyinghoneysnitch.utils.logger"))
check("analysis", lambda: __import__("flyinghoneysnitch.analysis"))
check("mapping", lambda: __import__("flyinghoneysnitch.mapping"))
check("monitoring", lambda: __import__("flyinghoneysnitch.monitoring"))
check("cellular", lambda: __import__("flyinghoneysnitch.cellular"))
check("cli.main", lambda: __import__("flyinghoneysnitch.cli.main"))
check("cli.isolation", lambda: __import__("flyinghoneysnitch.cli.isolation"))

# === 2. Isolation Package Imports ===
print("\n=== 2. Isolation Package Imports ===")
check("isolation", lambda: __import__("flyinghoneysnitch.isolation"))
check("isolation.config", lambda: __import__("flyinghoneysnitch.isolation.config"))
check("isolation.models", lambda: __import__("flyinghoneysnitch.isolation.models"))
check("isolation.runner", lambda: __import__("flyinghoneysnitch.isolation.runner"))
check("isolation.daemon", lambda: __import__("flyinghoneysnitch.isolation.daemon"))
check("isolation.monitor", lambda: __import__("flyinghoneysnitch.isolation.monitor"))
check("isolation.supplicant", lambda: __import__("flyinghoneysnitch.isolation.supplicant"))
check("isolation.attacks", lambda: __import__("flyinghoneysnitch.isolation.attacks"))
check("isolation.attacks.base", lambda: __import__("flyinghoneysnitch.isolation.attacks.base"))
check("isolation.attacks.gtk_abuse", lambda: __import__("flyinghoneysnitch.isolation.attacks.gtk_abuse"))
check("isolation.attacks.client2client", lambda: __import__("flyinghoneysnitch.isolation.attacks.client2client"))
check("isolation.attacks.client2monitor", lambda: __import__("flyinghoneysnitch.isolation.attacks.client2monitor"))
check("isolation.attacks.port_steal", lambda: __import__("flyinghoneysnitch.isolation.attacks.port_steal"))
check("isolation.attacks.broadcast_reflection", lambda: __import__("flyinghoneysnitch.isolation.attacks.broadcast_reflection"))
check("isolation.attacks.gateway_bounce", lambda: __import__("flyinghoneysnitch.isolation.attacks.gateway_bounce"))
check("isolation.libwifi", lambda: __import__("flyinghoneysnitch.isolation.libwifi"))
check("isolation.libwifi.crypto", lambda: __import__("flyinghoneysnitch.isolation.libwifi.crypto"))
check("isolation.framework", lambda: __import__("flyinghoneysnitch.isolation.framework"))
check("isolation.framework.testcase", lambda: __import__("flyinghoneysnitch.isolation.framework.testcase"))
check("isolation.framework.daemon", lambda: __import__("flyinghoneysnitch.isolation.framework.daemon"))
check("isolation.framework.station", lambda: __import__("flyinghoneysnitch.isolation.framework.station"))
check("isolation.port_restoration", lambda: __import__("flyinghoneysnitch.isolation.port_restoration"))

# === 3. Config System ===
print("\n=== 3. Config System ===")
from flyinghoneysnitch.utils.config import AppConfig
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
    from flyinghoneysnitch.db.database import DatabaseManager
    from flyinghoneysnitch.core.models import AccessPoint, Client, EncryptionType, GeoPosition

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

    # Verify isolation tables exist
    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(db.engine)
    tables = inspector.get_table_names()
    check("isolation_sessions table exists", lambda: assert_eq("isolation_sessions" in tables, True))
    check("isolation_results table exists", lambda: assert_eq("isolation_results" in tables, True))
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
from flyinghoneysnitch.isolation.attacks.base import AttackType, AttackOutcome, AttackResult
from flyinghoneysnitch.isolation.models import IsolationTestSession

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

# All attack factories
from flyinghoneysnitch.isolation.attacks.gtk_abuse import check_gtk_shared
from flyinghoneysnitch.isolation.attacks.broadcast_reflection import create_broadcast_reflection_result
from flyinghoneysnitch.isolation.attacks.gateway_bounce import create_gateway_bounce_result
from flyinghoneysnitch.isolation.attacks.port_steal import create_port_steal_result
from flyinghoneysnitch.isolation.attacks.client2client import create_c2c_result
from flyinghoneysnitch.isolation.attacks.client2monitor import create_c2m_result

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

# === 6. Isolation Runner ===
print("\n=== 6. Isolation Runner ===")
from flyinghoneysnitch.isolation.runner import IsolationTestRunner
runner = IsolationTestRunner(interface="wlan0")
check("IsolationTestRunner creation", lambda: None)

gtk_r = runner.run_gtk_check("wlan1")
check("runner.run_gtk_check (inconclusive without hw)", lambda: assert_eq(gtk_r.outcome, AttackOutcome.INCONCLUSIVE))

session_result = runner.run_all("wlan1")
check("runner.run_all returns session", lambda: assert_eq(session_result.session_id is not None, True))
check("runner.run_all has results", lambda: assert_eq(len(session_result.results) > 0, True))
check("runner.run_all finished", lambda: assert_eq(session_result.end_time is not None, True))

# === 7. CLI Registration ===
print("\n=== 7. CLI Registration ===")
from click.testing import CliRunner
from flyinghoneysnitch.cli.main import cli
cli_runner = CliRunner()

result_ver = cli_runner.invoke(cli, ["--version"])
check("fhs --version", lambda: assert_eq("0.1.0" in result_ver.output, True))

result_help = cli_runner.invoke(cli, ["--help"])
for cmd in ["scan", "analyze", "export", "monitor", "bluetooth", "cellular", "isolation", "gui", "info", "audit"]:
    check(f"CLI has '{cmd}'", lambda c=cmd: assert_eq(c in result_help.output, True))

result_iso = cli_runner.invoke(cli, ["isolation", "--help"])
for sub in ["test", "c2c", "c2m", "run-all", "setup", "build"]:
    check(f"isolation has '{sub}'", lambda s=sub: assert_eq(s in result_iso.output, True))

# === 8. Crypto (FHS magic) ===
print("\n=== 8. Crypto (FHS magic) ===")
from flyinghoneysnitch.utils.crypto import MAGIC, encrypt_file, decrypt_file, is_encrypted_file
check("MAGIC == FHS\\x01", lambda: assert_eq(MAGIC, b"FHS\x01"))

tmpdir2 = tempfile.mkdtemp()
try:
    src = os.path.join(tmpdir2, "plain.txt")
    enc = os.path.join(tmpdir2, "encrypted.fhs")
    dec = os.path.join(tmpdir2, "decrypted.txt")
    with open(src, "w") as f:
        f.write("FlyingHoneySnitch smoke test data")
    encrypt_file(src, enc, "testpass123")
    check("encrypt_file creates file", lambda: assert_eq(os.path.exists(enc), True))
    check("is_encrypted_file", lambda: assert_eq(is_encrypted_file(enc), True))
    check("plain file not encrypted", lambda: assert_eq(is_encrypted_file(src), False))
    decrypt_file(enc, dec, "testpass123")
    with open(dec) as f:
        content = f.read()
    check("decrypt roundtrip matches", lambda: assert_eq(content, "FlyingHoneySnitch smoke test data"))
finally:
    shutil.rmtree(tmpdir2)

# === 9. libwifi CCMP Crypto ===
print("\n=== 9. libwifi CCMP Crypto ===")
from flyinghoneysnitch.isolation.libwifi.crypto import encrypt_ccmp, decrypt_ccmp, aes_wrap_key
check("encrypt_ccmp callable", lambda: assert_eq(callable(encrypt_ccmp), True))
check("decrypt_ccmp callable", lambda: assert_eq(callable(decrypt_ccmp), True))
check("aes_wrap_key callable", lambda: assert_eq(callable(aes_wrap_key), True))

# === 10. Data Files ===
print("\n=== 10. Data Files ===")
data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
check("data/ dir exists", lambda: assert_eq(os.path.isdir(data_dir), True))
check("default_config.yaml exists", lambda: assert_eq(os.path.isfile(os.path.join(data_dir, "default_config.yaml")), True))
iso_dir = os.path.join(data_dir, "isolation")
check("data/isolation/ exists", lambda: assert_eq(os.path.isdir(iso_dir), True))
iso_files = os.listdir(iso_dir)
check("isolation configs present", lambda: assert_eq(len(iso_files) > 5, True))

# === 11. Vendor Directory ===
print("\n=== 11. Vendor Directory ===")
vendor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
check("vendor/ dir exists", lambda: assert_eq(os.path.isdir(vendor_dir), True))
check("vendor/build.sh exists", lambda: assert_eq(os.path.isfile(os.path.join(vendor_dir, "build.sh")), True))
check("vendor/hostap_2_10/ exists", lambda: assert_eq(os.path.isdir(os.path.join(vendor_dir, "hostap_2_10")), True))

# === Summary ===
print()
print("=" * 50)
print(f"  SMOKE TEST: {passed} passed, {failed} failed")
print("=" * 50)
sys.exit(1 if failed else 0)
