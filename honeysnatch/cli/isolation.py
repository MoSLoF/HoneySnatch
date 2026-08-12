"""Isolation testing commands for the honeysnatch CLI.

Provides `fhs isolation` subcommands for running client isolation
vulnerability tests based on the AirSnitch research framework.

Hardware required
-----------------
  - Compiled hostap binaries (``fhs isolation build``)
  - Linux with CAP_NET_RAW (root)
  - One or two monitor-mode capable Wi-Fi adapters
  - ``data/isolation/client.conf`` with two network blocks

Simulation mode
---------------
  Pass ``--simulate`` to any command to run without hardware.
  Results will be INCONCLUSIVE but validate the CLI path end-to-end.
"""
from __future__ import annotations

import click
from rich.console import Console
from honeysnatch.db.factory import open_database
from rich.table import Table
from rich.text import Text

console = Console()


# Shared consent options (review finding F-04): every live isolation
# entry point must present either a fresh CLI acknowledgment or a
# previously-granted persistent token for the target BSSID.
_target_opt = click.option(
    "--target-bssid", "-t", default=None,
    help="BSSID of the network under test (required for non-simulate runs).",
)
_ack_opt = click.option(
    "--i-have-permission-to-attack", "ack_bssid", default=None,
    metavar="BSSID",
    help=(
        "Explicit consent affirmation. Value MUST match --target-bssid. "
        "Acknowledgment lands in the audit log as evidence of authorization."
    ),
)


def _gate_or_die(target_bssid, ack_bssid, simulate, **context):
    """Run the consent gate; convert its exceptions to click aborts.

    Returns an :class:`Authorization` (or None if simulate). HS-02R
    (v0.1.4): the consent capability is now returned by require_consent
    as a ConsentReceipt; from_cli_ack requires that receipt, so a
    caller that bypasses require_consent cannot obtain an Authorization.
    """
    from honeysnatch.isolation.consent import (
        Authorization, ConsentRequiredError, BadBssidError, require_consent,
    )
    try:
        receipt = require_consent(
            bssid=target_bssid,
            ack_bssid=ack_bssid,
            simulate=simulate,
            context=context,
        )
    except (ConsentRequiredError, BadBssidError) as exc:
        console.print(f"\n[bold red]Refused:[/] {exc}")
        raise SystemExit(2)

    if simulate:
        return None
    # AUTH-01 (v0.1.5): dispatch to the factory that matches the
    # receipt's source. A CLI-ack receipt goes to from_cli_ack; a
    # token-derived receipt goes to from_token (where Authorization
    # will revalidate the on-disk token before every live method).
    if receipt.source == "token":
        return Authorization.from_token(target_bssid, receipt)
    return Authorization.from_cli_ack(target_bssid, receipt)


@click.group()
def isolation():
    """Client isolation vulnerability testing (AirSnitch)."""
    pass


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

_iface_opt    = click.option("--interface", "-i", required=True,
                              help="Primary wireless interface (victim).")
_config_opt   = click.option("--config", "-c", default=None,
                              help="wpa_supplicant config file.")
_server_opt   = click.option("--server", default="8.8.8.8",
                              help="Server IP for TCP/ICMP reachability probe.")
_simulate_opt = click.option("--simulate", is_flag=True, default=False,
                              help="Skip hardware; return INCONCLUSIVE (useful for CI).")


# ---------------------------------------------------------------------------
# fhs isolation test  — context override / GTK check
# ---------------------------------------------------------------------------

@isolation.command("test")
@_iface_opt
@_config_opt
@_server_opt
@_simulate_opt
@_target_opt
@_ack_opt
@click.option("--second-interface", "-j", default=None,
              help="Second wireless interface (attacker). Defaults to same as --interface.")
def test_isolation(interface, config, server, simulate, target_bssid, ack_bssid, second_interface):
    """Run a GTK-shared check (context override / GTK abuse test).

    Connects as victim and attacker to the same network and checks
    whether both clients receive the same GTK.  A shared GTK allows
    injection of broadcast Wi-Fi frames containing unicast IP payloads.
    """
    _authz = _gate_or_die(target_bssid, ack_bssid, simulate,
                 command="isolation test", interface=interface,
                 second_interface=second_interface or interface)

    from honeysnatch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        authorization=_authz,
        interface=interface,
        config_file=config or "",
        server=server,
        second_interface=second_interface or interface,
        simulate=simulate,
    )
    result = runner.run_gtk_check(second_interface or interface)
    _print_result("GTK check", result)


# ---------------------------------------------------------------------------
# fhs isolation c2c  — client-to-client
# ---------------------------------------------------------------------------

@isolation.command("c2c")
@_iface_opt
@click.option("--second-interface", "-j", required=True,
              help="Second wireless interface (attacker).")
@_config_opt
@click.option(
    "--mode",
    type=click.Choice(["arp", "ethernet", "ip", "broadcast",
                       "port-steal-down", "port-steal-up",
                       "gtk", "gw-bounce", "bcast-reflect"]),
    default="ip",
    help="Test mode.",
)
@_server_opt
@_simulate_opt
@_target_opt
@_ack_opt
def test_c2c(interface, second_interface, config, mode, server, simulate,
             target_bssid, ack_bssid):
    """Run client-to-client isolation tests using two interfaces.

    \b
    Modes:
      arp              ARP request direct to victim
      ethernet         Raw Ethernet unicast to victim MAC
      ip               IP ping / TCP SYN to victim IP          [default]
      broadcast        Broadcast Ethernet with unicast IP dst (GTK-abuse)
      port-steal-down  Spoof victim MAC to intercept downlink
      port-steal-up    Spoof gateway MAC to intercept uplink
      gtk              GTK shared-key check
      gw-bounce        Gateway bouncing (MAC=GW but IP=victim)
      bcast-reflect    Broadcast reflection
    """
    _authz = _gate_or_die(target_bssid, ack_bssid, simulate,
                 command=f"isolation c2c --mode {mode}",
                 interface=interface, second_interface=second_interface)

    from honeysnatch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        authorization=_authz,
        interface=interface,
        config_file=config or "",
        server=server,
        second_interface=second_interface,
        simulate=simulate,
    )

    dispatch = {
        "gtk":            lambda: runner.run_gtk_check(second_interface),
        "port-steal-down": lambda: runner.run_port_steal(second_interface, direction="downlink"),
        "port-steal-up":  lambda: runner.run_port_steal(second_interface, direction="uplink"),
        "gw-bounce":      lambda: runner.run_gateway_bounce(second_interface),
        "bcast-reflect":  lambda: runner.run_broadcast_reflection(second_interface),
    }

    if mode in dispatch:
        result = dispatch[mode]()
    else:
        result = runner.run_client2client(second_interface, mode=mode)

    _print_result(f"C2C-{mode}", result)


# ---------------------------------------------------------------------------
# fhs isolation c2m  — client-to-monitor
# ---------------------------------------------------------------------------

@isolation.command("c2m")
@_iface_opt
@click.option("--monitor-interface", "-m", required=True,
              help="Monitor-mode interface for passive capture.")
@_config_opt
@click.option("--channel", type=int, default=None,
              help="Set monitor interface to this channel before capture.")
@_simulate_opt
@_target_opt
@_ack_opt
def test_c2m(interface, monitor_interface, config, channel, simulate,
             target_bssid, ack_bssid):
    """Run client-to-monitor isolation test.

    Puts ``monitor-interface`` into monitor mode, generates traffic on
    ``interface``, and checks whether the monitor sees the frames.
    A positive result indicates the AP/network does not isolate traffic
    at the radio layer.
    """
    _authz = _gate_or_die(target_bssid, ack_bssid, simulate,
                 command="isolation c2m", interface=interface,
                 monitor_interface=monitor_interface)

    from honeysnatch.isolation.runner import IsolationTestRunner

    if channel:
        try:
            from honeysnatch.isolation.libwifi.wifi import set_channel
            set_channel(monitor_interface, channel)
            console.print(f"Set {monitor_interface} to channel {channel}")
        except Exception as exc:
            console.print(f"[yellow]Warning: could not set channel: {exc}[/]")

    runner = IsolationTestRunner(
        authorization=_authz,
        interface=interface,
        config_file=config or "",
        simulate=simulate,
    )
    result = runner.run_client2monitor(monitor_interface)
    _print_result("C2M", result)


# ---------------------------------------------------------------------------
# fhs isolation run-all  — full battery
# ---------------------------------------------------------------------------

@isolation.command("run-all")
@_iface_opt
@click.option("--second-interface", "-j", required=True,
              help="Second wireless interface.")
@_config_opt
@_simulate_opt
@_target_opt
@_ack_opt
@click.option("--output-db", default=None,
              help="Path to .db file to persist results.")
@click.pass_context
def run_all(ctx: click.Context, interface, second_interface, config, simulate,
            target_bssid, ack_bssid, output_db):
    """Run the full isolation test battery and show a summary table.

    Tests: GTK check, C2C-IP, C2C-ARP, C2C-broadcast, gateway bounce,
    broadcast reflection, port-steal downlink, port-steal uplink.
    """
    _authz = _gate_or_die(target_bssid, ack_bssid, simulate,
                 command="isolation run-all", interface=interface,
                 second_interface=second_interface)

    from honeysnatch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        authorization=_authz,
        interface=interface,
        config_file=config or "",
        second_interface=second_interface,
        simulate=simulate,
    )

    console.print(f"\n[bold]honeysnatch — Isolation Test Battery[/]")
    console.print(f"  Victim:   {interface}")
    console.print(f"  Attacker: {second_interface}")
    if simulate:
        console.print("  [yellow]⚠  Simulation mode — no hardware required[/]\n")

    session = runner.run_all(second_interface)

    table = Table(title="Isolation Test Results", show_header=True)
    table.add_column("Attack",   style="bold", min_width=28)
    table.add_column("Outcome",  min_width=14)
    table.add_column("Details",  overflow="fold")

    for result in session.results:
        outcome_text, style = _outcome_cell(result.outcome.value)
        table.add_row(
            result.attack_type.value,
            Text(outcome_text, style=style),
            result.details[:90] + ("…" if len(result.details) > 90 else ""),
        )

    console.print(table)
    console.print(
        f"\n[red]Vulnerable: {session.vulnerable_count}[/]  "
        f"[green]Secure: {session.secure_count}[/]  "
        f"[yellow]Inconclusive: "
        f"{session.total_count - session.vulnerable_count - session.secure_count}[/]  "
        f"Total: {session.total_count}"
    )

    # Optionally persist
    if output_db:
        try:
            db = open_database(output_db, config=ctx.obj.get('config'))
            _persist_isolation_session(db, session)
            console.print(f"\n[green]Results saved to {output_db}[/]")
        except Exception as exc:
            console.print(f"\n[red]Could not save to DB: {exc}[/]")


# ---------------------------------------------------------------------------
# fhs isolation setup  — environment setup scripts
# ---------------------------------------------------------------------------

@isolation.command("setup")
@click.argument("scenario",
                type=click.Choice(["gtkabuse", "gwbounce", "portsteal", "hwsim"]))
def setup_environment(scenario):
    """Run a bridge/hwsim setup script for the chosen test scenario.

    \b
    Scenarios:
      gtkabuse   br0 bridge suitable for GTK injection tests
      gwbounce   br0 bridge with gateway routing for bounce tests
      portsteal  Multi-AP bridge for port-stealing tests
      hwsim      mac80211_hwsim virtual radios (no physical hardware needed)
    """
    import subprocess
    from pathlib import Path

    scripts = {
        "gtkabuse":  "setup-br0-gtkabuse.sh",
        "gwbounce":  "setup-br0-gwbounce.sh",
        "portsteal": "setup-br0-portsteal.sh",
        "hwsim":     "setup-hwsim.sh",
    }

    script_dir = Path(__file__).resolve().parents[2] / "vendor" / "setup"
    script_path = script_dir / scripts[scenario]

    if not script_path.exists():
        console.print(f"[red]Setup script not found: {script_path}[/]")
        console.print("Run `fhs isolation build` first to populate the vendor/ directory.")
        raise SystemExit(1)

    console.print(f"Running setup: [bold]{scenario}[/] ({script_path.name})")
    subprocess.run(["bash", str(script_path)], check=True)
    console.print("[green]Setup complete.[/]")


# ---------------------------------------------------------------------------
# fhs isolation build  — compile hostap vendor binaries
# ---------------------------------------------------------------------------

@isolation.command("build")
@click.option("--hostap-version", default="hostap_2_10",
              type=click.Choice(["hostap_2_9", "hostap_2_10"]),
              help="hostap release to compile.")
def build_hostap(hostap_version):
    """Compile the modified hostapd and wpa_supplicant from vendor/.

    Run this once before using any isolation tests that require
    active wireless connections.  Requires: libnl, libssl, libdbus,
    gcc, make (see README for full dependency list).
    """
    import subprocess
    from pathlib import Path

    vendor_dir = Path(__file__).resolve().parents[2] / "vendor"
    build_script = vendor_dir / "build.sh"

    if not build_script.exists():
        console.print(f"[red]Build script not found: {build_script}[/]")
        console.print(
            "Ensure you have cloned the full honeysnatch repository "
            "including the vendor/ subtree."
        )
        raise SystemExit(1)

    console.print(f"Building [bold]{hostap_version}[/] (this may take a minute)…")
    result = subprocess.run(
        ["bash", str(build_script), hostap_version],
        cwd=str(vendor_dir),
    )
    if result.returncode == 0:
        console.print("[green]Build complete.[/]")
    else:
        console.print("[red]Build failed — check the output above.[/]")
        raise SystemExit(result.returncode)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _outcome_cell(outcome_str: str) -> tuple[str, str]:
    return {
        "vulnerable":   ("● VULNERABLE",   "bold red"),
        "secure":       ("● SECURE",       "bold green"),
        "inconclusive": ("○ INCONCLUSIVE", "yellow"),
        "error":        ("✗ ERROR",        "bold red"),
    }.get(outcome_str, (outcome_str.upper(), "white"))


def _print_result(name: str, result) -> None:
    """Print a single attack result to the console."""
    label, style = _outcome_cell(result.outcome.value)
    console.print(f"\n[bold]{name}[/]: [{style}]{label}[/]")
    if result.details:
        console.print(f"  [dim]{result.details}[/]")


def _persist_isolation_session(db, session) -> None:
    """Persist an IsolationTestSession to the database."""
    from honeysnatch.db.schema import (
        IsolationSessionRecord,
        IsolationResultRecord,
    )
    with db.get_session() as dbs:
        sess_rec = IsolationSessionRecord(
            session_id=session.session_id,
            name=session.name,
            interface=session.interface,
            second_interface=session.second_interface,
            target_ssid=session.target_ssid,
            target_bssid=session.target_bssid,
            config_file=session.config_file,
            start_time=session.start_time,
            end_time=session.end_time,
        )
        dbs.add(sess_rec)
        dbs.flush()

        for r in session.results:
            res_rec = IsolationResultRecord(
                session_id=sess_rec.id,
                attack_type=r.attack_type.value,
                outcome=r.outcome.value,
                target_bssid=r.target_bssid,
                target_ssid=r.target_ssid,
                victim_identity=r.victim_identity,
                attacker_identity=r.attacker_identity,
                victim_mac=r.victim_mac,
                attacker_mac=r.attacker_mac,
                details=r.details,
                duration_seconds=r.duration_seconds,
                timestamp=r.timestamp,
                raw_log="\n".join(r.raw_log),
            )
            dbs.add(res_rec)
        dbs.commit()


# ---------------------------------------------------------------------------
# fhs isolation consent  — manage persistent consent tokens (F-04)
# ---------------------------------------------------------------------------

@isolation.group("consent")
def consent_group():
    """Manage persistent consent tokens for live isolation testing."""
    pass


@consent_group.command("grant")
@click.argument("bssid")
@click.option("--window-minutes", "-w", type=int, default=60, show_default=True,
              help="Token lifetime in minutes (1-1440).")
@click.option("--reason", "-r", default="",
              help="Free-text authorization note (recorded in audit log).")
def consent_grant(bssid, window_minutes, reason):
    """Grant a persistent consent token for BSSID.

    Every live isolation command against BSSID within the window will be
    authorized without the --i-have-permission-to-attack acknowledgment.
    The grant itself is recorded in the audit log.
    """
    from honeysnatch.isolation.consent import (
        BadBssidError, grant_consent,
    )
    from honeysnatch.utils.audit import get_audit_logger

    try:
        token = grant_consent(bssid, window_minutes=window_minutes, reason=reason)
    except (BadBssidError, ValueError) as exc:
        console.print(f"[bold red]Refused:[/] {exc}")
        raise SystemExit(2)

    get_audit_logger().record(
        "isolation_consent_granted",
        {
            "bssid": token.bssid,
            "granted_by": token.granted_by,
            "granted_at": token.granted_at,
            "expires_at": token.expires_at,
            "window_minutes": window_minutes,
            "reason": token.reason,
        },
    )
    console.print(
        f"[green]Granted consent for [bold]{token.bssid}[/][/] until "
        f"[bold]{token.expires_at}[/] (by {token.granted_by})."
    )


@consent_group.command("list")
def consent_list():
    """List all persistent consent tokens on this host."""
    from datetime import datetime, timezone
    from honeysnatch.isolation.consent import _default_store_dir, load_consent

    store = _default_store_dir()
    if not store.exists():
        console.print("[dim]No consent tokens on this host.[/]")
        return

    now = datetime.now(timezone.utc)
    table = Table(title="Consent Tokens")
    table.add_column("BSSID")
    table.add_column("Granted at (UTC)")
    table.add_column("Expires at (UTC)")
    table.add_column("Status")
    table.add_column("Granted by")

    found = 0
    for f in sorted(store.glob("*.json")):
        # Reconstruct BSSID from filename (12 hex chars → aa:bb:cc:dd:ee:ff).
        stem = f.stem
        if len(stem) != 12:
            continue
        bssid = ":".join(stem[i:i+2] for i in range(0, 12, 2))
        tok = load_consent(bssid)
        if tok is None:
            continue
        found += 1
        status = "valid" if tok.is_valid_for(bssid, now) else "EXPIRED"
        style = "green" if status == "valid" else "yellow"
        table.add_row(tok.bssid, tok.granted_at, tok.expires_at,
                      Text(status, style=style), tok.granted_by)

    if found == 0:
        console.print("[dim]No consent tokens on this host.[/]")
    else:
        console.print(table)


@consent_group.command("revoke")
@click.argument("bssid")
def consent_revoke(bssid):
    """Revoke a persistent consent token by BSSID."""
    from honeysnatch.isolation.consent import (
        BadBssidError, canonicalize_bssid, _default_store_dir,
    )
    from honeysnatch.utils.audit import get_audit_logger

    try:
        canonical = canonicalize_bssid(bssid)
    except BadBssidError as exc:
        console.print(f"[bold red]Refused:[/] {exc}")
        raise SystemExit(2)

    path = _default_store_dir() / f"{canonical.replace(':', '')}.json"
    if not path.exists():
        console.print(f"[yellow]No token to revoke for {canonical}.[/]")
        return

    path.unlink()
    get_audit_logger().record("isolation_consent_revoked", {"bssid": canonical})
    console.print(f"[green]Revoked consent for {canonical}.[/]")
