"""Isolation testing commands for the FlyingHoneySnitch CLI.

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
from rich.table import Table
from rich.text import Text

console = Console()


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
@click.option("--second-interface", "-j", default=None,
              help="Second wireless interface (attacker). Defaults to same as --interface.")
def test_isolation(interface, config, server, simulate, second_interface):
    """Run a GTK-shared check (context override / GTK abuse test).

    Connects as victim and attacker to the same network and checks
    whether both clients receive the same GTK.  A shared GTK allows
    injection of broadcast Wi-Fi frames containing unicast IP payloads.
    """
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
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
def test_c2c(interface, second_interface, config, mode, server, simulate):
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
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
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
def test_c2m(interface, monitor_interface, config, channel, simulate):
    """Run client-to-monitor isolation test.

    Puts ``monitor-interface`` into monitor mode, generates traffic on
    ``interface``, and checks whether the monitor sees the frames.
    A positive result indicates the AP/network does not isolate traffic
    at the radio layer.
    """
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    if channel:
        try:
            from flyinghoneysnitch.isolation.libwifi.wifi import set_channel
            set_channel(monitor_interface, channel)
            console.print(f"Set {monitor_interface} to channel {channel}")
        except Exception as exc:
            console.print(f"[yellow]Warning: could not set channel: {exc}[/]")

    runner = IsolationTestRunner(
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
@click.option("--output-db", default=None,
              help="Path to .db file to persist results.")
def run_all(interface, second_interface, config, simulate, output_db):
    """Run the full isolation test battery and show a summary table.

    Tests: GTK check, C2C-IP, C2C-ARP, C2C-broadcast, gateway bounce,
    broadcast reflection, port-steal downlink, port-steal uplink.
    """
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        interface=interface,
        config_file=config or "",
        second_interface=second_interface,
        simulate=simulate,
    )

    console.print(f"\n[bold]FlyingHoneySnitch — Isolation Test Battery[/]")
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
            from flyinghoneysnitch.db.database import DatabaseManager
            db = DatabaseManager(output_db)
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
            "Ensure you have cloned the full FlyingHoneySnitch repository "
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
    from flyinghoneysnitch.db.schema import (
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
