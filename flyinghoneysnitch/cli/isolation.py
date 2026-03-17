"""Isolation testing commands for the FlyingHoneySnitch CLI.

Provides `fhs isolation` subcommands for running client isolation
vulnerability tests based on the AirSnitch research framework.
"""
from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def isolation():
    """Client isolation vulnerability testing (AirSnitch)."""
    pass


@isolation.command("test")
@click.option("--interface", "-i", required=True, help="Primary wireless interface.")
@click.option("--config", "-c", default=None, help="wpa_supplicant config file.")
@click.option("--server", default="8.8.8.8", help="Server for TCP SYN challenge.")
@click.option("--same-bss", is_flag=True, help="Force same AP for victim and attacker.")
@click.option("--other-bss", is_flag=True, help="Force different APs.")
@click.option("--delay", default=0, type=float, help="Delay before reconnecting.")
@click.option("--same-id", is_flag=True, help="Reconnect under victim identity.")
@click.option("--flip-id", is_flag=True, help="Flip victim/attacker identities.")
@click.pass_context
def test_isolation(ctx, interface, config, server, same_bss, other_bss,
                   delay, same_id, flip_id):
    """Run a context override (MAC address stealing) test.

    Connects as a victim, sends a TCP SYN, then reconnects as attacker
    to check if victim's traffic is intercepted.
    """
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        interface=interface,
        config_file=config or "",
        server=server,
    )
    result = runner.run_gtk_check(interface)
    _print_result(result)


@isolation.command("c2c")
@click.option("--interface", "-i", required=True, help="Primary interface (victim).")
@click.option("--second-interface", "-j", required=True, help="Second interface (attacker).")
@click.option("--config", "-c", default=None, help="wpa_supplicant config file.")
@click.option("--mode", type=click.Choice(["arp", "ethernet", "ip", "broadcast",
              "port-steal", "gtk"]), default="ip", help="Test mode.")
@click.option("--same-bss", is_flag=True)
@click.option("--other-bss", is_flag=True)
@click.option("--server", default="8.8.8.8", help="Server for TCP SYN.")
@click.pass_context
def test_c2c(ctx, interface, second_interface, config, mode, same_bss,
             other_bss, server):
    """Run client-to-client isolation test using two interfaces."""
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        interface=interface,
        config_file=config or "",
        second_interface=second_interface,
    )
    if mode == "gtk":
        result = runner.run_gtk_check(second_interface)
    elif mode == "port-steal":
        result = runner.run_port_steal(second_interface)
    else:
        result = runner.run_client2client(second_interface, mode=mode)
    _print_result(result)


@isolation.command("c2m")
@click.option("--interface", "-i", required=True, help="Primary interface (attacker).")
@click.option("--monitor-interface", "-m", required=True, help="Monitor interface.")
@click.option("--config", "-c", default=None)
@click.option("--channel", type=int, help="Monitor channel.")
@click.pass_context
def test_c2m(ctx, interface, monitor_interface, config, channel):
    """Run client-to-monitor isolation test."""
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        interface=interface,
        config_file=config or "",
    )
    result = runner.run_client2monitor(monitor_interface)
    _print_result(result)


@isolation.command("run-all")
@click.option("--interface", "-i", required=True, help="Primary interface.")
@click.option("--second-interface", "-j", required=True, help="Second interface.")
@click.option("--config", "-c", default=None, help="wpa_supplicant config file.")
@click.pass_context
def run_all(ctx, interface, second_interface, config):
    """Run all isolation tests and show summary."""
    from flyinghoneysnitch.isolation.runner import IsolationTestRunner

    runner = IsolationTestRunner(
        interface=interface,
        config_file=config or "",
    )
    session = runner.run_all(second_interface)

    console.print(f"\n[bold]Isolation Test Session: {session.session_id}[/]\n")

    table = Table(title="Test Results")
    table.add_column("Attack", style="bold")
    table.add_column("Outcome")
    table.add_column("Details")

    for result in session.results:
        outcome_style = {
            "vulnerable": "[red]VULNERABLE[/]",
            "secure": "[green]SECURE[/]",
            "inconclusive": "[yellow]INCONCLUSIVE[/]",
            "error": "[red]ERROR[/]",
        }.get(result.outcome.value, result.outcome.value)

        table.add_row(
            result.attack_type.value,
            outcome_style,
            result.details[:80],
        )

    console.print(table)
    console.print(f"\nVulnerable: {session.vulnerable_count} | "
                  f"Secure: {session.secure_count} | "
                  f"Total: {session.total_count}")


@isolation.command("setup")
@click.argument("scenario", type=click.Choice(["gtkabuse", "gwbounce", "portsteal", "hwsim"]))
def setup_environment(scenario):
    """Run environment setup scripts for isolation testing."""
    import subprocess
    from pathlib import Path

    scripts = {
        "gtkabuse": "setup-br0-gtkabuse.sh",
        "gwbounce": "setup-br0-gwbounce.sh",
        "portsteal": "setup-br0-portsteal.sh",
        "hwsim": "setup-hwsim.sh",
    }

    script_dir = Path(__file__).resolve().parents[2] / "vendor" / "setup"
    script_path = script_dir / scripts[scenario]

    if not script_path.exists():
        console.print(f"[red]Setup script not found: {script_path}[/]")
        raise SystemExit(1)

    console.print(f"Running setup: {scenario}")
    subprocess.run(["bash", str(script_path)], check=True)


@isolation.command("build")
@click.option("--hostap-version", default="hostap_2_10",
              type=click.Choice(["hostap_2_9", "hostap_2_10"]))
def build_hostap(hostap_version):
    """Compile modified hostapd and wpa_supplicant from vendor/."""
    import subprocess
    from pathlib import Path

    vendor_dir = Path(__file__).resolve().parents[2] / "vendor"
    build_script = vendor_dir / "build.sh"

    if not build_script.exists():
        console.print(f"[red]Build script not found: {build_script}[/]")
        raise SystemExit(1)

    console.print(f"Building {hostap_version}...")
    subprocess.run(
        ["bash", str(build_script), hostap_version],
        cwd=str(vendor_dir),
        check=True,
    )
    console.print("[green]Build complete![/]")


def _print_result(result):
    """Print a single attack result."""
    outcome_style = {
        "vulnerable": "[red]VULNERABLE[/]",
        "secure": "[green]SECURE[/]",
        "inconclusive": "[yellow]INCONCLUSIVE[/]",
        "error": "[red]ERROR[/]",
    }.get(result.outcome.value, result.outcome.value)

    console.print(f"\n[bold]{result.attack_type.value}[/]: {outcome_style}")
    if result.details:
        console.print(f"  {result.details}")
