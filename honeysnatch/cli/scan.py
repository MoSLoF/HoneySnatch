"""Scan commands for the honeysnatch CLI.

Provides `fhs scan` subcommands for starting/stopping wireless scans,
listing interfaces, and viewing scan results.
"""

from __future__ import annotations

import signal
import sys
import time

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from honeysnatch.core.models import ScanEvent

console = Console()


@click.group()
def scan():
    """Wireless scanning commands."""
    pass


@scan.command("start")
@click.option(
    "--interface", "-i",
    required=True,
    help="Wireless interface to use (must support monitor mode).",
)
@click.option(
    "--channels", "-c",
    default=None,
    help="Comma-separated channel list (e.g., '1,6,11' or '1-14').",
)
@click.option(
    "--hop-interval", "-t",
    default=0.5,
    type=float,
    help="Channel hop interval in seconds.",
)
@click.option(
    "--no-5ghz",
    is_flag=True,
    default=False,
    help="Skip 5 GHz channels.",
)
@click.option(
    "--capture", "-w",
    default=None,
    type=click.Path(),
    help="Save packets to pcap file in this directory.",
)
@click.option(
    "--name", "-n",
    default="",
    help="Name for this scan session.",
)
@click.option(
    "--duration", "-d",
    default=0,
    type=int,
    help="Scan duration in seconds (0 = unlimited).",
)
@click.pass_context
def start_scan(
    ctx: click.Context,
    interface: str,
    channels: str | None,
    hop_interval: float,
    no_5ghz: bool,
    capture: str | None,
    name: str,
    duration: int,
) -> None:
    """Start a passive WiFi scan.

    Requires a wireless interface in monitor mode. Use `fhs scan list-interfaces`
    to see available interfaces.

    Examples:

        fhs scan start -i wlan0mon

        fhs scan start -i wlan0mon -c 1,6,11 -d 60

        fhs scan start -i wlan0mon --capture /tmp/captures
    """
    from honeysnatch.utils.permissions import check_permissions

    # Check permissions
    perms = check_permissions()
    if not perms.can_scan:
        console.print(f"[red]Error:[/] {perms.message}")
        raise SystemExit(1)

    # Parse channels
    channel_list = None
    if channels:
        channel_list = _parse_channels(channels)
        if not channel_list:
            console.print("[red]Error:[/] Invalid channel specification")
            raise SystemExit(1)

    # Initialize scanner
    from honeysnatch.core.scanner import WifiScanner

    scanner = WifiScanner(
        interface=interface,
        channels=channel_list,
        hop_interval=hop_interval,
        scan_5ghz=not no_5ghz,
        session_name=name,
    )

    # Initialize pcap capture if requested
    pcap_capture = None
    if capture:
        from honeysnatch.core.capture import PcapCapture
        pcap_capture = PcapCapture(output_dir=capture)
        pcap_path = pcap_capture.start()
        console.print(f"[dim]Recording to:[/] {pcap_path}")

    # Set up live display
    console.print(f"\n[bold cyan]honeysnatch[/] - Scanning on [bold]{interface}[/]")
    console.print("[dim]Press Ctrl+C to stop\n[/]")

    # Signal handler for graceful shutdown
    def handle_signal(signum, frame):
        scanner.stop()
        if pcap_capture:
            pcap_capture.stop()

    signal.signal(signal.SIGINT, handle_signal)

    # Event handler for live display
    def on_event(event: ScanEvent):
        if event.event_type == "ap_found" and event.ap:
            ap = event.ap
            enc_color = "green" if ap.encryption.value == "Open" else "yellow"
            console.print(
                f"  [green]+AP[/] {ap.bssid} "
                f"ch:{ap.channel:>3} "
                f"[{enc_color}]{ap.encryption.value:<12}[/] "
                f"{ap.rssi:>4} dBm  "
                f"[bold]{ap.ssid or '[Hidden]'}[/]"
                f"  {ap.vendor}"
            )
        elif event.event_type == "client_found" and event.client:
            cl = event.client
            assoc = f"-> {cl.bssid}" if cl.bssid else "[not associated]"
            console.print(
                f"  [blue]+Client[/] {cl.mac} "
                f"{cl.rssi:>4} dBm  "
                f"{assoc}  "
                f"{cl.vendor}"
            )

    scanner.on_event(on_event)

    # Start scanning
    scanner.start()

    # Wait for duration or Ctrl+C
    try:
        if duration > 0:
            start_time = time.time()
            while scanner.is_running and (time.time() - start_time) < duration:
                time.sleep(1)
            scanner.stop()
        else:
            while scanner.is_running:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    if scanner.is_running:
        scanner.stop()

    if pcap_capture and pcap_capture.is_recording:
        pcap_capture.stop()

    # Print summary
    session = scanner.session
    console.print(f"\n[bold]Scan Summary[/]")
    console.print(f"  Duration:     {session.duration_seconds:.0f}s")
    console.print(f"  APs found:    {session.ap_count}")
    console.print(f"  Clients found:{session.client_count}")
    console.print(f"  Packets:      {scanner.packet_count}")
    console.print(f"  Hidden APs:   {scanner.hidden_ap_count}")

    # Save session to database
    config = ctx.obj["config"]
    from honeysnatch.db.database import create_session_db

    db = create_session_db(config.data_dir, session.name)
    db_session_id = db.create_scan_session(
        name=session.name,
        interface=session.interface,
        channels=session.channels,
    )
    for ap in session.access_points.values():
        db.save_access_point(db_session_id, ap)
    for client in session.clients.values():
        db.save_client(db_session_id, client)
    db.end_scan_session(db_session_id)
    db.close()

    console.print(f"\n  [dim]Session saved: {db.db_path}[/]")


@scan.command("list-interfaces")
def list_interfaces() -> None:
    """List available wireless interfaces."""
    from honeysnatch.utils.interfaces import list_wireless_interfaces

    interfaces = list_wireless_interfaces()

    if not interfaces:
        console.print("[yellow]No wireless interfaces found.[/]")
        console.print("[dim]Ensure you have a wireless adapter connected.[/]")
        return

    table = Table(title="Wireless Interfaces")
    table.add_column("Interface", style="bold")
    table.add_column("PHY")
    table.add_column("Mode")
    table.add_column("MAC")
    table.add_column("Driver")
    table.add_column("Monitor", justify="center")

    for iface in interfaces:
        table.add_row(
            iface.name,
            iface.phy,
            iface.mode,
            iface.mac,
            iface.driver or "-",
            "[green]Yes[/]" if iface.supports_monitor else "[red]No[/]",
        )

    console.print(table)


@scan.command("enable-monitor")
@click.argument("interface")
def enable_monitor(interface: str) -> None:
    """Enable monitor mode on a wireless interface."""
    from honeysnatch.utils.interfaces import enable_monitor_mode
    from honeysnatch.utils.permissions import check_permissions

    perms = check_permissions()
    if not perms.can_scan:
        console.print(f"[red]Error:[/] {perms.message}")
        raise SystemExit(1)

    result = enable_monitor_mode(interface)
    if result:
        console.print(f"[green]Monitor mode enabled:[/] {result}")
    else:
        console.print(f"[red]Failed to enable monitor mode on {interface}[/]")
        raise SystemExit(1)


@scan.command("disable-monitor")
@click.argument("interface")
def disable_monitor(interface: str) -> None:
    """Disable monitor mode on a wireless interface."""
    from honeysnatch.utils.interfaces import disable_monitor_mode

    if disable_monitor_mode(interface):
        console.print(f"[green]Monitor mode disabled:[/] {interface}")
    else:
        console.print(f"[red]Failed to disable monitor mode on {interface}[/]")


def _parse_channels(spec: str) -> list[int]:
    """Parse a channel specification string like '1,6,11' or '1-14' or '1-14,36-48'."""
    channels = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                channels.extend(range(int(start), int(end) + 1))
            except ValueError:
                return []
        else:
            try:
                channels.append(int(part))
            except ValueError:
                return []
    return sorted(set(channels))
