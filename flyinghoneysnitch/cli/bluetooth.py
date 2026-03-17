"""Bluetooth commands for FlyingHoneySnitch CLI.

Provides `fhs bluetooth` subcommands for BlueScout Bluetooth scanning.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def bluetooth():
    """Bluetooth scanning commands (BlueScout)."""
    pass


@bluetooth.command("scan")
@click.option("--device", "-d", default="/dev/ubertooth0", help="Ubertooth device path.")
@click.option("--duration", "-t", default=30, type=int, help="Scan duration in seconds.")
def bt_scan(device: str, duration: int) -> None:
    """Scan for Bluetooth devices using Ubertooth One.

    Requires an Ubertooth One device connected via USB.
    """
    import signal
    import time

    try:
        from flyinghoneysnitch.bluetooth.scanner import BluetoothScanner
    except ImportError:
        console.print(
            "[red]Bluetooth dependencies not installed.[/]\n"
            "Install with: pip install flyinghoneysnitch[bluetooth]"
        )
        raise SystemExit(1)

    scanner = BluetoothScanner(device=device)

    console.print(f"\n[bold cyan]BlueScout[/] - Bluetooth Scanning ({duration}s)")
    console.print(f"[dim]Device: {device}[/]\n")

    def handle_signal(signum, frame):
        scanner.stop()

    signal.signal(signal.SIGINT, handle_signal)

    scanner.start()

    start_time = time.time()
    try:
        while scanner.is_running and (time.time() - start_time) < duration:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    scanner.stop()

    # Display results
    devices = scanner.get_devices()

    if not devices:
        console.print("[yellow]No Bluetooth devices found.[/]")
        return

    table = Table(title=f"Bluetooth Devices ({len(devices)})")
    table.add_column("Address", style="bold")
    table.add_column("Type")
    table.add_column("RSSI", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for dev in devices:
        table.add_row(
            dev.address,
            dev.device_type,
            f"{dev.rssi} dBm",
            str(dev.first_seen),
            str(dev.last_seen),
        )

    console.print(table)
