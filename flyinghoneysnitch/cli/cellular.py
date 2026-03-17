"""Cellular commands for FlyingHoneySnitch CLI.

Provides `fhs cellular` subcommands for CellGuard cellular scanning
and rogue base station detection.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def cellular():
    """Cellular network scanning commands (CellGuard)."""
    pass


@cellular.command("scan")
@click.option("--duration", "-t", default=60, type=int, help="Scan duration in seconds.")
@click.option("--gsm/--no-gsm", default=True, help="Enable GSM/2G scanning.")
@click.option("--lte/--no-lte", default=True, help="Enable LTE/4G scanning.")
@click.option("--rtl-device", default=0, type=int, help="RTL-SDR device index.")
@click.option("--hackrf-device", default="", help="HackRF device args.")
@click.option(
    "--bands", default=None,
    help="Comma-separated LTE band numbers (e.g., 2,4,7,12).",
)
def cell_scan(
    duration: int, gsm: bool, lte: bool,
    rtl_device: int, hackrf_device: str, bands: str | None,
) -> None:
    """Scan for cellular base stations.

    Uses RTL-SDR for GSM and HackRF for LTE scanning.
    Requires gr-gsm and/or srsRAN installed.
    """
    import signal
    import time

    try:
        from flyinghoneysnitch.cellular.scanner import CellularScanner
    except ImportError:
        console.print(
            "[red]Cellular dependencies not available.[/]\n"
            "Install: sudo apt install gr-gsm srsran hackrf rtl-sdr"
        )
        raise SystemExit(1)

    lte_bands = None
    if bands:
        lte_bands = [int(b.strip()) for b in bands.split(",")]

    scanner = CellularScanner(
        rtlsdr_device=rtl_device,
        hackrf_device=hackrf_device,
        scan_gsm=gsm,
        scan_lte=lte,
        lte_bands=lte_bands,
    )

    console.print(f"\n[bold cyan]CellGuard[/] - Cellular Scanning ({duration}s)")
    console.print(f"[dim]GSM={gsm} LTE={lte} RTL={rtl_device}[/]\n")

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
    towers = scanner.get_towers()

    if not towers:
        console.print("[yellow]No cell towers found.[/]")
        return

    table = Table(title=f"Cell Towers ({len(towers)})")
    table.add_column("CID", style="bold")
    table.add_column("Tech")
    table.add_column("PLMN")
    table.add_column("Operator")
    table.add_column("Freq (MHz)", justify="right")
    table.add_column("Band")
    table.add_column("RSSI", justify="right")

    for t in towers:
        table.add_row(
            t.cell_id,
            t.technology,
            t.plmn or "-",
            t.operator or "Unknown",
            f"{t.frequency_mhz:.1f}",
            t.band or "-",
            f"{t.rssi} dBm",
        )

    console.print(table)


@cellular.command("baseline")
@click.argument("output_path")
@click.option("--duration", "-t", default=120, type=int, help="Scan duration for baseline.")
@click.option("--gsm/--no-gsm", default=True)
@click.option("--lte/--no-lte", default=True)
@click.option("--rtl-device", default=0, type=int)
@click.option("--hackrf-device", default="")
def save_baseline(
    output_path: str, duration: int, gsm: bool, lte: bool,
    rtl_device: int, hackrf_device: str,
) -> None:
    """Scan and save current towers as known-good baseline.

    The baseline file is used by the detect command to identify rogue towers.
    """
    import time

    from flyinghoneysnitch.cellular.scanner import CellularScanner
    from flyinghoneysnitch.cellular.detector import RogueBaseStationDetector

    scanner = CellularScanner(
        rtlsdr_device=rtl_device,
        hackrf_device=hackrf_device,
        scan_gsm=gsm,
        scan_lte=lte,
    )

    console.print(f"\n[bold cyan]CellGuard[/] - Building Baseline ({duration}s)")
    console.print("Scanning for known towers...\n")

    scanner.start()

    start_time = time.time()
    try:
        while scanner.is_running and (time.time() - start_time) < duration:
            time.sleep(1)
            console.print(
                f"\r  Towers: {scanner.tower_count} | Scans: {scanner.scan_count}",
                end="",
            )
    except KeyboardInterrupt:
        pass

    scanner.stop()
    console.print()

    towers = scanner.get_towers()
    if not towers:
        console.print("[yellow]No towers found — cannot create baseline.[/]")
        return

    detector = RogueBaseStationDetector()
    detector.save_baseline(towers, output_path)
    console.print(f"\n[green]Baseline saved: {len(towers)} towers -> {output_path}[/]")


@cellular.command("detect")
@click.option("--baseline", "-b", required=True, type=click.Path(exists=True),
              help="Path to baseline JSON file.")
@click.option("--duration", "-t", default=120, type=int, help="Detection scan duration.")
@click.option("--gsm/--no-gsm", default=True)
@click.option("--lte/--no-lte", default=True)
@click.option("--rtl-device", default=0, type=int)
@click.option("--hackrf-device", default="")
def detect_rogue(
    baseline: str, duration: int, gsm: bool, lte: bool,
    rtl_device: int, hackrf_device: str,
) -> None:
    """Scan and detect rogue base stations (IMSI catchers / Stingrays).

    Compares discovered towers against a known-good baseline and flags
    anomalies using multiple detection heuristics.
    """
    import time

    from flyinghoneysnitch.cellular.scanner import CellularScanner
    from flyinghoneysnitch.cellular.detector import RogueBaseStationDetector

    detector = RogueBaseStationDetector()
    detector.load_baseline_file(baseline)

    scanner = CellularScanner(
        rtlsdr_device=rtl_device,
        hackrf_device=hackrf_device,
        scan_gsm=gsm,
        scan_lte=lte,
        on_tower_found=lambda t: _check_tower(detector, t),
    )

    console.print(f"\n[bold cyan]CellGuard[/] - Rogue Detection ({duration}s)")
    console.print(f"[dim]Baseline loaded. Monitoring...[/]\n")

    scanner.start()

    start_time = time.time()
    try:
        while scanner.is_running and (time.time() - start_time) < duration:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    scanner.stop()

    # Summary
    alerts = detector.get_alerts()
    if not alerts:
        console.print("\n[green]No rogue base stations detected.[/]")
        return

    table = Table(title=f"Rogue Detection Alerts ({len(alerts)})")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Message")
    table.add_column("CID")
    table.add_column("RSSI", justify="right")

    severity_style = {
        "critical": "[bold red]",
        "warning": "[yellow]",
        "info": "[dim]",
    }

    for alert in alerts:
        style = severity_style.get(alert.severity, "")
        end_style = "[/]" if style else ""
        table.add_row(
            f"{style}{alert.severity.upper()}{end_style}",
            alert.alert_type,
            alert.message,
            alert.tower.cell_id,
            f"{alert.tower.rssi} dBm",
        )

    console.print(table)


def _check_tower(detector, tower) -> None:
    """Check a single tower and print any alerts."""
    alerts = detector.check_tower(tower)
    for alert in alerts:
        severity_color = {"critical": "red", "warning": "yellow"}.get(alert.severity, "white")
        console.print(
            f"  [{severity_color}][{alert.severity.upper()}][/{severity_color}] "
            f"{alert.message}"
        )
