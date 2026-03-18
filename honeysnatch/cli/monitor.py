"""Monitor commands for honeysnatch CLI.

Provides `fhs monitor` subcommands for continuous wireless monitoring (SentryWeb).
"""

from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.group()
def monitor():
    """Continuous wireless monitoring commands (SentryWeb)."""
    pass


@monitor.command("start")
@click.option("--interface", "-i", required=True, help="Monitor-mode wireless interface.")
@click.option("--known-aps", "-k", default=None, type=click.Path(exists=True),
              help="File listing known/authorized APs (one BSSID per line).")
@click.option("--alert-rogue", is_flag=True, default=True, help="Alert on rogue/unknown APs.")
@click.option("--alert-new-client", is_flag=True, default=False, help="Alert on new client devices.")
@click.pass_context
def start_monitor(
    ctx: click.Context,
    interface: str,
    known_aps: str | None,
    alert_rogue: bool,
    alert_new_client: bool,
) -> None:
    """Start continuous wireless monitoring.

    Monitors for unauthorized access points, new devices, and policy violations.
    """
    import signal
    import time

    from honeysnatch.core.models import ScanEvent
    from honeysnatch.core.scanner import WifiScanner
    from honeysnatch.monitoring.alerting import AlertEngine

    # Load known APs
    authorized_bssids: set[str] = set()
    if known_aps:
        with open(known_aps) as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    authorized_bssids.add(line)
        console.print(f"[dim]Loaded {len(authorized_bssids)} authorized APs[/]")

    # Initialize alert engine
    alert_engine = AlertEngine(
        authorized_bssids=authorized_bssids,
        alert_on_rogue=alert_rogue,
        alert_on_new_client=alert_new_client,
    )

    # Initialize scanner
    scanner = WifiScanner(
        interface=interface,
        session_name="SentryWeb Monitor",
    )

    console.print(f"\n[bold cyan]SentryWeb[/] - Continuous Monitoring on [bold]{interface}[/]")
    console.print("[dim]Press Ctrl+C to stop\n[/]")

    def on_event(event: ScanEvent):
        alerts = alert_engine.process_event(event)
        for alert in alerts:
            severity_color = {
                "critical": "red",
                "warning": "yellow",
                "info": "blue",
            }.get(alert["severity"], "white")
            console.print(
                f"  [{severity_color}][{alert['severity'].upper()}][/] "
                f"{alert['message']}"
            )

    scanner.on_event(on_event)

    def handle_signal(signum, frame):
        scanner.stop()

    signal.signal(signal.SIGINT, handle_signal)

    scanner.start()

    try:
        while scanner.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    scanner.stop()
    console.print(f"\n[bold]Monitoring stopped.[/] Alerts: {alert_engine.alert_count}")


@monitor.command("alerts")
@click.argument("db_path", type=click.Path(exists=True))
def show_alerts(db_path: str) -> None:
    """Show alerts from a monitoring session."""
    from rich.table import Table
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from honeysnatch.db.schema import AlertRecord, Base

    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)

    with Session() as db:
        alerts = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(100).all()

    if not alerts:
        console.print("[yellow]No alerts found.[/]")
        return

    table = Table(title="Security Alerts")
    table.add_column("Time")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Message")
    table.add_column("BSSID/MAC")

    for alert in alerts:
        sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(alert.severity, "white")
        table.add_row(
            str(alert.timestamp),
            f"[{sev_color}]{alert.severity}[/]",
            alert.alert_type,
            alert.message,
            alert.bssid or alert.mac or "-",
        )

    console.print(table)
