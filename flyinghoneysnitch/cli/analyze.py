"""Analysis commands for FlyingHoneySnitch CLI.

Provides `fhs analyze` subcommands for post-hoc analysis of scan sessions.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def analyze():
    """Post-hoc analysis commands (HoneyView)."""
    pass


@analyze.command("sessions")
@click.argument("db_path", type=click.Path(exists=True))
def list_sessions(db_path: str) -> None:
    """List scan sessions in a database."""
    from flyinghoneysnitch.db.database import DatabaseManager

    db = DatabaseManager(db_path)
    sessions = db.list_sessions()
    db.close()

    if not sessions:
        console.print("[yellow]No sessions found.[/]")
        return

    table = Table(title="Scan Sessions")
    table.add_column("Session ID", style="bold")
    table.add_column("Name")
    table.add_column("Start Time")
    table.add_column("End Time")
    table.add_column("Interface")
    table.add_column("APs", justify="right")
    table.add_column("Clients", justify="right")

    for s in sessions:
        table.add_row(
            s["session_id"],
            s["name"],
            str(s["start_time"]),
            str(s["end_time"] or "-"),
            s["interface"],
            str(s["ap_count"]),
            str(s["client_count"]),
        )

    console.print(table)


@analyze.command("aps")
@click.argument("db_path", type=click.Path(exists=True))
@click.option("--sort", "-s", default="rssi", type=click.Choice(["rssi", "ssid", "channel", "encryption"]))
@click.option("--filter-enc", "-e", default=None, help="Filter by encryption type.")
@click.option("--filter-channel", "-c", default=None, type=int, help="Filter by channel.")
def show_aps(
    db_path: str,
    sort: str,
    filter_enc: str | None,
    filter_channel: int | None,
) -> None:
    """Show access points from a scan session."""
    from flyinghoneysnitch.db.database import DatabaseManager

    db = DatabaseManager(db_path)
    sessions = db.list_sessions()
    if not sessions:
        console.print("[yellow]No sessions found.[/]")
        return

    session = db.load_scan_session(sessions[0]["session_id"])
    db.close()

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    aps = list(session.access_points.values())

    # Apply filters
    if filter_enc:
        aps = [ap for ap in aps if ap.encryption.value.lower() == filter_enc.lower()]
    if filter_channel:
        aps = [ap for ap in aps if ap.channel == filter_channel]

    # Sort
    if sort == "rssi":
        aps.sort(key=lambda a: a.rssi, reverse=True)
    elif sort == "ssid":
        aps.sort(key=lambda a: a.ssid.lower())
    elif sort == "channel":
        aps.sort(key=lambda a: a.channel)
    elif sort == "encryption":
        aps.sort(key=lambda a: a.encryption.value)

    table = Table(title=f"Access Points ({len(aps)})")
    table.add_column("BSSID", style="bold")
    table.add_column("SSID")
    table.add_column("Ch", justify="right")
    table.add_column("RSSI", justify="right")
    table.add_column("Encryption")
    table.add_column("Vendor")
    table.add_column("Clients", justify="right")
    table.add_column("Beacons", justify="right")

    for ap in aps:
        enc_style = "red" if ap.encryption.value == "Open" else "green"
        ssid_display = ap.ssid or "[dim][Hidden][/]"
        table.add_row(
            ap.bssid,
            ssid_display,
            str(ap.channel),
            f"{ap.rssi} dBm",
            f"[{enc_style}]{ap.encryption.value}[/]",
            ap.vendor or "-",
            str(len(ap.clients)),
            str(ap.beacon_count),
        )

    console.print(table)


@analyze.command("clients")
@click.argument("db_path", type=click.Path(exists=True))
@click.option("--sort", "-s", default="rssi", type=click.Choice(["rssi", "mac", "probes"]))
def show_clients(db_path: str, sort: str) -> None:
    """Show discovered clients from a scan session."""
    from flyinghoneysnitch.db.database import DatabaseManager

    db = DatabaseManager(db_path)
    sessions = db.list_sessions()
    if not sessions:
        console.print("[yellow]No sessions found.[/]")
        return

    session = db.load_scan_session(sessions[0]["session_id"])
    db.close()

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    clients = list(session.clients.values())

    if sort == "rssi":
        clients.sort(key=lambda c: c.rssi, reverse=True)
    elif sort == "mac":
        clients.sort(key=lambda c: c.mac)
    elif sort == "probes":
        clients.sort(key=lambda c: len(c.probe_requests), reverse=True)

    table = Table(title=f"Clients ({len(clients)})")
    table.add_column("MAC", style="bold")
    table.add_column("BSSID")
    table.add_column("RSSI", justify="right")
    table.add_column("Vendor")
    table.add_column("Probes")
    table.add_column("Data Pkts", justify="right")

    for cl in clients:
        probes = ", ".join(cl.probe_requests[:5])
        if len(cl.probe_requests) > 5:
            probes += f" (+{len(cl.probe_requests) - 5} more)"
        table.add_row(
            cl.mac,
            cl.bssid or "[dim]-[/]",
            f"{cl.rssi} dBm",
            cl.vendor or "-",
            probes or "[dim]-[/]",
            str(cl.data_count),
        )

    console.print(table)


@analyze.command("summary")
@click.argument("db_path", type=click.Path(exists=True))
def show_summary(db_path: str) -> None:
    """Show summary statistics for a scan session."""
    from collections import Counter

    from flyinghoneysnitch.db.database import DatabaseManager

    db = DatabaseManager(db_path)
    sessions = db.list_sessions()
    if not sessions:
        console.print("[yellow]No sessions found.[/]")
        return

    session = db.load_scan_session(sessions[0]["session_id"])
    db.close()

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    aps = list(session.access_points.values())
    clients = list(session.clients.values())

    console.print(f"\n[bold cyan]Scan Summary:[/] {session.name}")
    console.print(f"  Session ID:  {session.session_id}")
    console.print(f"  Interface:   {session.interface}")
    console.print(f"  Duration:    {session.duration_seconds:.0f}s")
    console.print(f"  Total APs:   {len(aps)}")
    console.print(f"  Total Clients: {len(clients)}")

    # Encryption breakdown
    enc_counts = Counter(ap.encryption.value for ap in aps)
    console.print("\n[bold]Encryption Breakdown:[/]")
    for enc, count in enc_counts.most_common():
        style = "red" if enc == "Open" else "green"
        console.print(f"  [{style}]{enc:<20}[/] {count}")

    # Channel distribution
    ch_counts = Counter(ap.channel for ap in aps)
    console.print("\n[bold]Channel Distribution:[/]")
    for ch, count in sorted(ch_counts.items()):
        bar = "#" * min(count, 40)
        console.print(f"  Ch {ch:>3}: {bar} ({count})")

    # Top vendors
    vendor_counts = Counter(ap.vendor for ap in aps if ap.vendor)
    if vendor_counts:
        console.print("\n[bold]Top Vendors:[/]")
        for vendor, count in vendor_counts.most_common(10):
            console.print(f"  {vendor:<30} {count}")

    # Hidden networks
    hidden = [ap for ap in aps if ap.hidden]
    if hidden:
        console.print(f"\n[bold yellow]Hidden Networks: {len(hidden)}[/]")
        for ap in hidden:
            console.print(f"  {ap.bssid} ch:{ap.channel} {ap.rssi} dBm")

    console.print()
