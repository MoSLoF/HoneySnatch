"""Audit log CLI commands for honeysnatch.

Provides `fhs audit` subcommands for verifying, viewing,
and exporting the tamper-evident audit trail.
"""

from __future__ import annotations

import json
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def audit():
    """Audit log management and verification."""
    pass


@audit.command("verify")
@click.option("--data-dir", "-d", default="", help="Data directory containing audit.jsonl.")
def audit_verify(data_dir: str) -> None:
    """Verify the integrity of the audit log chain.

    Walks the entire HMAC chain and reports any tampering.
    """
    from honeysnatch.utils.audit import get_audit_logger

    logger = get_audit_logger(data_dir)
    valid, count, message = logger.verify()

    if valid:
        console.print(f"[bold green]PASS[/] {message}")
    else:
        console.print(f"[bold red]FAIL[/] {message}")
        raise SystemExit(1)


@audit.command("show")
@click.option("--data-dir", "-d", default="", help="Data directory containing audit.jsonl.")
@click.option("--event", "-e", default="", help="Filter by event type.")
@click.option("--limit", "-n", default=50, help="Maximum entries to show.")
def audit_show(data_dir: str, event: str, limit: int) -> None:
    """Display recent audit log entries."""
    from honeysnatch.utils.audit import get_audit_logger

    logger = get_audit_logger(data_dir)
    entries = logger.get_entries(event_filter=event, limit=limit)

    if not entries:
        console.print("[yellow]No audit entries found.[/]")
        return

    table = Table(title=f"Audit Log ({len(entries)} entries)")
    table.add_column("Seq", style="dim", justify="right")
    table.add_column("Timestamp")
    table.add_column("Event", style="bold")
    table.add_column("Details")
    table.add_column("Hash", style="dim", max_width=16)

    for e in entries:
        ts = e.get("ts", "")
        # Truncate to readable format
        if len(ts) > 19:
            ts = ts[:19].replace("T", " ")
        data_str = ""
        data = e.get("data", {})
        if data:
            # Show key=value pairs compactly
            parts = [f"{k}={v}" for k, v in list(data.items())[:3]]
            data_str = ", ".join(parts)
            if len(data) > 3:
                data_str += f" (+{len(data) - 3} more)"

        table.add_row(
            str(e.get("seq", "")),
            ts,
            e.get("event", ""),
            data_str,
            e.get("hash", "")[:16] + "...",
        )

    console.print(table)


@audit.command("export")
@click.option("--data-dir", "-d", default="", help="Data directory containing audit.jsonl.")
@click.option("--output", "-o", default=None, help="Output JSON file path.")
@click.option("--event", "-e", default="", help="Filter by event type.")
def audit_export(data_dir: str, output: str | None, event: str) -> None:
    """Export audit log entries to JSON."""
    from honeysnatch.utils.audit import get_audit_logger

    logger = get_audit_logger(data_dir)

    # Verify chain first
    valid, count, message = logger.verify()
    if not valid:
        console.print(f"[bold red]WARNING:[/] Audit chain failed verification: {message}")
        console.print("Exporting anyway, but data integrity cannot be guaranteed.")

    entries = logger.get_entries(event_filter=event)

    if output is None:
        output = f"fhb_audit_{datetime.now():%Y%m%d_%H%M%S}.json"

    data = {
        "exported_at": datetime.now().isoformat(),
        "chain_valid": valid,
        "verification": message,
        "entry_count": len(entries),
        "entries": entries,
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]Exported {len(entries)} audit entries to:[/] {output}")
