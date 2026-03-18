"""Main CLI entry point for honeysnatch.

Provides the `fhs` command group with subcommands for scanning,
analysis, monitoring, and export operations.
"""

from __future__ import annotations

import click

from honeysnatch import __app_name__, __version__


@click.group()
@click.version_option(version=__version__, prog_name=__app_name__)
@click.option(
    "--config", "-c",
    type=click.Path(),
    default=None,
    help="Path to config file.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug logging.",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """honeysnatch - Wireless Discovery & Assessment Tool Suite.

    A comprehensive tool for passive WiFi discovery, RF mapping,
    wireless security analysis, continuous monitoring, and
    client isolation vulnerability testing.
    """
    ctx.ensure_object(dict)

    from honeysnatch.utils.config import load_config
    from honeysnatch.utils.logger import setup_logging

    app_config = load_config(config)
    if verbose:
        app_config.log_level = "DEBUG"

    setup_logging(level=app_config.log_level)
    ctx.obj["config"] = app_config


# Register subcommand groups
from honeysnatch.cli.scan import scan  # noqa: E402
from honeysnatch.cli.export import export  # noqa: E402
from honeysnatch.cli.analyze import analyze  # noqa: E402
from honeysnatch.cli.monitor import monitor  # noqa: E402
from honeysnatch.cli.bluetooth import bluetooth  # noqa: E402
from honeysnatch.cli.cellular import cellular  # noqa: E402
from honeysnatch.cli.audit import audit  # noqa: E402
from honeysnatch.cli.isolation import isolation  # noqa: E402

cli.add_command(scan)
cli.add_command(export)
cli.add_command(analyze)
cli.add_command(monitor)
cli.add_command(bluetooth)
cli.add_command(cellular)
cli.add_command(audit)
cli.add_command(isolation)


@cli.command()
def gui():
    """Launch the honeysnatch desktop GUI."""
    try:
        from honeysnatch.gui.app import main as gui_main
        gui_main()
    except ImportError:
        click.echo(
            "GUI dependencies not installed. Install with:\n"
            "  pip install honeysnatch[gui]",
            err=True,
        )
        raise SystemExit(1)


@cli.command()
def info():
    """Show system information and capabilities."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    console.print(f"\n[bold cyan]{__app_name__}[/] v{__version__}\n")

    # Permission check
    from honeysnatch.utils.permissions import check_permissions
    perms = check_permissions()

    table = Table(title="System Status")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row(
        "Root Access",
        "[green]Yes[/]" if perms.is_root else "[red]No[/]",
        "Running as root" if perms.is_root else "Not root",
    )
    table.add_row(
        "CAP_NET_RAW",
        "[green]Yes[/]" if perms.has_cap_net_raw else "[red]No[/]",
        "Can capture packets" if perms.has_cap_net_raw else "Cannot capture",
    )
    table.add_row(
        "CAP_NET_ADMIN",
        "[green]Yes[/]" if perms.has_cap_net_admin else "[red]No[/]",
        "Can manage interfaces" if perms.has_cap_net_admin else "Cannot manage",
    )
    table.add_row(
        "Scan Ready",
        "[green]Yes[/]" if perms.can_scan else "[red]No[/]",
        perms.message,
    )

    console.print(table)

    # List wireless interfaces
    from honeysnatch.utils.interfaces import list_wireless_interfaces
    ifaces = list_wireless_interfaces()

    if ifaces:
        iface_table = Table(title="Wireless Interfaces")
        iface_table.add_column("Interface", style="bold")
        iface_table.add_column("PHY")
        iface_table.add_column("Mode")
        iface_table.add_column("MAC")
        iface_table.add_column("Driver")
        iface_table.add_column("Monitor")

        for iface in ifaces:
            iface_table.add_row(
                iface.name,
                iface.phy,
                iface.mode,
                iface.mac,
                iface.driver,
                "[green]Yes[/]" if iface.supports_monitor else "[red]No[/]",
            )
        console.print(iface_table)
    else:
        console.print("[yellow]No wireless interfaces found[/]")


if __name__ == "__main__":
    cli()
