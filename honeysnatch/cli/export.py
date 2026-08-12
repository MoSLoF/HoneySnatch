"""Export commands for honeysnatch CLI.

Provides `fhs export` subcommands for exporting scan data
to CSV, JSON, and KML formats.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from honeysnatch.db.factory import open_database

console = Console()


@click.group()
def export():
    """Export scan data to various formats."""
    pass


@export.command("csv")
@click.argument("db_path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--type", "-t", "data_type", default="aps", type=click.Choice(["aps", "clients", "all"]))
@click.option("--encrypt", "-e", is_flag=True, default=False, help="Encrypt the output file (AES-256-GCM).")
@click.option("--passphrase", "-p", default=None, help="Encryption passphrase (prompted if not given).")
@click.pass_context
def export_csv(ctx: click.Context, db_path: str, output: str | None, data_type: str, encrypt: bool, passphrase: str | None) -> None:
    """Export scan session to CSV.

    DB_PATH is the path to a .db session file.
    """

    db = open_database(db_path, config=ctx.obj.get('config'))
    sessions = db.list_sessions()

    if not sessions:
        console.print("[yellow]No sessions found in database.[/]")
        return

    session_id = sessions[0]["session_id"]
    session = db.load_scan_session(session_id)

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    if output is None:
        output = f"fhs_export_{datetime.now():%Y%m%d_%H%M%S}.csv"

    with open(output, "w", newline="") as f:
        if data_type in ("aps", "all"):
            writer = csv.writer(f)
            writer.writerow([
                "BSSID", "SSID", "Channel", "Frequency", "RSSI", "Max RSSI",
                "Encryption", "Cipher", "Auth", "Band", "Vendor", "Hidden",
                "Beacon Count", "Data Count", "WPS", "First Seen", "Last Seen",
                "Latitude", "Longitude", "Client Count",
            ])
            for ap in session.access_points.values():
                writer.writerow([
                    ap.bssid, ap.ssid, ap.channel, ap.frequency, ap.rssi, ap.max_rssi,
                    ap.encryption.value, ap.cipher, ap.auth, ap.band.value, ap.vendor,
                    ap.hidden, ap.beacon_count, ap.data_count, ap.wps,
                    ap.first_seen.isoformat(), ap.last_seen.isoformat(),
                    ap.position.latitude if ap.position else "",
                    ap.position.longitude if ap.position else "",
                    len(ap.clients),
                ])

        if data_type in ("clients", "all"):
            if data_type == "all":
                f.write("\n")
            writer = csv.writer(f)
            writer.writerow([
                "MAC", "BSSID", "SSID", "RSSI", "Vendor", "Probe Requests",
                "Data Count", "First Seen", "Last Seen",
            ])
            for cl in session.clients.values():
                writer.writerow([
                    cl.mac, cl.bssid or "", cl.ssid or "", cl.rssi, cl.vendor,
                    ";".join(cl.probe_requests), cl.data_count,
                    cl.first_seen.isoformat(), cl.last_seen.isoformat(),
                ])

    db.close()

    if encrypt:
        _encrypt_output(output, passphrase)
    else:
        console.print(f"[green]Exported to:[/] {output}")


@export.command("json")
@click.argument("db_path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--encrypt", "-e", is_flag=True, default=False, help="Encrypt the output file (AES-256-GCM).")
@click.option("--passphrase", "-p", default=None, help="Encryption passphrase (prompted if not given).")
@click.pass_context
def export_json(ctx: click.Context, db_path: str, output: str | None, encrypt: bool, passphrase: str | None) -> None:
    """Export scan session to JSON."""

    db = open_database(db_path, config=ctx.obj.get('config'))
    sessions = db.list_sessions()

    if not sessions:
        console.print("[yellow]No sessions found in database.[/]")
        return

    session_id = sessions[0]["session_id"]
    session = db.load_scan_session(session_id)

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    if output is None:
        output = f"fhs_export_{datetime.now():%Y%m%d_%H%M%S}.json"

    data = {
        "session": {
            "id": session.session_id,
            "name": session.name,
            "interface": session.interface,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "duration_seconds": session.duration_seconds,
            "channels": session.channels,
        },
        "access_points": [
            {
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "channel": ap.channel,
                "frequency": ap.frequency,
                "rssi": ap.rssi,
                "max_rssi": ap.max_rssi,
                "encryption": ap.encryption.value,
                "cipher": ap.cipher,
                "auth": ap.auth,
                "band": ap.band.value,
                "vendor": ap.vendor,
                "hidden": ap.hidden,
                "beacon_count": ap.beacon_count,
                "data_count": ap.data_count,
                "wps": ap.wps,
                "first_seen": ap.first_seen.isoformat(),
                "last_seen": ap.last_seen.isoformat(),
                "position": {
                    "lat": ap.position.latitude,
                    "lon": ap.position.longitude,
                } if ap.position else None,
                "clients": ap.clients,
            }
            for ap in session.access_points.values()
        ],
        "clients": [
            {
                "mac": cl.mac,
                "bssid": cl.bssid,
                "ssid": cl.ssid,
                "rssi": cl.rssi,
                "vendor": cl.vendor,
                "probe_requests": cl.probe_requests,
                "data_count": cl.data_count,
                "first_seen": cl.first_seen.isoformat(),
                "last_seen": cl.last_seen.isoformat(),
            }
            for cl in session.clients.values()
        ],
        "summary": {
            "total_aps": session.ap_count,
            "total_clients": session.client_count,
        },
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    db.close()

    if encrypt:
        _encrypt_output(output, passphrase)
    else:
        console.print(f"[green]Exported to:[/] {output}")


@export.command("kml")
@click.argument("db_path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--encrypt", "-e", is_flag=True, default=False, help="Encrypt the output file (AES-256-GCM).")
@click.option("--passphrase", "-p", default=None, help="Encryption passphrase (prompted if not given).")
@click.pass_context
def export_kml(ctx: click.Context, db_path: str, output: str | None, encrypt: bool, passphrase: str | None) -> None:
    """Export scan session to KML (Google Earth).

    Only APs with GPS coordinates will be included.
    """

    db = open_database(db_path, config=ctx.obj.get('config'))
    sessions = db.list_sessions()

    if not sessions:
        console.print("[yellow]No sessions found in database.[/]")
        return

    session_id = sessions[0]["session_id"]
    session = db.load_scan_session(session_id)

    if not session:
        console.print("[red]Failed to load session.[/]")
        return

    if output is None:
        output = f"fhs_export_{datetime.now():%Y%m%d_%H%M%S}.kml"

    # Build KML document
    placemarks = []
    for ap in session.access_points.values():
        if not ap.position:
            continue
        enc_icon = "ylw" if ap.encryption.value != "Open" else "red"
        placemarks.append(
            f"""    <Placemark>
      <name>{_xml_escape(ap.ssid or '[Hidden]')}</name>
      <description>
        BSSID: {ap.bssid}
        Channel: {ap.channel}
        Encryption: {ap.encryption.value}
        Signal: {ap.rssi} dBm (max: {ap.max_rssi} dBm)
        Vendor: {_xml_escape(ap.vendor)}
        Clients: {len(ap.clients)}
      </description>
      <Point>
        <coordinates>{ap.position.longitude},{ap.position.latitude},0</coordinates>
      </Point>
    </Placemark>"""
        )

    kml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>honeysnatch Scan - {_xml_escape(session.name)}</name>
    <description>Scan session: {session.start_time.isoformat()}</description>
{"".join(placemarks)}
  </Document>
</kml>"""

    with open(output, "w") as f:
        f.write(kml_content)

    db.close()

    geo_count = sum(1 for ap in session.access_points.values() if ap.position)
    if encrypt:
        _encrypt_output(output, passphrase)
    else:
        console.print(f"[green]Exported {geo_count} APs to:[/] {output}")


def _encrypt_output(output_path: str, passphrase: str | None) -> None:
    """Encrypt an export file in-place using AES-256-GCM."""
    from honeysnatch.utils.crypto import encrypt_file

    if not passphrase:
        passphrase = click.prompt("Encryption passphrase", hide_input=True, confirmation_prompt=True)

    encrypted_path = output_path + ".enc"
    encrypt_file(output_path, encrypted_path, passphrase)

    # Replace plaintext with encrypted version
    Path(output_path).unlink()
    Path(encrypted_path).rename(output_path)
    console.print(f"[green]Exported (encrypted) to:[/] {output_path}")


def _xml_escape(s: str) -> str:
    """Escape special XML characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
