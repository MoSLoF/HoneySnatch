"""Report generation for HoneyView analysis.

Generates HTML, CSV, and summary reports from scan session data.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional

from honeysnatch.analysis.patterns import PatternAnalyzer
from honeysnatch.analysis.profiles import ProfileEngine
from honeysnatch.core.models import ScanSession
from honeysnatch.utils.logger import get_logger

log = get_logger("reports")


def generate_html_report(
    session: ScanSession,
    output_path: Optional[str] = None,
) -> str:
    """Generate a comprehensive HTML report for a scan session.

    Args:
        session: The scan session data.
        output_path: Path for the HTML file. Auto-generated if None.

    Returns:
        Path to the generated report.
    """
    if output_path is None:
        output_path = f"fhb_report_{session.session_id}.html"

    analyzer = PatternAnalyzer(session)
    profiles = ProfileEngine()

    enc_summary = analyzer.encryption_summary()
    vendor_summary = analyzer.vendor_summary()
    evil_twins = analyzer.find_potential_evil_twins()

    # Sort APs by signal strength
    aps_sorted = sorted(session.access_points.values(), key=lambda a: a.rssi, reverse=True)
    clients_sorted = sorted(session.clients.values(), key=lambda c: c.rssi, reverse=True)

    # Build AP table rows
    ap_rows = ""
    for ap in aps_sorted:
        score = profiles.security_score(ap)
        score_class = "good" if score >= 70 else "warn" if score >= 40 else "bad"
        ap_rows += f"""
        <tr>
            <td class="mono">{ap.bssid}</td>
            <td>{ap.ssid or '<em>[Hidden]</em>'}</td>
            <td>{ap.channel}</td>
            <td>{ap.rssi} dBm</td>
            <td class="enc-{ap.encryption.value.lower().replace('-', '').replace(' ', '')}">{ap.encryption.value}</td>
            <td>{ap.vendor or '-'}</td>
            <td>{len(ap.clients)}</td>
            <td class="{score_class}">{score}</td>
        </tr>"""

    # Build client table rows
    client_rows = ""
    for cl in clients_sorted:
        probes = ", ".join(cl.probe_requests[:5])
        if len(cl.probe_requests) > 5:
            probes += f" (+{len(cl.probe_requests) - 5})"
        client_rows += f"""
        <tr>
            <td class="mono">{cl.mac}</td>
            <td class="mono">{cl.bssid or '-'}</td>
            <td>{cl.rssi} dBm</td>
            <td>{cl.vendor or '-'}</td>
            <td>{probes or '-'}</td>
            <td>{cl.data_count}</td>
        </tr>"""

    # Evil twin warnings
    evil_twin_html = ""
    if evil_twins:
        evil_twin_html = '<div class="alert">'
        for et in evil_twins:
            evil_twin_html += f'<p><strong>Potential Evil Twin:</strong> SSID "{et["ssid"]}" - {et["reason"]}</p>'
        evil_twin_html += '</div>'

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>honeysnatch Report - {session.name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        h2 {{ color: #0f3460; background: #16213e; padding: 10px; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th {{ background: #16213e; color: #e94560; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #333; }}
        tr:hover {{ background: #16213e; }}
        .mono {{ font-family: 'Courier New', monospace; font-size: 0.9em; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-box {{ background: #16213e; padding: 16px; border-radius: 8px; min-width: 150px; }}
        .stat-box .value {{ font-size: 2em; font-weight: bold; color: #e94560; }}
        .stat-box .label {{ color: #aaa; }}
        .good {{ color: #00ff88; }}
        .warn {{ color: #ffaa00; }}
        .bad {{ color: #ff4444; }}
        .alert {{ background: #3d1a1a; border: 1px solid #ff4444; padding: 12px; border-radius: 4px; margin: 12px 0; }}
        .enc-open {{ color: #ff4444; font-weight: bold; }}
        .enc-wep {{ color: #ff8800; }}
        .enc-wpa {{ color: #ffaa00; }}
        .enc-wpa2 {{ color: #00ff88; }}
        .enc-wpa3 {{ color: #00cc66; }}
    </style>
</head>
<body>
    <h1>honeysnatch Scan Report</h1>

    <div class="summary">
        <div class="stat-box">
            <div class="value">{session.ap_count}</div>
            <div class="label">Access Points</div>
        </div>
        <div class="stat-box">
            <div class="value">{session.client_count}</div>
            <div class="label">Clients</div>
        </div>
        <div class="stat-box">
            <div class="value">{session.duration_seconds:.0f}s</div>
            <div class="label">Duration</div>
        </div>
        <div class="stat-box">
            <div class="value">{enc_summary.get('Open', 0)}</div>
            <div class="label bad">Open Networks</div>
        </div>
    </div>

    <h2>Session Details</h2>
    <table>
        <tr><td><strong>Name</strong></td><td>{session.name}</td></tr>
        <tr><td><strong>Session ID</strong></td><td class="mono">{session.session_id}</td></tr>
        <tr><td><strong>Interface</strong></td><td>{session.interface}</td></tr>
        <tr><td><strong>Start</strong></td><td>{session.start_time}</td></tr>
        <tr><td><strong>End</strong></td><td>{session.end_time or 'In progress'}</td></tr>
    </table>

    {evil_twin_html}

    <h2>Access Points ({session.ap_count})</h2>
    <table>
        <thead>
            <tr><th>BSSID</th><th>SSID</th><th>Ch</th><th>RSSI</th><th>Encryption</th><th>Vendor</th><th>Clients</th><th>Score</th></tr>
        </thead>
        <tbody>{ap_rows}</tbody>
    </table>

    <h2>Clients ({session.client_count})</h2>
    <table>
        <thead>
            <tr><th>MAC</th><th>Associated AP</th><th>RSSI</th><th>Vendor</th><th>Probe Requests</th><th>Data Pkts</th></tr>
        </thead>
        <tbody>{client_rows}</tbody>
    </table>

    <h2>Encryption Summary</h2>
    <table>
        <thead><tr><th>Type</th><th>Count</th><th>Percentage</th></tr></thead>
        <tbody>
            {''.join(f'<tr><td>{enc}</td><td>{count}</td><td>{count/max(session.ap_count,1)*100:.1f}%</td></tr>' for enc, count in sorted(enc_summary.items(), key=lambda x: x[1], reverse=True))}
        </tbody>
    </table>

    <footer style="margin-top: 40px; color: #666; border-top: 1px solid #333; padding-top: 10px;">
        Generated by honeysnatch v0.1.0 at {datetime.now().isoformat()}
    </footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("HTML report generated: %s", output_path)
    return output_path


def generate_summary_text(session: ScanSession) -> str:
    """Generate a plain text summary of a scan session."""
    lines = [
        f"honeysnatch Scan Summary",
        f"{'=' * 40}",
        f"Session:    {session.name}",
        f"Interface:  {session.interface}",
        f"Duration:   {session.duration_seconds:.0f}s",
        f"APs:        {session.ap_count}",
        f"Clients:    {session.client_count}",
        f"",
    ]

    from collections import Counter
    enc_counts = Counter(ap.encryption.value for ap in session.access_points.values())
    lines.append("Encryption:")
    for enc, count in enc_counts.most_common():
        lines.append(f"  {enc:<20} {count}")

    return "\n".join(lines)
