"""HTML-injection regression tests for reports/maps (review HS-07).

Every attacker-controlled string field (SSID, vendor, probe-request,
evil-twin reason, session name/interface) that gets interpolated into
generated HTML must be escaped. A crafted beacon SSID like
`<script>fetch('http://evil')</script>` — captured passively and later
opened in a browser — must render as text, not execute.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from honeysnatch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    ScanSession,
)


HOSTILE_SSID = "<script>alert('xss')</script>"
HOSTILE_VENDOR = "\"><img src=x onerror=fetch('http://evil')>"
HOSTILE_PROBE = "</td></tr><tr><td>injected"
HOSTILE_REASON = "<iframe src='http://evil'></iframe>"


def _hostile_session() -> ScanSession:
    session = ScanSession(
        session_id="test-hs07",
        name="hostile" + HOSTILE_SSID,
        interface="wlan0" + HOSTILE_PROBE,
        start_time=datetime(2026, 1, 1, 12, 0, 0),
        end_time=datetime(2026, 1, 1, 12, 5, 0),
    )
    ap = AccessPoint(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid=HOSTILE_SSID,
        channel=6,
        band=Band.BAND_2_4GHZ,
        rssi=-42,
        encryption=EncryptionType.WPA2,
        vendor=HOSTILE_VENDOR,
    )
    session.access_points[ap.bssid] = ap
    cl = Client(
        mac="11:22:33:44:55:66",
        bssid=ap.bssid,
        rssi=-55,
        vendor=HOSTILE_VENDOR,
    )
    cl.probe_requests.append(HOSTILE_PROBE)
    session.clients[cl.mac] = cl
    return session


class TestReportsEscape:
    def test_hostile_ssid_rendered_as_text(self, tmp_path):
        from honeysnatch.analysis.reports import generate_html_report
        session = _hostile_session()
        out = tmp_path / "report.html"
        generate_html_report(session, str(out))
        html = out.read_text()

        # Escaped forms must be present.
        assert "&lt;script&gt;" in html, "HS-07 regression: SSID <script> not escaped"
        # Raw hostile tags MUST NOT appear as live markup.
        # The DANGEROUS shape is a live `<` followed by a tag name that a
        # browser would parse. `onerror=fetch` appearing inside escaped
        # text content is inert.
        assert "<script>alert" not in html
        assert "<img " not in html  # any live <img tag would allow XSS
        assert "<iframe" not in html
        # The `<em>[Hidden]</em>` sentinel is safe by design — we choose
        # to allow that specific literal because it's not attacker-derived.

    def test_hostile_vendor_rendered_as_text(self, tmp_path):
        from honeysnatch.analysis.reports import generate_html_report
        session = _hostile_session()
        out = tmp_path / "r.html"
        generate_html_report(session, str(out))
        html = out.read_text()
        assert "&quot;&gt;&lt;img" in html or "&#x27;" in html or "&gt;&lt;img" in html
        assert "<img src=x onerror" not in html

    def test_hostile_probe_request_rendered_as_text(self, tmp_path):
        from honeysnatch.analysis.reports import generate_html_report
        session = _hostile_session()
        out = tmp_path / "r.html"
        generate_html_report(session, str(out))
        html = out.read_text()
        assert "&lt;/td&gt;" in html  # the </td></tr> injection escaped
        # The literal "injected" as content is fine — it should just be text.


class TestMapPopupEscape:
    def test_hostile_ssid_in_popup_is_escaped(self):
        from honeysnatch.mapping.renderer import _ap_popup
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid=HOSTILE_SSID,
            channel=6,
            band=Band.BAND_2_4GHZ,
            rssi=-42,
            encryption=EncryptionType.WPA2,
            vendor=HOSTILE_VENDOR,
        )
        popup = _ap_popup(ap)
        assert "&lt;script&gt;" in popup, \
            "HS-07 regression: map popup SSID not escaped"
        assert "<script>alert" not in popup
        assert "<img " not in popup
