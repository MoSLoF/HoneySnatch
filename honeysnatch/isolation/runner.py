"""High-level test runner for client isolation testing.

Orchestrates AirSnitch-style isolation attacks using the wpa_supplicant
control interface via the Supplicant / Daemon classes.

CONSENT BOUNDARY (review finding HS-02):
The runner is the SHARED live-execution boundary for the CLI, the GUI,
and any programmatic caller. Every `run_*` method that touches on-air
traffic checks `_gate_live_run()` before doing hardware/subprocess/scapy
work. That gate consults an :class:`Authorization` attached to the
runner instance. Callers construct the runner in exactly one of three
authorized states:

  - `simulate=True`  → dry-run, no on-air packets, no consent needed
  - `authorization=Authorization.from_cli_ack(bssid)` → CLI already ran
                       `require_consent()` and passed
  - `authorization=Authorization.from_token(bssid)` → a valid persistent
                       consent token exists

Constructing the runner without one of those (i.e. `simulate=False`
with no `authorization`) makes every subsequent `run_*` call raise
:class:`ConsentRequiredError` — this is what defeats the earlier GUI
bypass that instantiated `IsolationTestRunner(simulate=False)` directly.

Each ``run_*`` method:
  1. Verifies consent via `_gate_live_run()`.
  2. Starts wpa_supplicant on the victim interface (and attacker if needed).
  3. Waits for association and key exchange.
  4. Executes the specific attack sequence.
  5. Returns a concrete AttackResult — never INCONCLUSIVE unless the
     underlying precondition genuinely cannot be met (e.g. no GTK).

Prerequisites (hardware path):
  - Compiled hostap binaries in ``vendor/hostap_2_10/``  (``vendor/build.sh``)
  - Linux, CAP_NET_RAW / root
  - One or two monitor-mode capable Wi-Fi adapters
  - A ``data/isolation/client.conf`` with two network blocks

Pure-Python simulation path (no hardware):
  - Set ``simulate=True`` on the runner; attacks use packet-crafting
    logic on a virtual loopback without launching wpa_supplicant.
    Results are INCONCLUSIVE but validate the logic paths.
"""
from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime
from typing import Optional

from honeysnatch.isolation.attacks.base import (
    AttackOutcome,
    AttackResult,
    AttackType,
)
from honeysnatch.isolation.consent import (
    Authorization,
    ConsentRequiredError,
)
from honeysnatch.isolation.models import IsolationTestSession
from honeysnatch.isolation.config import (
    IsolationConfig,
    find_default_config,
    find_hostap_binary,
)
from honeysnatch.utils.logger import get_logger

log = get_logger("isolation.runner")

# How long to wait for wpa_supplicant to associate (seconds)
_CONNECT_TIMEOUT = 30

# How long to wait for a packet reply in active tests (seconds)
_PACKET_TIMEOUT = 5.0

# TCP port used for the SYN-based reachability probe
_TCP_PROBE_PORT = 443


class IsolationTestRunner:
    """Orchestrate client isolation tests.

    Parameters
    ----------
    interface:
        Primary wireless interface (victim NIC).
    config_file:
        Path to ``wpa_supplicant`` config with two network blocks
        (victim + attacker).  Defaults to ``data/isolation/client.conf``.
    config:
        :class:`IsolationConfig` object.  Keyword overrides are accepted
        directly as ``**kwargs`` (``server``, ``second_interface``, …).
    simulate:
        When True, skip hardware and return simulated results.  Useful
        on Windows / CI where wireless hardware is absent.
    """

    def __init__(
        self,
        interface: str,
        config_file: str = "",
        config: Optional[IsolationConfig] = None,
        simulate: bool = False,
        authorization: Optional[Authorization] = None,
        **kwargs,
    ) -> None:
        self.interface = interface
        self.config_file = config_file or (config.wpa_supplicant_config if config else "")
        if not self.config_file:
            self.config_file = find_default_config("supplicant") or ""
        self.config = config or IsolationConfig()
        self.simulate = simulate
        # HS-02 remediation: the runner NOW carries an authorization
        # object. `simulate=True` neutralizes the check (no on-air work
        # happens); every other construction requires a valid
        # Authorization or every `run_*` call raises.
        self._authorization = authorization
        self.options = kwargs
        self.session: Optional[IsolationTestSession] = None

        # Resolve server / second_interface from kwargs for convenience
        self._server: str = kwargs.get("server", self.config.default_server)
        self._second_iface: str = kwargs.get("second_interface", "")

    def _gate_live_run(self, attack_label: str = "") -> None:
        """Refuse any on-air run without valid consent (review HS-02).

        Called at the top of every `run_*` method. `simulate=True`
        constructors bypass; every other path must have set a valid
        `authorization` at construction time. HS-02R strengthened this
        with an unforgeable receipt check — see
        ``Authorization.is_valid()`` and ``_MINTED_RECEIPTS``.
        """
        if self.simulate:
            return
        if self._authorization is None or not self._authorization.is_valid():
            raise ConsentRequiredError(
                f"Live isolation run ({attack_label or 'unknown'}) refused: "
                "no valid authorization on the runner (missing or forged "
                "receipt). Construct with simulate=True for a dry-run, OR "
                "obtain an authorization by first calling "
                "`honeysnatch.isolation.consent.require_consent()` and then "
                "`Authorization.from_cli_ack(bssid)` / `.from_token(bssid)`."
            )

    def _verify_observed_target(self, observed_bssid: str, attack_label: str = "") -> None:
        """HS-02R: refuse to proceed if the associated BSSID isn't the one
        the operator authorized.

        MUST be called from every `run_*` method AFTER wpa_supplicant
        reports association and BEFORE any injection / capture / probe.
        On mismatch, records an audit event with both BSSIDs and raises
        so no on-air work happens.
        """
        if self.simulate:
            return  # no on-air work in simulation
        if self._authorization is None:
            # _gate_live_run already refused; belt-and-braces.
            raise ConsentRequiredError(
                "_verify_observed_target called without authorization"
            )
        if not self._authorization.matches_observed_bssid(observed_bssid):
            from honeysnatch.utils.audit import get_audit_logger
            try:
                get_audit_logger().record(
                    "isolation_bssid_mismatch",
                    {
                        "attack": attack_label,
                        "authorized_bssid": self._authorization.bssid,
                        "observed_bssid": observed_bssid,
                    },
                )
            except Exception:
                pass
            raise ConsentRequiredError(
                f"Refused: authorized BSSID {self._authorization.bssid} "
                f"does not match observed BSSID {observed_bssid}. "
                "No attack packets were emitted."
            )

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _new_session(self, name: str = "") -> IsolationTestSession:
        session = IsolationTestSession(
            session_id=str(uuid.uuid4())[:8],
            name=name or f"isolation-{datetime.now():%Y%m%d-%H%M%S}",
            interface=self.interface,
            config_file=self.config_file,
            second_interface=self._second_iface,
        )
        self.session = session
        return session

    # ------------------------------------------------------------------
    # Individual attack runners
    # ------------------------------------------------------------------

    def run_gtk_check(self, second_interface: str = "", **kwargs) -> AttackResult:
        """Check whether two connected clients share the same GTK.

        If the GTK is shared an adversary can inject broadcast Wi-Fi frames
        containing unicast IP packets that bypass client isolation
        (Vanhoef NDSS'26 §3 — GTK Abuse).

        Returns
        -------
        AttackResult with:
          - VULNERABLE  → GTK bytes and index are identical for both clients
          - SECURE      → GTK values differ
          - INCONCLUSIVE → could not extract key (no hostap binary / simulation)
        """
        self._gate_live_run('GTK check')
        iface2 = second_interface or self._second_iface or self.interface

        if self.simulate:
            return AttackResult(
                attack_type=AttackType.GTK_SHARED,
                outcome=AttackOutcome.INCONCLUSIVE,
                details="Simulation mode: GTK check requires live wpa_supplicant",
            )

        log.info("GTK check: starting supplicants on %s and %s", self.interface, iface2)
        try:
            return self._gtk_check_live(iface2)
        except Exception as exc:
            log.error("GTK check failed: %s", exc)
            return AttackResult(
                attack_type=AttackType.GTK_SHARED,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _gtk_check_live(self, iface2: str) -> AttackResult:
        """Live GTK extraction via wpaspy GET_GTK command."""
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.attacks.gtk_abuse import check_gtk_shared

        sup1 = Supplicant(iface=self.interface, config_file=self.config_file,
                          debug=self.config.debug_level)
        sup2 = Supplicant(iface=iface2, config_file=self.config_file,
                          debug=self.config.debug_level)

        try:
            info1 = sup1.start_and_connect()
            self._verify_observed_target(info1.bssid, attack_label="live-isolation")
            info2 = sup2.start_and_connect()
            self._verify_observed_target(info2.bssid, attack_label="live-isolation-secondary")

            result = check_gtk_shared(
                victim_gtk=info1.gtk,
                attacker_gtk=info2.gtk,
                victim_gtk_idx=info1.gtk_idx,
                attacker_gtk_idx=info2.gtk_idx,
            )
            result.victim_mac = info1.mac
            result.attacker_mac = info2.mac
            result.target_bssid = info1.bssid
            result.target_ssid = info1.ssid
            return result

        finally:
            with contextlib.suppress(Exception):
                sup1.stop()
            with contextlib.suppress(Exception):
                sup2.stop()

    # ------------------------------------------------------------------

    def run_client2client(
        self,
        second_interface: str = "",
        mode: str = "ip",
        **kwargs,
    ) -> AttackResult:
        """Test client-to-client traffic isolation.

        Connects victim (interface 1) and attacker (interface 2) to the
        same network, then attempts to send a frame from attacker directly
        to victim at the specified layer.

        Parameters
        ----------
        mode:
            ``"arp"``       – ARP request to victim IP
            ``"ethernet"``  – Raw Ethernet unicast to victim MAC
            ``"ip"``        – IP ping / TCP SYN to victim IP
            ``"broadcast"`` – Broadcast frame containing unicast IP payload
        """
        self._gate_live_run('C2C')
        iface2 = second_interface or self._second_iface

        if self.simulate:
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_CLIENT_IP,
                outcome=AttackOutcome.INCONCLUSIVE,
                details=f"Simulation mode: C2C-{mode} skipped (no hardware)",
            )

        if not iface2:
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_CLIENT_IP,
                outcome=AttackOutcome.ERROR,
                details="second_interface required for C2C test",
            )

        log.info("C2C-%s: %s → %s", mode, iface2, self.interface)
        try:
            return self._c2c_live(iface2, mode)
        except Exception as exc:
            log.error("C2C test failed: %s", exc)
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_CLIENT_IP,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _c2c_live(self, iface2: str, mode: str) -> AttackResult:
        """Live C2C test using scapy injection."""
        from scapy.all import (
            Ether, ARP, IP, TCP, UDP, ICMP, Raw,
            sendp, sniff, conf,
        )
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.attacks.client2client import (
            create_c2c_result,
            AttackType as C2CType,
        )

        sup_victim  = Supplicant(iface=self.interface,  config_file=self.config_file,
                                 debug=self.config.debug_level)
        sup_attacker = Supplicant(iface=iface2, config_file=self.config_file,
                                  debug=self.config.debug_level)

        try:
            info_v = sup_victim.start_and_connect()
            self._verify_observed_target(info_v.bssid, attack_label="live-isolation")
            info_a = sup_attacker.start_and_connect()
            self._verify_observed_target(info_a.bssid, attack_label="live-isolation-secondary")

            victim_ip  = info_v.ip
            victim_mac = info_v.mac
            atk_ip     = info_a.ip
            atk_mac    = info_a.mac

            received = threading.Event()

            def _sniffer(pkt):
                if IP in pkt and pkt[IP].src == atk_ip and pkt[IP].dst == victim_ip:
                    received.set()

            # Start sniffer on victim interface
            t = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    prn=_sniffer,
                    timeout=_PACKET_TIMEOUT,
                    store=False,
                ),
                daemon=True,
            )
            t.start()
            time.sleep(0.5)  # Let sniffer settle

            if mode == "arp":
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=atk_mac) / \
                      ARP(op=1, hwsrc=atk_mac, psrc=atk_ip, pdst=victim_ip)
                sendp(pkt, iface=iface2, verbose=False)

            elif mode == "ethernet":
                pkt = Ether(dst=victim_mac, src=atk_mac) / \
                      IP(src=atk_ip, dst=victim_ip) / \
                      ICMP()
                sendp(pkt, iface=iface2, verbose=False)

            elif mode == "ip":
                pkt = Ether(dst=victim_mac, src=atk_mac) / \
                      IP(src=atk_ip, dst=victim_ip) / \
                      TCP(dport=_TCP_PROBE_PORT, flags="S")
                sendp(pkt, iface=iface2, verbose=False)

            elif mode == "broadcast":
                # GTK-abuse style: Ethernet broadcast but unicast IP dst
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=atk_mac) / \
                      IP(src=atk_ip, dst=victim_ip) / \
                      ICMP()
                sendp(pkt, iface=iface2, verbose=False)

            t.join(timeout=_PACKET_TIMEOUT + 1)
            vulnerable = received.is_set()

            return create_c2c_result(
                mode=mode,
                success=vulnerable,
                details=(
                    f"{'Frame reached' if vulnerable else 'Frame blocked'}: "
                    f"{atk_ip} ({atk_mac}) → {victim_ip} ({victim_mac}) [{mode}]"
                ),
                victim_mac=victim_mac,
                attacker_mac=atk_mac,
                target_bssid=info_v.bssid,
                target_ssid=info_v.ssid,
            )

        finally:
            with contextlib.suppress(Exception):
                sup_victim.stop()
            with contextlib.suppress(Exception):
                sup_attacker.stop()

    # ------------------------------------------------------------------

    def run_client2monitor(
        self,
        monitor_interface: str,
        mode: str = "default",
        **kwargs,
    ) -> AttackResult:
        """Test whether connected-client traffic leaks to a monitor interface.

        The attacker puts ``monitor_interface`` into monitor mode and listens
        while the victim sends traffic.  If frames are captured the network
        fails to isolate the PHY layer.
        """
        self._gate_live_run('C2M')
        if self.simulate:
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_MONITOR,
                outcome=AttackOutcome.INCONCLUSIVE,
                details="Simulation mode: C2M skipped",
            )

        if not monitor_interface:
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_MONITOR,
                outcome=AttackOutcome.ERROR,
                details="monitor_interface required",
            )

        log.info("C2M: victim=%s monitor=%s", self.interface, monitor_interface)
        try:
            return self._c2m_live(monitor_interface, mode)
        except Exception as exc:
            log.error("C2M test failed: %s", exc)
            return AttackResult(
                attack_type=AttackType.CLIENT_TO_MONITOR,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _c2m_live(self, monitor_iface: str, mode: str) -> AttackResult:
        """Live C2M test: connect victim, sniff on monitor."""
        from scapy.all import sniff, Ether, IP, ICMP, sendp
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.libwifi.wifi import set_monitor_mode
        from honeysnatch.isolation.attacks.client2monitor import create_c2m_result

        # Ensure monitor interface is in monitor mode
        try:
            set_monitor_mode(monitor_iface)
        except Exception as exc:
            log.warning("Could not set %s to monitor mode: %s", monitor_iface, exc)

        sup = Supplicant(iface=self.interface, config_file=self.config_file,
                         debug=self.config.debug_level)

        try:
            info = sup.start_and_connect()
            self._verify_observed_target(info.bssid, attack_label="live-c2m")
            victim_ip  = info.ip
            victim_mac = info.mac

            leaked = threading.Event()

            def _mon_handler(pkt):
                if IP in pkt and pkt[IP].src == victim_ip:
                    leaked.set()

            t = threading.Thread(
                target=lambda: sniff(
                    iface=monitor_iface,
                    prn=_mon_handler,
                    timeout=_PACKET_TIMEOUT,
                    store=False,
                ),
                daemon=True,
            )
            t.start()

            # Generate victim traffic
            for _ in range(3):
                pkt = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / \
                      IP(src=victim_ip, dst=self._server) / ICMP()
                sendp(pkt, iface=self.interface, verbose=False)
                time.sleep(0.3)

            t.join(timeout=_PACKET_TIMEOUT + 1)

            return create_c2m_result(
                leaked=leaked.is_set(),
                mode=mode,
                details=(
                    f"{'Traffic visible' if leaked.is_set() else 'No traffic observed'} "
                    f"on {monitor_iface} while victim {victim_ip} ({victim_mac}) transmitted"
                ),
            )

        finally:
            with contextlib.suppress(Exception):
                sup.stop()

    # ------------------------------------------------------------------

    def run_port_steal(
        self,
        second_interface: str = "",
        direction: str = "downlink",
        **kwargs,
    ) -> AttackResult:
        """Port-stealing attack: intercept victim's uplink or downlink traffic.

        Uplink steal (direction="uplink"):
            Attacker spoofs the gateway MAC on iface2.  Victim's uplink
            frames are routed to the attacker's NIC instead of the real GW.

        Downlink steal (direction="downlink"):
            Attacker spoofs the victim MAC on iface2.  Gateway routes
            victim-destined downlink frames to the attacker.

        Reference: Vanhoef NDSS'26 §4 — Port Stealing.
        """
        self._gate_live_run('port-steal')
        iface2 = second_interface or self._second_iface
        attype = AttackType.PORT_STEAL_UPLINK if direction == "uplink" \
                 else AttackType.PORT_STEAL_DOWNLINK

        if self.simulate:
            return AttackResult(
                attack_type=attype,
                outcome=AttackOutcome.INCONCLUSIVE,
                details=f"Simulation mode: port-steal-{direction} skipped",
            )

        if not iface2:
            return AttackResult(
                attack_type=attype,
                outcome=AttackOutcome.ERROR,
                details="second_interface required for port steal",
            )

        log.info("Port steal (%s): victim=%s attacker=%s",
                 direction, self.interface, iface2)
        try:
            return self._port_steal_live(iface2, direction, attype)
        except Exception as exc:
            log.error("Port steal failed: %s", exc)
            return AttackResult(
                attack_type=attype,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _port_steal_live(
        self,
        iface2: str,
        direction: str,
        attype: AttackType,
    ) -> AttackResult:
        """Live port-stealing via MAC spoofing + ARP poisoning."""
        from scapy.all import (
            Ether, ARP, IP, TCP, ICMP, Raw,
            sendp, sniff,
        )
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.libwifi.wifi import set_macaddress, restore_macaddress
        from honeysnatch.isolation.attacks.port_steal import create_port_steal_result

        sup_victim   = Supplicant(iface=self.interface, config_file=self.config_file,
                                  debug=self.config.debug_level)
        sup_attacker = Supplicant(iface=iface2, config_file=self.config_file,
                                  debug=self.config.debug_level)

        original_atk_mac: Optional[str] = None

        try:
            info_v = sup_victim.start_and_connect()
            self._verify_observed_target(info_v.bssid, attack_label="live-isolation")
            info_a = sup_attacker.start_and_connect()
            self._verify_observed_target(info_a.bssid, attack_label="live-isolation-secondary")

            victim_ip  = info_v.ip
            victim_mac = info_v.mac
            gw_ip      = _get_default_gw()
            gw_mac     = _arp_resolve(gw_ip, iface2) if gw_ip else None
            atk_mac    = info_a.mac

            intercepted = threading.Event()

            if direction == "uplink":
                # Spoof gateway MAC on attacker interface so the AP bridges
                # victim's uplink frames to us instead of the real GW.
                if not gw_mac:
                    return AttackResult(
                        attack_type=attype,
                        outcome=AttackOutcome.INCONCLUSIVE,
                        details="Could not resolve gateway MAC for uplink steal",
                    )
                original_atk_mac = atk_mac
                try:
                    set_macaddress(iface2, gw_mac)
                except Exception as exc:
                    log.warning("MAC spoof failed (%s): %s", iface2, exc)

                def _uplink_sniffer(pkt):
                    if IP in pkt and pkt[IP].src == victim_ip:
                        intercepted.set()

                t = threading.Thread(
                    target=lambda: sniff(
                        iface=iface2,
                        prn=_uplink_sniffer,
                        timeout=_PACKET_TIMEOUT,
                        store=False,
                    ),
                    daemon=True,
                )
                t.start()

                # Force victim to send uplink traffic
                _send_icmp(self.interface, victim_mac, victim_ip,
                           gw_ip or self._server)
                t.join(timeout=_PACKET_TIMEOUT + 1)

            else:  # downlink
                # Spoof victim MAC on attacker interface so GW bridges
                # victim-destined downlink frames to us.
                original_atk_mac = atk_mac
                try:
                    set_macaddress(iface2, victim_mac)
                except Exception as exc:
                    log.warning("MAC spoof failed (%s): %s", iface2, exc)

                def _downlink_sniffer(pkt):
                    if IP in pkt and pkt[IP].dst == victim_ip:
                        intercepted.set()

                t = threading.Thread(
                    target=lambda: sniff(
                        iface=iface2,
                        prn=_downlink_sniffer,
                        timeout=_PACKET_TIMEOUT,
                        store=False,
                    ),
                    daemon=True,
                )
                t.start()

                # Send traffic destined for victim from an external host
                # (simulate: send a ping from attacker's real external IP)
                _send_icmp(iface2, victim_mac, gw_ip or self._server, victim_ip)
                t.join(timeout=_PACKET_TIMEOUT + 1)

            return create_port_steal_result(
                direction=direction,
                intercepted=intercepted.is_set(),
                details=(
                    f"{'Intercepted' if intercepted.is_set() else 'Blocked'}: "
                    f"{direction} traffic for {victim_ip} ({victim_mac})"
                ),
            )

        finally:
            if original_atk_mac:
                with contextlib.suppress(Exception):
                    restore_macaddress(iface2)
            with contextlib.suppress(Exception):
                sup_victim.stop()
            with contextlib.suppress(Exception):
                sup_attacker.stop()

    # ------------------------------------------------------------------

    def run_gateway_bounce(
        self,
        second_interface: str = "",
        **kwargs,
    ) -> AttackResult:
        """Gateway bouncing: bypass MAC-layer isolation via IP routing.

        The attacker sends a frame with its own MAC at Ethernet layer but the
        victim's IP at IP layer.  If the AP/gateway forwards the frame to the
        victim at the IP layer, isolation is bypassed.

        Reference: Vanhoef NDSS'26 §3 — Gateway Bouncing.
        """
        self._gate_live_run('gateway-bounce')
        iface2 = second_interface or self._second_iface

        if self.simulate:
            return AttackResult(
                attack_type=AttackType.GATEWAY_BOUNCE,
                outcome=AttackOutcome.INCONCLUSIVE,
                details="Simulation mode: gateway bounce skipped",
            )

        if not iface2:
            return AttackResult(
                attack_type=AttackType.GATEWAY_BOUNCE,
                outcome=AttackOutcome.ERROR,
                details="second_interface required for gateway bounce",
            )

        log.info("Gateway bounce: victim=%s attacker=%s", self.interface, iface2)
        try:
            return self._gw_bounce_live(iface2)
        except Exception as exc:
            log.error("Gateway bounce failed: %s", exc)
            return AttackResult(
                attack_type=AttackType.GATEWAY_BOUNCE,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _gw_bounce_live(self, iface2: str) -> AttackResult:
        """Live gateway bounce via crafted Ethernet+IP frame."""
        from scapy.all import Ether, IP, ICMP, sendp, sniff
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.attacks.gateway_bounce import (
            create_gateway_bounce_result,
        )

        sup_victim   = Supplicant(iface=self.interface, config_file=self.config_file,
                                  debug=self.config.debug_level)
        sup_attacker = Supplicant(iface=iface2, config_file=self.config_file,
                                  debug=self.config.debug_level)

        try:
            info_v = sup_victim.start_and_connect()
            self._verify_observed_target(info_v.bssid, attack_label="live-isolation")
            info_a = sup_attacker.start_and_connect()
            self._verify_observed_target(info_a.bssid, attack_label="live-isolation-secondary")

            victim_ip  = info_v.ip
            victim_mac = info_v.mac
            atk_mac    = info_a.mac
            gw_mac     = _arp_resolve(_get_default_gw(), iface2) or "ff:ff:ff:ff:ff:ff"

            intercepted = threading.Event()

            def _victim_sniffer(pkt):
                if IP in pkt and pkt[IP].dst == victim_ip:
                    intercepted.set()

            t = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    prn=_victim_sniffer,
                    timeout=_PACKET_TIMEOUT,
                    store=False,
                ),
                daemon=True,
            )
            t.start()

            # Key frame: src MAC = attacker, dst MAC = gateway, dst IP = victim
            # Gateway bounces the packet at IP layer to victim.
            bounce_pkt = (
                Ether(src=atk_mac, dst=gw_mac) /
                IP(src=info_a.ip, dst=victim_ip) /
                ICMP()
            )
            sendp(bounce_pkt, iface=iface2, verbose=False, count=3)

            t.join(timeout=_PACKET_TIMEOUT + 1)

            return create_gateway_bounce_result(
                intercepted=intercepted.is_set(),
                details=(
                    f"{'Gateway forwarded' if intercepted.is_set() else 'Gateway blocked'} "
                    f"spoofed packet to {victim_ip} — "
                    f"src_mac={atk_mac} dst_mac={gw_mac}"
                ),
            )

        finally:
            with contextlib.suppress(Exception):
                sup_victim.stop()
            with contextlib.suppress(Exception):
                sup_attacker.stop()

    # ------------------------------------------------------------------

    def run_broadcast_reflection(
        self,
        second_interface: str = "",
        **kwargs,
    ) -> AttackResult:
        """Test whether broadcast frames from one client reach other clients.

        Sends a broadcast UDP frame from the attacker interface and listens
        on the victim interface.  If the victim receives the broadcast,
        client isolation does not filter intra-BSS broadcasts.
        """
        self._gate_live_run('broadcast-reflection')
        iface2 = second_interface or self._second_iface

        if self.simulate:
            return AttackResult(
                attack_type=AttackType.BROADCAST_REFLECTION,
                outcome=AttackOutcome.INCONCLUSIVE,
                details="Simulation mode: broadcast reflection skipped",
            )

        if not iface2:
            return AttackResult(
                attack_type=AttackType.BROADCAST_REFLECTION,
                outcome=AttackOutcome.ERROR,
                details="second_interface required",
            )

        log.info("Broadcast reflection: attacker=%s victim=%s", iface2, self.interface)
        try:
            return self._broadcast_reflection_live(iface2)
        except Exception as exc:
            log.error("Broadcast reflection failed: %s", exc)
            return AttackResult(
                attack_type=AttackType.BROADCAST_REFLECTION,
                outcome=AttackOutcome.ERROR,
                details=str(exc),
            )

    def _broadcast_reflection_live(self, iface2: str) -> AttackResult:
        """Live broadcast reflection test."""
        from scapy.all import Ether, IP, UDP, Raw, sendp, sniff
        from honeysnatch.isolation.supplicant import Supplicant
        from honeysnatch.isolation.attacks.broadcast_reflection import (
            create_broadcast_reflection_result,
        )

        # Use a unique magic payload so we can filter cleanly
        MAGIC = b"FHS-BCAST-" + uuid.uuid4().bytes[:4]
        BCAST_PORT = 19999

        sup_victim   = Supplicant(iface=self.interface, config_file=self.config_file,
                                  debug=self.config.debug_level)
        sup_attacker = Supplicant(iface=iface2, config_file=self.config_file,
                                  debug=self.config.debug_level)

        try:
            info_v = sup_victim.start_and_connect()
            self._verify_observed_target(info_v.bssid, attack_label="live-isolation")
            info_a = sup_attacker.start_and_connect()
            self._verify_observed_target(info_a.bssid, attack_label="live-isolation-secondary")

            received = threading.Event()

            def _victim_sniffer(pkt):
                if UDP in pkt and pkt[UDP].dport == BCAST_PORT:
                    if Raw in pkt and MAGIC in bytes(pkt[Raw].load):
                        received.set()

            t = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    prn=_victim_sniffer,
                    timeout=_PACKET_TIMEOUT,
                    store=False,
                ),
                daemon=True,
            )
            t.start()
            time.sleep(0.3)

            bcast_pkt = (
                Ether(src=info_a.mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src=info_a.ip, dst="255.255.255.255") /
                UDP(sport=BCAST_PORT, dport=BCAST_PORT) /
                Raw(MAGIC)
            )
            sendp(bcast_pkt, iface=iface2, verbose=False, count=3)

            t.join(timeout=_PACKET_TIMEOUT + 1)

            return create_broadcast_reflection_result(
                received=received.is_set(),
                details=(
                    f"{'Broadcast reached' if received.is_set() else 'Broadcast blocked'} "
                    f"victim {info_v.ip} ({info_v.mac}) "
                    f"from attacker {info_a.ip} ({info_a.mac})"
                ),
            )

        finally:
            with contextlib.suppress(Exception):
                sup_victim.stop()
            with contextlib.suppress(Exception):
                sup_attacker.stop()

    # ------------------------------------------------------------------
    # Composite run-all
    # ------------------------------------------------------------------

    def run_all(self, second_interface: str = "") -> IsolationTestSession:
        """Run the full isolation test battery and return a session.

        Tests run in this order:
          1. GTK shared check
          2. C2C IP
          3. C2C ARP
          4. C2C broadcast (GTK-abuse style)
          5. Gateway bounce
          6. Broadcast reflection
          7. Port steal downlink
          8. Port steal uplink

        The session can be persisted to the database via
        :meth:`~honeysnatch.db.database.DatabaseManager.save_isolation_session`.
        """
        self._gate_live_run('run-all')
        iface2 = second_interface or self._second_iface
        session = self._new_session("full-isolation-test")
        session.second_interface = iface2

        tests = [
            ("GTK check",            lambda: self.run_gtk_check(iface2)),
            ("C2C-IP",               lambda: self.run_client2client(iface2, mode="ip")),
            ("C2C-ARP",              lambda: self.run_client2client(iface2, mode="arp")),
            ("C2C-broadcast",        lambda: self.run_client2client(iface2, mode="broadcast")),
            ("Gateway bounce",       lambda: self.run_gateway_bounce(iface2)),
            ("Broadcast reflection", lambda: self.run_broadcast_reflection(iface2)),
            ("Port steal downlink",  lambda: self.run_port_steal(iface2, direction="downlink")),
            ("Port steal uplink",    lambda: self.run_port_steal(iface2, direction="uplink")),
        ]

        for name, fn in tests:
            log.info("Running: %s", name)
            try:
                result = fn()
            except Exception as exc:
                log.error("%s raised: %s", name, exc)
                result = AttackResult(
                    attack_type=AttackType.CLIENT_TO_CLIENT_IP,
                    outcome=AttackOutcome.ERROR,
                    details=f"{name}: {exc}",
                )
            session.add_result(result)
            _log_result(name, result)

        session.finish()
        log.info(
            "Isolation test complete — vulnerable: %d / %d",
            session.vulnerable_count, session.total_count,
        )
        return session


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _get_default_gw() -> Optional[str]:
    """Return the default gateway IP from the routing table (Linux)."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    gw_int = int(gw_hex, 16)
                    # little-endian 32-bit
                    gw_bytes = struct.pack("<I", gw_int)
                    return socket.inet_ntoa(gw_bytes)
    except Exception:
        pass
    return None


def _arp_resolve(ip: Optional[str], iface: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve an IP to a MAC via ARP on the given interface."""
    if not ip:
        return None
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface,
            timeout=timeout,
            verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None


def _send_icmp(iface: str, src_mac: str, src_ip: str, dst_ip: str) -> None:
    """Send a few ICMP echo requests from src to dst."""
    try:
        from scapy.all import Ether, IP, ICMP, sendp
        pkt = Ether(src=src_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()
        sendp(pkt, iface=iface, count=3, inter=0.1, verbose=False)
    except Exception as exc:
        log.debug("_send_icmp error: %s", exc)


def _log_result(name: str, result: AttackResult) -> None:
    """Log a single test result at the appropriate level."""
    emoji = {
        AttackOutcome.VULNERABLE:    "🔴 VULNERABLE",
        AttackOutcome.SECURE:        "🟢 SECURE",
        AttackOutcome.INCONCLUSIVE:  "🟡 INCONCLUSIVE",
        AttackOutcome.ERROR:         "⚠️  ERROR",
    }.get(result.outcome, str(result.outcome.value))
    log.info("  %-26s → %s", name, emoji)
    if result.details:
        log.debug("    %s", result.details)
