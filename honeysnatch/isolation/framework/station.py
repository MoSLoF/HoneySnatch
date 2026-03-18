"""Station classes for structured test case execution.

Adapted from AirSnitch's library/station.py. Provides Station,
Authenticator, and Supplicant classes that work with the
trigger/action test framework.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from honeysnatch.isolation.libwifi.wifi import (
    log, STATUS, DEBUG, WARNING,
    DHCP_sock, ARP_sock,
)
from honeysnatch.isolation.libwifi.crypto import encrypt_ccmp
from honeysnatch.isolation.framework.daemon import LibraryDaemon
from honeysnatch.isolation.framework.testcase import Trigger, Action

from scapy.all import Dot11, Dot11QoS, Ether, DHCP, BOOTP, IP, UDP, Net


class Station(LibraryDaemon):
    """A station that executes test cases via trigger/action model."""

    def __init__(self, options):
        self.test = None
        if hasattr(options, 'test') and options.test is not None:
            self.test = options.test
            del options.test

        super().__init__(options)

        self.receive_func = None
        self.receive_eth = self.receive_mon = False
        self.bss = None
        self.pn = 5
        self.ip = None
        self.peerip = None
        self.obtained_ip = False
        self.pending_trigger = None
        self.arp_sock = None
        self.tk = self.gtk = None
        self.gtk_idx = 0
        self.gtk_seq = 0

    def perform_actions(self, trigger):
        if self.test is None:
            return
        if self.test.is_action_triggered(trigger):
            trigger_str = Trigger().__str__(trigger)
            log(STATUS, f"Trigger = {trigger_str}.", color="orange")
            if not self.test.generated:
                log(STATUS, f"Generating {getattr(self.test, 'name', 'unnamed')} test case.", color="green")
                self.test.generate(station=self)
                self.test.generated = True

        while self.test.is_action_triggered(trigger):
            act = self.test.get_next_action()
            if act.delay:
                time.sleep(act.delay)
            if act.action == Action.Receive:
                self.receive_func = act.function
                self.receive_eth = act.eth
                self.receive_mon = act.mon
            if act.action == Action.Inject:
                assert act.frame is not None
                if act.encrypt:
                    frame = self.encrypt(act.frame, self.tk)
                else:
                    frame = act.frame
                if act.eth:
                    self.inject_eth(frame)
                else:
                    self.inject_mon(frame)
                log(STATUS, "Injected " + repr(frame))
            if act.action == Action.Function:
                assert act.function is not None
                act.function(self)
            if act.action == Action.Reconnect:
                self.reconnect(optimized=act.optimized)
                break
            if act.action == Action.Terminate or act.terminate:
                if act.terminate_delay:
                    time.sleep(act.terminate_delay)
                self.terminate()
            if act.action == Action.GetIp and not self.obtained_ip:
                self.pending_trigger = trigger
                self.get_ip()
                log(DEBUG, "Waiting with next action until we have an IP")
                break

    def handle_started(self):
        self.perform_actions(Trigger.NoTrigger)

    def handle_trigger_associated(self):
        self.perform_actions(Trigger.Associated)

    def handle_trigger_authenticated(self):
        if not self.tk:
            self.load_keys()
        self.perform_actions(Trigger.AfterAuth)

    def handle_trigger_received(self):
        self.perform_actions(Trigger.Received)

    def handle_trigger_connected(self):
        if not self.tk:
            self.load_keys()
        self.perform_actions(Trigger.Connected)

    def handle_trigger_disconnected(self):
        self.perform_actions(Trigger.Disconnected)

    def encrypt(self, frame, key):
        if len(key) == 16:
            self.pn += 1
            return encrypt_ccmp(frame, key, self.pn)
        return None

    def handle_eth(self, frame):
        if self.receive_eth and self.receive_func(self, frame):
            self.receive_eth = False
            self.handle_trigger_received()

    def handle_mon(self, frame):
        if self.receive_mon and self.receive_func(self, frame):
            self.receive_mon = False
            self.handle_trigger_received()

    def set_ip_addresses(self, ip, peerip):
        self.ip = ip
        self.peerip = peerip
        self.obtained_ip = True
        if self.pending_trigger is not None:
            log(DEBUG, "Continuing actions that waited on IP address")
            trigger = self.pending_trigger
            self.pending_trigger = None
            self.perform_actions(trigger)

    def terminate(self):
        log(STATUS, "Disconnecting.", color="green")
        self.wpaspy_command("TERMINATE")
        self.terminated = True

    def load_keys(self):
        pass  # Override in subclasses

    def get_ip(self):
        pass  # Override in subclasses

    def reconnect(self, optimized=None):
        pass  # Override in subclasses


class FrameworkAuthenticator(Station):
    """Authenticator (AP) station for the test framework."""

    def __init__(self, options):
        options.ap = True
        super().__init__(options)
        self.sn = 10
        self.clientmac = None
        self.dhcp = None

    @property
    def peermac(self):
        return self.clientmac

    def load_keys(self):
        tk = self.wpaspy_command("GET_TK " + self.clientmac)
        self.tk = bytes.fromhex(tk)
        gtk, idx, seq = self.wpaspy_command("GET_GTK").split()
        self.gtk = bytes.fromhex(gtk)
        self.gtk_idx = int(idx)
        self.gtk_seq = int(seq, 16)

    def get_header(self, qos=True):
        header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
        if qos:
            header[Dot11].subtype = 8
            header.add_payload(Dot11QoS())
        self.sn += 1
        header.FCfield |= 'from-DS'
        header.addr1 = self.clientmac
        header.addr2 = self.mac
        header.addr3 = self.mac
        return header

    def handle_wpaspy(self, msg):
        log(DEBUG, "daemon: " + msg)
        if "AP-STA-ASSOCIATING" in msg:
            _, clientmac = msg.split()
            self.clientmac = clientmac
            self.handle_trigger_associated()
        if "AP-STA-CONNECTED" in msg:
            self.handle_trigger_connected()
        if "AP-STA-DISCONNECTED" in msg:
            _, clientmac = msg.split()
            if self.clientmac != clientmac:
                return
            self.clientmac = None
            self.handle_trigger_disconnected()

    def get_ip(self):
        self.dhcp = DHCP_sock(
            sock=self.sock_eth,
            domain='example.com',
            pool=Net('192.168.100.0/24'),
            network='192.168.100.0/24',
            gw='192.168.100.254',
            renewal_time=600, lease_time=3600,
        )
        import subprocess
        subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

    def handle_eth(self, p):
        if self.clientmac and p[Ether].src != self.clientmac:
            return
        if self.dhcp:
            self.dhcp.reply(p)
            if not self.obtained_ip and DHCP in p and self.clientmac in self.dhcp.leases:
                req_type = next(
                    opt[1] for opt in p[DHCP].options
                    if isinstance(opt, tuple) and opt[0] == 'message-type'
                )
                if req_type == 3:
                    peerip = self.dhcp.leases[self.clientmac]
                    self.set_ip_addresses('192.168.100.254', peerip)
        super().handle_eth(p)


class FrameworkSupplicant(Station):
    """Supplicant (client) station for the test framework."""

    def __init__(self, options):
        options.ap = False
        super().__init__(options)
        self.sn = 10
        self.time_retrans_dhcp = None
        self.dhcp_offer_frame = None
        self.dhcp_xid = None

    @property
    def peermac(self):
        return self.bss

    def load_keys(self):
        tk = self.wpaspy_command("GET tk")
        self.tk = bytes.fromhex(tk)
        gtk, idx, seq = self.wpaspy_command("GET_GTK").split()
        self.gtk = bytes.fromhex(gtk)
        self.gtk_idx = int(idx)
        self.gtk_seq = int(seq, 16)

    def clear_keys(self):
        self.tk = self.gtk = None

    def reconnect(self, optimized=None):
        log(STATUS, "Reconnecting to the AP.", color="orange")
        if optimized is not None:
            self.wpaspy_command("SET reassoc_same_bss_optim " + str(optimized))
        self.wpaspy_command("REASSOCIATE")

    def get_ip(self):
        if not self.dhcp_offer_frame:
            self.send_dhcp_discover()
        else:
            self.send_dhcp_request(self.dhcp_offer_frame)
        self.time_retrans_dhcp = time.time() + 2.5

    def send_dhcp_discover(self):
        import random
        if self.dhcp_xid is None:
            self.dhcp_xid = random.randint(0, 2**31)
        rawmac = bytes.fromhex(self.mac.replace(':', ''))
        req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) /
               IP(src="0.0.0.0", dst="255.255.255.255") /
               UDP(sport=68, dport=67) /
               BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid) /
               DHCP(options=[("message-type", "discover"), "end"]))
        self.inject_eth(req)

    def send_dhcp_request(self, offer):
        rawmac = bytes.fromhex(self.mac.replace(':', ''))
        myip = offer[BOOTP].yiaddr
        reply = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) /
                 IP(src="0.0.0.0", dst="255.255.255.255") /
                 UDP(sport=68, dport=67) /
                 BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid) /
                 DHCP(options=[("message-type", "request"),
                               ("requested_addr", myip),
                               ("hostname", "fhsclient"), "end"]))
        self.inject_eth(reply)

    def handle_eth_dhcp(self, p):
        if DHCP not in p:
            return
        req_type = next(
            opt[1] for opt in p[DHCP].options
            if isinstance(opt, tuple) and opt[0] == 'message-type'
        )
        if req_type == 2:
            log(STATUS, "Received DHCP offer, sending request.")
            self.send_dhcp_request(p)
            self.dhcp_offer_frame = p
        elif req_type == 5:
            clientip = p[BOOTP].yiaddr
            serverip = p[IP].src
            self.time_retrans_dhcp = None
            log(STATUS, f"DHCP ack: IP={clientip}, router={serverip}", color="green")
            self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=clientip, ARP_addr=self.mac)
            self.set_ip_addresses(clientip, serverip)

    def handle_eth(self, frame):
        if self.arp_sock is not None:
            self.arp_sock.reply(frame)
        if BOOTP in frame and frame[BOOTP].xid == self.dhcp_xid:
            self.handle_eth_dhcp(frame)
        super().handle_eth(frame)

    def handle_tick(self):
        if self.time_retrans_dhcp is not None and time.time() > self.time_retrans_dhcp:
            log(WARNING, "Retransmitting DHCP message", color="orange")
            self.get_ip()

    def get_header(self, qos=True):
        header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
        if qos:
            header[Dot11].subtype = 8
            header.add_payload(Dot11QoS())
        self.sn += 1
        header.FCfield |= 'to-DS'
        header.addr1 = self.bss
        header.addr2 = self.mac
        header.addr3 = self.bss
        return header

    def handle_wpaspy(self, msg):
        log(DEBUG, "daemon: " + msg)
        if "Associated with" in msg:
            x = re.compile("Associated with (.*)")
            self.bss = x.search(msg).group(1)
            self.handle_trigger_associated()
        if ("WPA: Key negotiation completed with" in msg or
                "WPA: EAPOL processing complete" in msg):
            self.handle_trigger_authenticated()
        if "CTRL-EVENT-CONNECTED" in msg:
            self.handle_trigger_connected()
        if "CTRL-EVENT-DISCONNECTED" in msg:
            self.handle_trigger_disconnected()
