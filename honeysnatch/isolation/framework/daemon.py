"""Library-style daemon with select-based event loop.

Adapted from AirSnitch's library/daemon.py. Provides the base
Daemon class used by the Station framework for structured test
case execution.

This is distinct from isolation/daemon.py which is the research-style
daemon used by the procedural attack scripts.
"""
from __future__ import annotations

import os
import subprocess
import select
import time
from typing import Optional

from honeysnatch.isolation.libwifi.wifi import (
    log, STATUS, DEBUG, ERROR, WARNING, croprepr,
    MonitorSocket, L2Socket, set_monitor_mode, get_device_driver,
)


def log_level2switch(options) -> list[str]:
    debug = getattr(options, 'debug', 0)
    if debug >= 2:
        return ["-dd", "-K"]
    elif debug >= 1:
        return ["-d", "-K"]
    return ["-K"]


class LibraryDaemon:
    """Wi-Fi Daemon with select-based event loop.

    This is the library-style daemon from AirSnitch that provides
    a socket-based event loop with monitor, ethernet, and wpaspy handlers.
    """

    default_hostap = "./vendor/hostap_2_10"
    default_config = "./data/isolation"
    default_wpaspy = "/var/run"

    def __init__(self, options):
        self.options = options
        self.process = None
        self.terminated = False
        self.nic_iface = self.nic_mon = None
        self.sock_eth = self.sock_mon = None
        self.wpaspy_ctrl = None
        self.wpaspy_queue = []
        self.mac = None

        try:
            self._configure_interfaces()
        except Exception as ex:
            log(ERROR, "Unable to configure interfaces: " + str(ex))
            raise RuntimeError(
                "Interface configuration failed. "
                "Does the interface exist? Are you running as root?"
            ) from ex

        import scapy.arch
        self.mac = scapy.arch.get_if_hwaddr(self.nic_iface)

        self.sock_eth = None
        from scapy.all import ETH_P_ALL
        self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon)

        if getattr(self.options, 'ap', False):
            self.ctrl_iface = self.default_wpaspy + "/hostapd/" + self.nic_iface
        else:
            self.ctrl_iface = self.default_wpaspy + "/wpa_supplicant/" + self.nic_iface

    def _configure_interfaces(self):
        subprocess.check_output(["rfkill", "unblock", "wifi"])
        self.nic_iface = self.options.iface

        import scapy.arch
        try:
            scapy.arch.get_if_addr(self.nic_iface)
        except ValueError:
            raise RuntimeError(f"Interface {self.nic_iface} doesn't exist.")

        self.nic_mon = "mon" + self.nic_iface[:12]

        try:
            scapy.arch.get_if_addr(self.nic_mon)
        except ValueError:
            subprocess.call(["iw", self.nic_mon, "del"],
                          stdout=subprocess.PIPE, stdin=subprocess.PIPE)
            subprocess.check_output(["iw", self.nic_iface, "interface", "add",
                                    self.nic_mon, "type", "monitor"])

        set_monitor_mode(self.nic_mon)
        log(STATUS, f"Using interface {self.nic_mon} ({get_device_driver(self.nic_mon)}) to inject frames.")

    def _wpaspy_connect(self):
        from honeysnatch.isolation.wpaspy import Ctrl

        time_abort = time.time() + 10
        while not os.path.exists(self.ctrl_iface) and time.time() < time_abort:
            time.sleep(0.1)

        if not os.path.exists(self.ctrl_iface):
            raise RuntimeError(
                "Unable to connect to control interface. "
                "Did hostapd/wpa_supplicant start properly?"
            )

        self.wpaspy_ctrl = Ctrl(self.ctrl_iface)
        self.wpaspy_ctrl.attach()

    def handle_mon(self, p):
        pass

    def handle_eth(self, p):
        log(DEBUG, "Ethernet: " + croprepr(p))

    def handle_wpaspy(self, msg):
        log(DEBUG, "wpaspy: " + msg)

    def handle_started(self):
        pass

    def handle_tick(self):
        pass

    def inject_mon(self, p):
        self.sock_mon.send(p)

    def inject_eth(self, p):
        if self.sock_eth:
            self.sock_eth.send(p)

    def wpaspy_command(self, cmd):
        response = self.wpaspy_ctrl.request("> " + cmd)
        while not response.startswith("> "):
            self.wpaspy_queue.append(response)
            log(DEBUG, "<appending> " + response)
            response = self.wpaspy_ctrl.recv()

        if "UNKNOWN COMMAND" in response:
            raise RuntimeError(f"Daemon did not recognize command: {cmd.split()[0]}")
        elif "FAIL" in response:
            raise RuntimeError(f"Failed to execute command: {cmd}")

        return response[2:]

    def _get_command(self):
        hostap = self.default_hostap if not getattr(self.options, 'binary', None) else self.options.binary
        config = self.default_config if not getattr(self.options, 'config', None) else self.options.config

        if getattr(self.options, 'ap', False):
            if not getattr(self.options, 'config', None):
                config += "/hostapd.conf"
            binary = hostap + "/hostapd/hostapd" if not getattr(self.options, 'binary', None) else hostap
            cmd = [binary, "-i", self.options.iface, config]
        else:
            if not getattr(self.options, 'config', None):
                config += "/supplicant.conf"
            binary = hostap + "/wpa_supplicant/wpa_supplicant" if not getattr(self.options, 'binary', None) else hostap
            cmd = [binary, "-Dnl80211", "-i", self.options.iface, "-c", config, "-W"]

        cmd += log_level2switch(self.options)
        return cmd

    def run(self):
        subprocess.call(["rm", "-rf", self.ctrl_iface])
        cmd = self._get_command()
        log(STATUS, "Starting daemon using: " + " ".join(cmd))

        self.process = subprocess.Popen(cmd)
        self._wpaspy_connect()

        from scapy.all import ETH_P_ALL
        self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)
        self.handle_started()

        sockets = [self.sock_mon, self.sock_eth, self.wpaspy_ctrl.s]
        while True:
            while len(self.wpaspy_queue) > 0:
                self.handle_wpaspy(self.wpaspy_queue.pop())

            if self.terminated:
                break
            sel = select.select(sockets, [], [], 0.5)

            if self.sock_mon in sel[0]:
                p = self.sock_mon.recv()
                if p is not None:
                    self.handle_mon(p)

            if self.sock_eth in sel[0]:
                p = self.sock_eth.recv()
                from scapy.all import Ether
                if p is not None and Ether in p:
                    self.handle_eth(p)

            if self.wpaspy_ctrl.s in sel[0]:
                msg = self.wpaspy_ctrl.recv()
                self.handle_wpaspy(msg)

            self.handle_tick()

    def stop(self):
        log(STATUS, "Closing daemon and cleaning up...")
        if self.process:
            self.process.terminate()
            self.process.wait()
        if self.sock_eth:
            self.sock_eth.close()
        if self.sock_mon:
            self.sock_mon.close()
        self.terminated = True
