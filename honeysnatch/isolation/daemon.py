"""Base daemon for managing wpa_supplicant/hostapd processes.

Refactored from AirSnitch's research Daemon class. Provides process
lifecycle management, wpaspy control interface communication, and
event handling.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from honeysnatch.isolation.libwifi.wifi import log, STATUS, DEBUG, ERROR, WARNING


class IsolationDaemonError(Exception):
    """Error in isolation daemon operation."""
    pass


class Daemon:
    """Base daemon for managing wpa_supplicant or hostapd processes.

    Handles process startup, wpaspy control interface connection,
    and command execution.
    """

    def __init__(self, iface: str, config_file: str = "",
                 hostap_dir: str = "", debug: int = 0,
                 ap_mode: bool = False):
        self.iface = iface
        self.config_file = config_file
        self.debug = debug
        self.ap_mode = ap_mode
        self.process: Optional[subprocess.Popen] = None
        self.wpaspy_ctrl = None
        self.wpaspy_queue: list[str] = []
        self.terminated = False

        # Resolve hostap directory
        if hostap_dir:
            self.hostap_dir = hostap_dir
        else:
            # Default: vendor/hostap_2_10 relative to project root
            self.hostap_dir = str(
                Path(__file__).resolve().parents[2] / "vendor" / "hostap_2_10"
            )

        # Control interface path
        if ap_mode:
            self.ctrl_iface = f"/var/run/hostapd/{self.iface}"
        else:
            self.ctrl_iface = f"/var/run/wpa_supplicant/{self.iface}"

    def _get_binary_path(self) -> str:
        """Get the path to wpa_supplicant or hostapd binary."""
        if self.ap_mode:
            return os.path.join(self.hostap_dir, "hostapd", "hostapd")
        else:
            return os.path.join(self.hostap_dir, "wpa_supplicant", "wpa_supplicant")

    def _get_debug_flags(self) -> list[str]:
        """Get debug flags based on debug level."""
        if self.debug >= 2:
            return ["-dd", "-K"]
        elif self.debug >= 1:
            return ["-d", "-K"]
        return ["-K"]

    def _build_command(self) -> list[str]:
        """Build the command to start the daemon."""
        binary = self._get_binary_path()
        if not os.path.isfile(binary):
            raise IsolationDaemonError(
                f"Binary not found: {binary}. "
                "Run vendor/build.sh to compile hostap."
            )

        if self.ap_mode:
            if not self.config_file or not os.path.isfile(self.config_file):
                raise IsolationDaemonError(
                    f"Config file not found: {self.config_file}"
                )
            cmd = [binary, "-i", self.iface, self.config_file]
        else:
            if not self.config_file or not os.path.isfile(self.config_file):
                raise IsolationDaemonError(
                    f"Config file not found: {self.config_file}"
                )
            cmd = [binary, "-Dnl80211", "-i", self.iface,
                   "-c", self.config_file, "-W"]

        cmd += self._get_debug_flags()
        return cmd

    def connect_wpaspy(self) -> None:
        """Connect to the wpaspy control interface."""
        try:
            from honeysnatch.isolation.wpaspy import Ctrl
        except ImportError:
            raise IsolationDaemonError(
                "wpaspy module not available. Ensure vendor dependencies are built."
            )

        if Ctrl is None:
            raise IsolationDaemonError(
                "wpaspy Ctrl class not available. This feature requires Linux."
            )

        # Wait for control interface to appear
        time_abort = time.time() + 10
        while not os.path.exists(self.ctrl_iface) and time.time() < time_abort:
            time.sleep(0.1)

        if not os.path.exists(self.ctrl_iface):
            raise IsolationDaemonError(
                "Unable to connect to control interface. "
                "Did hostapd/wpa_supplicant start properly?"
            )

        try:
            self.wpaspy_ctrl = Ctrl(self.ctrl_iface)
            self.wpaspy_ctrl.attach()
        except Exception as e:
            raise IsolationDaemonError(
                f"Failed to connect to wpaspy control interface: {e}"
            ) from e

    def wpaspy_command(self, cmd: str, can_fail: bool = False) -> Optional[str]:
        """Send a command to wpa_supplicant/hostapd via wpaspy.

        Args:
            cmd: Command string to send
            can_fail: If True, don't raise on FAIL response

        Returns:
            Response string, or None if can_fail and command failed
        """
        if self.wpaspy_ctrl is None:
            raise IsolationDaemonError("Not connected to wpaspy control interface")

        response = self.wpaspy_ctrl.request(cmd)

        # Handle interleaved event messages
        while response.startswith("<"):
            self.wpaspy_queue.append(response)
            log(DEBUG, f"<appending> {response}")
            response = self.wpaspy_ctrl.recv()

        if "UNKNOWN COMMAND" in response:
            raise IsolationDaemonError(
                f"Daemon did not recognize command: {cmd.split()[0]}. "
                "Did you recompile wpa_supplicant/hostapd?"
            )
        if "FAIL" in response:
            if can_fail:
                return None
            raise IsolationDaemonError(f"Command failed: {cmd}")

        return response.strip()

    def wait_event(self, event: str, timeout: float = 10) -> bool:
        """Wait for a specific event from the control interface.

        Args:
            event: Event string to wait for
            timeout: Maximum time to wait in seconds

        Returns:
            True if event was received, False on timeout
        """
        # Check queued events first
        for i, msg in enumerate(self.wpaspy_queue):
            if event in msg:
                self.wpaspy_queue.pop(i)
                return True

        # Wait for new events
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.wpaspy_ctrl and self.wpaspy_ctrl.pending(timeout=0.5):
                msg = self.wpaspy_ctrl.recv()
                if event in msg:
                    return True
                self.wpaspy_queue.append(msg)

        return False

    def start(self) -> None:
        """Start the daemon process and connect to its control interface."""
        # Clean up stale control interface
        if os.path.exists(self.ctrl_iface):
            subprocess.call(["rm", "-rf", self.ctrl_iface])

        cmd = self._build_command()
        log(STATUS, "Starting daemon: " + " ".join(cmd))

        try:
            self.process = subprocess.Popen(cmd)
        except FileNotFoundError:
            raise IsolationDaemonError(
                f"Binary not found: {cmd[0]}. "
                "Run vendor/build.sh to compile."
            )

        self.connect_wpaspy()

    def stop(self) -> None:
        """Stop the daemon process and clean up."""
        log(STATUS, "Closing daemon and cleaning up...")
        if self.process:
            self.process.terminate()
            self.process.wait()
        self.terminated = True
