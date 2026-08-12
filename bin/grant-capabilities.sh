#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# grant-capabilities.sh — scoped CAP_NET_RAW / CAP_NET_ADMIN grant
#
# WHY THIS EXISTS (review finding F-01):
#   The obvious `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
#   works, but it grants network-raw capability to EVERY Python invocation
#   on the host, for EVERY user, forever. Any Python script, any pip-
#   installed CLI, any venv that inherits system python — all get the
#   capability. That's a system-wide privilege elevation to solve one
#   tool's need.
#
# WHAT THIS DOES:
#   Copies the current venv's Python interpreter to `.venv/bin/python-net`,
#   applies setcap to THAT copy only, and prints a one-liner so `fhs` can
#   be invoked through the elevated interpreter. Uninstalling the venv
#   removes the elevated binary. Other users, other venvs, other Python
#   invocations on the box are unaffected.
#
# USAGE:
#   source .venv/bin/activate
#   sudo bin/grant-capabilities.sh
#   # then run scans via: python-net -m honeysnatch scan start …
#
# UNDO:
#   rm .venv/bin/python-net   # removes the elevated copy
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

if [ "${VIRTUAL_ENV:-}" = "" ]; then
    echo "[!] No active virtualenv. Activate one first:" >&2
    echo "    source .venv/bin/activate" >&2
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "[!] Must run as root (sudo) to apply setcap." >&2
    exit 1
fi

SRC="$(readlink -f "$VIRTUAL_ENV/bin/python")"
DEST="$VIRTUAL_ENV/bin/python-net"

if [ ! -x "$SRC" ]; then
    echo "[!] Could not locate the venv's python interpreter at $SRC" >&2
    exit 1
fi

# Refuse to touch a system-scope interpreter. A venv Python usually resolves
# to /usr/bin/pythonX.Y — if the operator's venv uses --system-site-packages
# and their `python` symlink points at a shared interpreter, we absolutely do
# NOT want to setcap that. The venv MUST have its own copy.
case "$SRC" in
    /usr/bin/*|/usr/local/bin/*|/opt/*|/System/*)
        echo "[!] $SRC looks like a system interpreter. Refusing to setcap it." >&2
        echo "    Recreate the venv WITHOUT --system-site-packages so it owns" >&2
        echo "    its own python binary, then re-run this script." >&2
        exit 1
        ;;
esac

# HS-06 hardening: create a `hbv-netcap` group, restrict the elevated
# interpreter to root:hbv-netcap 0750, and require the operator to add
# their user to hbv-netcap explicitly. This narrows the arbitrary-Python
# risk from "any local user" to "group members only" while keeping the
# helper working across the standard venv setups.
if ! getent group hbv-netcap >/dev/null; then
    echo "[*] Creating hbv-netcap group"
    groupadd --system hbv-netcap
fi

echo "[*] Copying $SRC → $DEST (root:hbv-netcap 0750)"
cp -f "$SRC" "$DEST"
chown root:hbv-netcap "$DEST"
chmod 0750 "$DEST"

echo "[*] Applying CAP_NET_RAW,CAP_NET_ADMIN to $DEST (this interpreter only)"
setcap cap_net_raw,cap_net_admin=eip "$DEST"

echo ""
echo "[!] RESIDUAL RISK (documented, accepted): $DEST is a general-purpose"
echo "    Python interpreter with network-raw capability. Any hbv-netcap"
echo "    group member can invoke it with any script — the capability is"
echo "    on the interpreter, not on the honeysnatch module. Keep group"
echo "    membership tight and prefer per-command sudo rules when possible."
echo ""
echo "[✓] Done. Invoke honeysnatch scans through the elevated interpreter:"
echo ""
echo "    $DEST -m honeysnatch scan start -i wlan0mon"
echo ""
echo "    # or add a wrapper in your PATH:"
echo "    ln -s $DEST ~/.local/bin/fhs-net"
echo "    fhs-net -m honeysnatch scan start -i wlan0mon"
echo ""
echo "[*] Verification:"
getcap "$DEST"
ls -l "$DEST"
echo ""
echo "[*] To grant a user access:"
echo "    sudo usermod -aG hbv-netcap <username>"
echo "    # they must log out and back in for the new group to take effect"
echo ""
echo "[*] To revoke:"
echo "    rm $DEST                     # remove the elevated interpreter"
echo "    sudo groupdel hbv-netcap     # remove the group (optional)"
