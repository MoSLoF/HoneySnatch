#!/bin/bash
set -e

# HS-08: anchor to this script's directory so we work regardless of the
# caller's CWD. deploy-hackberrypi.sh, `fhs isolation build`, and manual
# invocations from repo root now all behave identically.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Usage.
if [[ $# -gt 1 ]] ; then
    echo "Usage; $0 [directory]"
    exit 1
fi

# Take in command line arguments.
HOSTAP=${1:-"hostap_2_10"} # Default to hostap_2_10.
CUSTOM_CONFIG=true

# Sanity checks.
if [ ! -d "$HOSTAP" ] ; then
	echo "Directory $HOSTAP not found (looked in $SCRIPT_DIR)"
	exit 1
fi

# Build hostapd.
cd $HOSTAP
cd hostapd
cp defconfig .config
if [ "$CUSTOM_CONFIG" = true ] ; then
	echo "" >> .config
	echo "# Configuration changes for the Wi-Fi Framework:"  >> .config
	echo "CONFIG_IEEE80211N=y" >> .config
	echo "CONFIG_SAE=y" >> .config
	echo "CONFIG_IEEE80211R=y" >> .config
	echo "CONFIG_INTERWORKING=y" >> .config
	echo "CONFIG_TESTING_OPTIONS=y" >> .config
	echo "CONFIG_FRAMEWORK_EXTENSIONS=y" >> .config
fi
make clean
make -j 2

# Build supplicant.
cd ../wpa_supplicant
cp defconfig .config
if [ "$CUSTOM_CONFIG" = true ] ; then
	echo "" >> .config
	echo "# Configuration changes for the Wi-Fi Framework:" >> .config
	echo "CONFIG_SAE=y" >> .config
	echo "CONFIG_TESTING_OPTIONS=y" >> .config
	echo "CONFIG_FRAMEWORK_EXTENSIONS=y" >> .config
fi
make clean
make -j 2
