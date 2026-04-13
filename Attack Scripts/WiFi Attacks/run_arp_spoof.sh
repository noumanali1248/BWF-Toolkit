#!/bin/bash

# ARP Spoofing Attack Helper Script
# Usage: ./run_arp_spoof.sh [TARGET_IP] [GATEWAY_IP]

# Default values (Change these to match your network if needed)
DEFAULT_TARGET="192.168.18.41 "
DEFAULT_GATEWAY="192.168.18.1"
SPOOF_MAC="00:11:22:33:44:55" # Fake MAC to ensure detection

TARGET=${1:-$DEFAULT_TARGET}
GATEWAY=${2:-$DEFAULT_GATEWAY}

echo "🚀 Starting ARP Spoofing Attack..."
echo "🎯 Target: $TARGET"
echo "🚪 Gateway: $GATEWAY"
echo "🎭 Spoofed MAC: $SPOOF_MAC"
echo "----------------------------------------"

# Run the attack script with sudo
sudo python3 arp_spoof_attack.py --target "$TARGET" --gateway "$GATEWAY" --spoof-mac "$SPOOF_MAC" --delay 0.5
