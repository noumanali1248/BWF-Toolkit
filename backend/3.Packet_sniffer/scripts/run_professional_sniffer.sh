#!/bin/bash

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🔬 Professional Packet Sniffer (GitHub: EONRaider/Packet-Sniffer)"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "📡 Interface: enp0s31f6"
echo "📊 Mode: Detailed (with packet data)"
echo ""
echo "Starting capture in 2 seconds..."
echo "Press Ctrl+C to stop"
echo ""
sleep 2

cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/Packet-Sniffer"

# Run the sniffer with sudo using venv Python (has netprotocols installed)
sudo "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/.venv/bin/python3" packet_sniffer/sniffer.py -i enp0s31f6 -d

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ Capture completed!"
echo "════════════════════════════════════════════════════════════════════════════════"

