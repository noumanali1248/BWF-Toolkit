#!/bin/bash

echo "========================================================================"
echo "Advanced Linux Packet Capture & Sniffing System"
echo "========================================================================"
echo ""
echo "This script will capture packets for 15 seconds and show detailed info"
echo ""

# Navigate to the directory
cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"

# Activate virtual environment
source .venv/bin/activate

# Run the packet capture script with sudo
echo "Starting packet capture with sudo permissions..."
echo "Press Ctrl+C to stop early, or wait for automatic completion"
echo ""

sudo .venv/bin/python3 - <<'PYTHON_SCRIPT'
import os
import sys
import time
import psutil
from datetime import datetime
from scapy.all import *

print("="*70)
print("📡 Available Network Interfaces:")
print("="*70)

# Get interfaces
net_io = psutil.net_io_counters(pernic=True)
interfaces = []

for interface_name in net_io.keys():
    if interface_name != 'lo':  # Skip loopback
        interfaces.append(interface_name)
        stats = net_io[interface_name]
        print(f"  • {interface_name:15s} - RX: {stats.packets_recv:,} packets, TX: {stats.packets_sent:,} packets")

if not interfaces:
    print("\n❌ No suitable interfaces found!")
    sys.exit(1)

print(f"\n🎯 Capturing on: {', '.join(interfaces)}")
print(f"⏱  Duration: 15 seconds")
print(f"📊 Showing first 10 packets in detail\n")
print("="*70)

packet_count = 0
start_time = time.time()

def packet_handler(packet):
    global packet_count
    packet_count += 1
    
    if packet_count <= 10:
        print(f"\n{'─'*70}")
        print(f"📦 Packet #{packet_count}")
        print(f"{'─'*70}")
        print(f"⏰ Time: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
        print(f"📏 Size: {len(packet)} bytes")
        
        # Extract protocol info
        protocol = "Unknown"
        src = ""
        dst = ""
        
        if packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst
            protocol = "Ethernet"
        
        if packet.haslayer(IP):
            src = f"{packet[IP].src}:{packet[IP].sport if packet.haslayer(TCP) or packet.haslayer(UDP) else ''}"
            dst = f"{packet[IP].dst}:{packet[IP].dport if packet.haslayer(TCP) or packet.haslayer(UDP) else ''}"
            protocol = packet[IP].sprintf("%IP.proto%")
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            flags = []
            if packet[TCP].flags.S: flags.append('SYN')
            if packet[TCP].flags.A: flags.append('ACK')
            if packet[TCP].flags.F: flags.append('FIN')
            if packet[TCP].flags.R: flags.append('RST')
            if packet[TCP].flags.P: flags.append('PSH')
            print(f"🚩 Flags: {', '.join(flags)}")
        
        if packet.haslayer(UDP):
            protocol = "UDP"
        
        if packet.haslayer(ARP):
            protocol = "ARP"
            src = f"{packet[ARP].psrc} ({packet[ARP].hwsrc})"
            dst = f"{packet[ARP].pdst} ({packet[ARP].hwdst})"
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            print(f"🔍 DNS Query: {packet[DNSQR].qname.decode('utf-8', errors='ignore')}")
        
        print(f"📡 Protocol: {protocol}")
        print(f"📤 Source: {src}")
        print(f"📥 Destination: {dst}")
        print(f"📝 Summary: {packet.summary()}")
    
    # Progress update every 50 packets
    if packet_count % 50 == 0:
        elapsed = time.time() - start_time
        print(f"\n⏱ {elapsed:.1f}s | 📦 {packet_count} packets captured | 📈 {packet_count/elapsed:.1f} pkt/s")

print("\n🔴 Starting capture...")
print("="*70 + "\n")

# Capture on first available interface
try:
    sniff(
        iface=interfaces[0],
        prn=packet_handler,
        timeout=15,
        store=False
    )
except KeyboardInterrupt:
    print("\n\n⚠ Interrupted by user")

# Final stats
elapsed = time.time() - start_time
print(f"\n{'='*70}")
print(f"📊 Capture Complete")
print(f"{'='*70}")
print(f"⏱  Duration: {elapsed:.2f} seconds")
print(f"📦 Total Packets: {packet_count}")
print(f"📈 Average Rate: {packet_count/elapsed:.2f} packets/second")
print(f"{'='*70}\n")

PYTHON_SCRIPT

echo ""
echo "✅ Capture completed!"
echo ""

