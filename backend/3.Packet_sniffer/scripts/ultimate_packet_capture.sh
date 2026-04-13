#!/bin/bash

# Ultimate Packet Capture System
# Uses libpcap (via tcpdump) and Wireshark (tshark) for comprehensive packet capture

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🔬 Ultimate Packet Capture System"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Using: libpcap + Wireshark (TShark) + tcpdump"
echo ""

# Configuration
INTERFACE="enp0s31f6"
DURATION=60
OUTPUT_DIR="/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$OUTPUT_DIR/capture_${TIMESTAMP}.pcap"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "📡 Interface: $INTERFACE"
echo "⏱  Duration: $DURATION seconds"
echo "💾 Output: $PCAP_FILE"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Check for required tools
echo "🔍 Checking tools..."
if ! command -v tcpdump &> /dev/null; then
    echo "❌ tcpdump not found"
    exit 1
fi
if ! command -v tshark &> /dev/null; then
    echo "❌ tshark not found"
    exit 1
fi
echo "✅ All tools available"
echo ""

# Start capture
echo "🔴 Starting packet capture..."
echo "   Press Ctrl+C to stop early"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Use tcpdump to capture with libpcap and display real-time
sudo timeout $DURATION tcpdump -i $INTERFACE -w $PCAP_FILE -v -n -e 2>&1 &
TCPDUMP_PID=$!

# Monitor the capture in real-time
echo "📊 Capture in progress..."
sleep 2

# Count packets every 5 seconds
for i in $(seq 1 $((DURATION / 5))); do
    sleep 5
    if [ -f "$PCAP_FILE" ]; then
        PACKET_COUNT=$(sudo tcpdump -r $PCAP_FILE 2>/dev/null | wc -l)
        echo "   ⏱ ${i}×5s: $PACKET_COUNT packets captured so far..."
    fi
done

# Wait for capture to complete
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ Capture completed!"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Analyze with tshark
if [ -f "$PCAP_FILE" ]; then
    TOTAL_PACKETS=$(sudo tshark -r $PCAP_FILE 2>/dev/null | wc -l)
    FILE_SIZE=$(du -h "$PCAP_FILE" | cut -f1)
    
    echo "📊 Capture Statistics:"
    echo "   • Total Packets: $TOTAL_PACKETS"
    echo "   • File Size: $FILE_SIZE"
    echo "   • File: $PCAP_FILE"
    echo ""
    
    # Show protocol distribution
    echo "📋 Protocol Distribution:"
    echo "════════════════════════════════════════════════════════════════════════════════"
    sudo tshark -r $PCAP_FILE -q -z io,phs 2>/dev/null | head -30
    echo ""
    
    # Show conversation statistics
    echo "🌐 Top 10 Conversations:"
    echo "════════════════════════════════════════════════════════════════════════════════"
    sudo tshark -r $PCAP_FILE -q -z conv,ip 2>/dev/null | head -15
    echo ""
    
    # Show first 20 packets in detail
    echo "📦 First 20 Packets (Detailed):"
    echo "════════════════════════════════════════════════════════════════════════════════"
    sudo tshark -r $PCAP_FILE -V -c 20 2>/dev/null | head -200
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "💡 Analysis Commands:"
    echo "   • View all packets: sudo tshark -r $PCAP_FILE"
    echo "   • View in Wireshark GUI: wireshark $PCAP_FILE"
    echo "   • Filter HTTP: sudo tshark -r $PCAP_FILE -Y http"
    echo "   • Filter DNS: sudo tshark -r $PCAP_FILE -Y dns"
    echo "   • Statistics: sudo tshark -r $PCAP_FILE -q -z io,stat,1"
    echo ""
    
    # Export to JSON
    JSON_FILE="${PCAP_FILE%.pcap}.json"
    echo "💾 Exporting to JSON..."
    sudo tshark -r $PCAP_FILE -T json > "$JSON_FILE" 2>/dev/null
    if [ -f "$JSON_FILE" ]; then
        JSON_SIZE=$(du -h "$JSON_FILE" | cut -f1)
        echo "   ✅ JSON exported: $JSON_FILE ($JSON_SIZE)"
    fi
    echo ""
    
else
    echo "❌ No capture file created!"
fi

echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ Done! Check the captures directory for files."
echo "════════════════════════════════════════════════════════════════════════════════"

