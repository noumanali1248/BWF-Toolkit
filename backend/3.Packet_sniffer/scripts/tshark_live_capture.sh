#!/bin/bash

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🔬 TShark Live Packet Capture System"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
mkdir -p live_captures

echo "Choose capture mode:"
echo ""
echo "1) Live to Console (Real-time, human-readable)"
echo "2) Write to Rotating PCAP Files (60s each, keep last 10)"
echo "3) Both (Live display + Save to files)"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo ""
        echo "🔴 Starting live capture to console..."
        echo "Press Ctrl+C to stop"
        echo ""
        echo "2389" | sudo -S tshark -i any
        ;;
    2)
        echo ""
        echo "💾 Starting rotating file capture..."
        echo "Files will be saved to: live_captures/"
        echo "Each file: 60 seconds, Keep last 10 files"
        echo "Press Ctrl+C to stop"
        echo ""
        echo "2389" | sudo -S tshark -i any -b duration:60 -b files:10 -w live_captures/capture.pcap
        ;;
    3)
        echo ""
        echo "🔴💾 Starting BOTH live display and file capture..."
        echo "Press Ctrl+C to stop"
        echo ""
        
        # Start file capture in background
        echo "2389" | sudo -S tshark -i any -b duration:60 -b files:10 -w live_captures/capture.pcap &
        BG_PID=$!
        
        sleep 2
        
        # Start live display in foreground
        echo "2389" | sudo -S tshark -i any
        
        # Kill background process when done
        kill $BG_PID 2>/dev/null
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ Capture stopped"
echo "════════════════════════════════════════════════════════════════════════════════"

if [ -d "live_captures" ] && [ "$(ls -A live_captures 2>/dev/null)" ]; then
    echo ""
    echo "📁 Captured files:"
    ls -lh live_captures/
    echo ""
    echo "💡 View captured files with:"
    echo "   wireshark live_captures/capture_00001*.pcap"
    echo "   tshark -r live_captures/capture_00001*.pcap"
fi

