#!/bin/bash

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🚀 Advanced Packet Capture with Traffic Generation"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

cd "/home/floki/Downloads/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"

# Start packet capture in background
echo "🔴 Starting packet capture (30 seconds)..."
echo "2389" | sudo -S python3 advanced_multi_capture.py &
CAPTURE_PID=$!

# Wait 2 seconds for capture to start
sleep 2

# Generate traffic
echo "📡 Generating network traffic..."
echo ""

# Ping various hosts
ping -c 10 google.com > /dev/null 2>&1 &
ping -c 10 8.8.8.8 > /dev/null 2>&1 &
ping -c 10 1.1.1.1 > /dev/null 2>&1 &

# DNS queries
dig google.com > /dev/null 2>&1 &
dig github.com > /dev/null 2>&1 &
dig reddit.com > /dev/null 2>&1 &

# HTTP/HTTPS requests
curl -s https://www.google.com > /dev/null 2>&1 &
curl -s https://www.github.com > /dev/null 2>&1 &
curl -s https://www.reddit.com > /dev/null 2>&1 &
curl -s http://example.com > /dev/null 2>&1 &

echo "✅ Traffic generation started"
echo ""
echo "⏱️  Waiting for capture to complete (30 seconds)..."

# Wait for capture to finish
wait $CAPTURE_PID

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ Capture Complete!"
echo "════════════════════════════════════════════════════════════════════════════════"

