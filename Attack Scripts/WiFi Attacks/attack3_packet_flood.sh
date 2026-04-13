#!/bin/bash
################################################################################
# ATTACK 3: NETWORK PACKET FLOOD
# Status: NEW - READY TO TEST
# Severity: HIGH
# Duration: 20 seconds
################################################################################

echo "=========================================="
echo "🌊 Network Packet Flood Attack"
echo "=========================================="
echo "Target: localhost:8000"
echo "Duration: 20 seconds"
echo "Rate: 100 packets/second"
echo ""

TARGET="http://localhost:8000/api/scan/results"
DURATION=20
RATE=100

echo "✅ Launching packet flood..."

START_TIME=$(date +%s)
SENT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    # Send rapid requests
    for i in {1..10}; do
        curl -s -m 0.1 "$TARGET" > /dev/null 2>&1 &
    done
    SENT=$((SENT + 10))
    
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION - ELAPSED))
    echo -ne "\r  [⚡] Attack in progress... ${REMAINING}s remaining | Packets sent: $SENT  "
    
    sleep 0.1
done

echo ""
echo ""
echo "✅ Attack completed!"
echo "  Total packets sent: $SENT"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"












################################################################################
# ATTACK 3: NETWORK PACKET FLOOD
# Status: NEW - READY TO TEST
# Severity: HIGH
# Duration: 20 seconds
################################################################################

echo "=========================================="
echo "🌊 Network Packet Flood Attack"
echo "=========================================="
echo "Target: localhost:8000"
echo "Duration: 20 seconds"
echo "Rate: 100 packets/second"
echo ""

TARGET="http://localhost:8000/api/scan/results"
DURATION=20
RATE=100

echo "✅ Launching packet flood..."

START_TIME=$(date +%s)
SENT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    # Send rapid requests
    for i in {1..10}; do
        curl -s -m 0.1 "$TARGET" > /dev/null 2>&1 &
    done
    SENT=$((SENT + 10))
    
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION - ELAPSED))
    echo -ne "\r  [⚡] Attack in progress... ${REMAINING}s remaining | Packets sent: $SENT  "
    
    sleep 0.1
done

echo ""
echo ""
echo "✅ Attack completed!"
echo "  Total packets sent: $SENT"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"














