#!/bin/bash
################################################################################
# RUN ALL 3 WIFI ATTACKS SEQUENTIALLY
# Total Duration: ~45 seconds
# Tests: DoS, Port Scan, Packet Flood
################################################################################

echo "================================================================================"
echo "🌐 WIFI ATTACK SUITE - MODULE 4 TESTING"
echo "================================================================================"
echo "Target: localhost:8000"
echo "Total Duration: ~45 seconds"
echo "Attacks: 3 types (DoS, Port Scan, Packet Flood)"
echo ""
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""
sleep 2

# Attack 1: DoS Flood
echo "================================================================================"
echo "🌊 ATTACK 1/3: HTTP DoS FLOOD"
echo "================================================================================"
echo "Method: Rapid HTTP requests"
echo "Requests: 200"
echo "Target: API endpoint"
echo "================================================================================"
echo ""

TARGET="http://127.0.0.1:8000/api/live-capture/status"
REQUEST_COUNT=200
SUCCESS=0

for i in $(seq 1 $REQUEST_COUNT); do
    curl -s -m 0.5 "$TARGET" > /dev/null 2>&1 &
    SUCCESS=$((SUCCESS + 1))
    
    if [ $((i % 50)) -eq 0 ]; then
        echo "  → Sent: $i requests"
    fi
done

wait
echo ""
echo "✅ DoS attack completed! ($REQUEST_COUNT requests)"
echo ""
sleep 5

# Attack 2: Port Scan
echo "================================================================================"
echo "🔍 ATTACK 2/3: PORT SCAN"
echo "================================================================================"
echo "Method: TCP port scanning"
echo "Ports: Common service ports (22, 80, 443, etc.)"
echo "Target: localhost"
echo "================================================================================"
echo ""

PORTS=(20 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 5900 8000 8080 8443)

for port in "${PORTS[@]}"; do
    echo -n "  [*] Scanning port $port... "
    timeout 0.5 nc -zv 127.0.0.1 $port 2>&1 | grep -q "succeeded" && echo "✅ OPEN" || echo "❌ CLOSED"
    sleep 0.1
done

echo ""
echo "✅ Port scan completed! (${#PORTS[@]} ports)"
echo ""
sleep 5

# Attack 3: Packet Flood
echo "================================================================================"
echo "🚀 ATTACK 3/3: PACKET FLOOD"
echo "================================================================================"
echo "Method: High-rate packet transmission"
echo "Duration: 15 seconds"
echo "Rate: ~100 packets/second"
echo "================================================================================"
echo ""

TARGET="http://127.0.0.1:8000/api/scan/results"
DURATION=15
START_TIME=$(date +%s)
SENT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    for i in {1..10}; do
        curl -s -m 0.1 "$TARGET" > /dev/null 2>&1 &
    done
    SENT=$((SENT + 10))
    
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION - ELAPSED))
    echo -ne "\r  [⚡] Attack in progress... ${REMAINING}s remaining | Packets: $SENT  "
    
    sleep 0.1
done

echo ""
echo ""
echo "✅ Packet flood completed! ($SENT packets)"
echo ""

# Summary
echo "================================================================================"
echo "✅ ALL WIFI ATTACKS COMPLETED!"
echo "================================================================================"
echo ""
echo "📊 Attack Summary:"
echo "  🌊 HTTP DoS Flood   : $REQUEST_COUNT requests - COMPLETED"
echo "  🔍 Port Scan        : ${#PORTS[@]} ports - COMPLETED"
echo "  🚀 Packet Flood     : $SENT packets - COMPLETED"
echo ""
echo "📱 View Results:"
echo "  Dashboard: http://localhost:8000/module4"
echo ""
echo "🔍 Verify Detection:"
echo "  - Check Module 4 for DoS, Port Scan, and Packet Flood alerts"
echo "  - Attacks should appear for 20 seconds"
echo "  - Then move to attack history"
echo ""
echo "================================================================================"












################################################################################
# RUN ALL 3 WIFI ATTACKS SEQUENTIALLY
# Total Duration: ~45 seconds
# Tests: DoS, Port Scan, Packet Flood
################################################################################

echo "================================================================================"
echo "🌐 WIFI ATTACK SUITE - MODULE 4 TESTING"
echo "================================================================================"
echo "Target: localhost:8000"
echo "Total Duration: ~45 seconds"
echo "Attacks: 3 types (DoS, Port Scan, Packet Flood)"
echo ""
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""
sleep 2

# Attack 1: DoS Flood
echo "================================================================================"
echo "🌊 ATTACK 1/3: HTTP DoS FLOOD"
echo "================================================================================"
echo "Method: Rapid HTTP requests"
echo "Requests: 200"
echo "Target: API endpoint"
echo "================================================================================"
echo ""

TARGET="http://127.0.0.1:8000/api/live-capture/status"
REQUEST_COUNT=200
SUCCESS=0

for i in $(seq 1 $REQUEST_COUNT); do
    curl -s -m 0.5 "$TARGET" > /dev/null 2>&1 &
    SUCCESS=$((SUCCESS + 1))
    
    if [ $((i % 50)) -eq 0 ]; then
        echo "  → Sent: $i requests"
    fi
done

wait
echo ""
echo "✅ DoS attack completed! ($REQUEST_COUNT requests)"
echo ""
sleep 5

# Attack 2: Port Scan
echo "================================================================================"
echo "🔍 ATTACK 2/3: PORT SCAN"
echo "================================================================================"
echo "Method: TCP port scanning"
echo "Ports: Common service ports (22, 80, 443, etc.)"
echo "Target: localhost"
echo "================================================================================"
echo ""

PORTS=(20 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 5900 8000 8080 8443)

for port in "${PORTS[@]}"; do
    echo -n "  [*] Scanning port $port... "
    timeout 0.5 nc -zv 127.0.0.1 $port 2>&1 | grep -q "succeeded" && echo "✅ OPEN" || echo "❌ CLOSED"
    sleep 0.1
done

echo ""
echo "✅ Port scan completed! (${#PORTS[@]} ports)"
echo ""
sleep 5

# Attack 3: Packet Flood
echo "================================================================================"
echo "🚀 ATTACK 3/3: PACKET FLOOD"
echo "================================================================================"
echo "Method: High-rate packet transmission"
echo "Duration: 15 seconds"
echo "Rate: ~100 packets/second"
echo "================================================================================"
echo ""

TARGET="http://127.0.0.1:8000/api/scan/results"
DURATION=15
START_TIME=$(date +%s)
SENT=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    for i in {1..10}; do
        curl -s -m 0.1 "$TARGET" > /dev/null 2>&1 &
    done
    SENT=$((SENT + 10))
    
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION - ELAPSED))
    echo -ne "\r  [⚡] Attack in progress... ${REMAINING}s remaining | Packets: $SENT  "
    
    sleep 0.1
done

echo ""
echo ""
echo "✅ Packet flood completed! ($SENT packets)"
echo ""

# Summary
echo "================================================================================"
echo "✅ ALL WIFI ATTACKS COMPLETED!"
echo "================================================================================"
echo ""
echo "📊 Attack Summary:"
echo "  🌊 HTTP DoS Flood   : $REQUEST_COUNT requests - COMPLETED"
echo "  🔍 Port Scan        : ${#PORTS[@]} ports - COMPLETED"
echo "  🚀 Packet Flood     : $SENT packets - COMPLETED"
echo ""
echo "📱 View Results:"
echo "  Dashboard: http://localhost:8000/module4"
echo ""
echo "🔍 Verify Detection:"
echo "  - Check Module 4 for DoS, Port Scan, and Packet Flood alerts"
echo "  - Attacks should appear for 20 seconds"
echo "  - Then move to attack history"
echo ""
echo "================================================================================"














