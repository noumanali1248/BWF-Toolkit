#!/bin/bash
################################################################################
# RUN WIFI ATTACK WITH AUTOMATIC DETECTION
# This script runs a WiFi attack and automatically adds it to the detection system
################################################################################

ATTACK_SCRIPT="$1"
ATTACK_TYPE="$2"

if [ -z "$ATTACK_SCRIPT" ] || [ -z "$ATTACK_TYPE" ]; then
    echo "Usage: $0 <attack_script> <attack_type>"
    echo ""
    echo "Available attack types:"
    echo "  packet_flood - For packet flood attacks"
    echo "  dos_flood    - For HTTP DoS attacks"
    echo "  port_scan    - For port scan attacks"
    echo ""
    echo "Examples:"
    echo "  $0 attack3_packet_flood.sh packet_flood"
    echo "  $0 attack1_dos.sh dos_flood"
    echo "  $0 attack2_portscan.sh port_scan"
    exit 1
fi

echo "================================================================================"
echo "🌐 WIFI ATTACK WITH DETECTION"
echo "================================================================================"
echo "Attack Script: $ATTACK_SCRIPT"
echo "Attack Type: $ATTACK_TYPE"
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""

# Step 1: Clear any existing attacks
echo "🧹 STEP 1: Clearing existing attacks..."
cd "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
echo '{"timestamp": "", "total_attacks": 0, "attacks": []}' > realtime_bluetooth_attacks.json
echo "✅ Cleared existing attacks"

# Step 2: Run the WiFi attack script
echo ""
echo "🚀 STEP 2: Running WiFi attack..."
bash "$ATTACK_SCRIPT"

# Step 3: Add the attack to detection system
echo ""
echo "📡 STEP 3: Adding attack to detection system..."
python3 "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Attack Scripts and Commands/WiFi Attacks/add_wifi_attack.py" "$ATTACK_TYPE"

# Step 4: Verify detection
echo ""
echo "✅ STEP 4: Verifying detection..."
sleep 2
curl -s http://localhost:8000/api/module4/real-attacks | python3 -c "
import json, sys
data = json.load(sys.stdin)
total = data.get('total_events', 0)
events = data.get('events', [])
print(f'Total attacks detected: {total}')
for event in events[:3]:
    print(f'- {event.get(\"title\", \"Unknown\")}')
"

echo ""
echo "================================================================================"
echo "🎯 WIFI ATTACK COMPLETED WITH DETECTION!"
echo "================================================================================"
echo "📱 Check Dashboard: http://localhost:8000/module4"
echo "✅ WiFi attacks should now be visible for 20 seconds"
echo "================================================================================"











################################################################################
# RUN WIFI ATTACK WITH AUTOMATIC DETECTION
# This script runs a WiFi attack and automatically adds it to the detection system
################################################################################

ATTACK_SCRIPT="$1"
ATTACK_TYPE="$2"

if [ -z "$ATTACK_SCRIPT" ] || [ -z "$ATTACK_TYPE" ]; then
    echo "Usage: $0 <attack_script> <attack_type>"
    echo ""
    echo "Available attack types:"
    echo "  packet_flood - For packet flood attacks"
    echo "  dos_flood    - For HTTP DoS attacks"
    echo "  port_scan    - For port scan attacks"
    echo ""
    echo "Examples:"
    echo "  $0 attack3_packet_flood.sh packet_flood"
    echo "  $0 attack1_dos.sh dos_flood"
    echo "  $0 attack2_portscan.sh port_scan"
    exit 1
fi

echo "================================================================================"
echo "🌐 WIFI ATTACK WITH DETECTION"
echo "================================================================================"
echo "Attack Script: $ATTACK_SCRIPT"
echo "Attack Type: $ATTACK_TYPE"
echo "Dashboard: http://localhost:8000/module4"
echo "================================================================================"
echo ""

# Step 1: Clear any existing attacks
echo "🧹 STEP 1: Clearing existing attacks..."
cd "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
echo '{"timestamp": "", "total_attacks": 0, "attacks": []}' > realtime_bluetooth_attacks.json
echo "✅ Cleared existing attacks"

# Step 2: Run the WiFi attack script
echo ""
echo "🚀 STEP 2: Running WiFi attack..."
bash "$ATTACK_SCRIPT"

# Step 3: Add the attack to detection system
echo ""
echo "📡 STEP 3: Adding attack to detection system..."
python3 "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Attack Scripts and Commands/WiFi Attacks/add_wifi_attack.py" "$ATTACK_TYPE"

# Step 4: Verify detection
echo ""
echo "✅ STEP 4: Verifying detection..."
sleep 2
curl -s http://localhost:8000/api/module4/real-attacks | python3 -c "
import json, sys
data = json.load(sys.stdin)
total = data.get('total_events', 0)
events = data.get('events', [])
print(f'Total attacks detected: {total}')
for event in events[:3]:
    print(f'- {event.get(\"title\", \"Unknown\")}')
"

echo ""
echo "================================================================================"
echo "🎯 WIFI ATTACK COMPLETED WITH DETECTION!"
echo "================================================================================"
echo "📱 Check Dashboard: http://localhost:8000/module4"
echo "✅ WiFi attacks should now be visible for 20 seconds"
echo "================================================================================"













