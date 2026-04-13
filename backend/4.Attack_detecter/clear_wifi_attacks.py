#!/usr/bin/env python3
"""
Clear all WiFi attack data - for demonstration purposes
Keep only Bluetooth attacks in the system
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from comprehensive_attack_detector import get_comprehensive_attack_detector

# Get the singleton instance
detector = get_comprehensive_attack_detector()

# Count current attacks
total_attacks = len(detector.attack_events)
wifi_attacks = [a for a in detector.attack_events if 'bluetooth' not in str(a.get('type', '')).lower() and 'bt_' not in str(a.get('type', ''))]
bluetooth_attacks = [a for a in detector.attack_events if 'bluetooth' in str(a.get('type', '')).lower() or 'bt_' in str(a.get('type', ''))]

print("🔍 CURRENT ATTACK STATUS")
print("=" * 50)
print(f"📊 Total attacks: {total_attacks}")
print(f"📡 WiFi/Network attacks: {len(wifi_attacks)}")
print(f"🔵 Bluetooth attacks: {len(bluetooth_attacks)}")
print("")

# Clear WiFi attacks - keep only Bluetooth attacks
detector.attack_events = bluetooth_attacks

# Clear WiFi-related pattern data
if 'wifi_attacks' in detector.attack_patterns:
    detector.attack_patterns['wifi_attacks'] = []
if 'network_attacks' in detector.attack_patterns:
    detector.attack_patterns['network_attacks'] = []
if 'security_vulnerabilities' in detector.attack_patterns:
    detector.attack_patterns['security_vulnerabilities'] = []

print("✅ WiFi ATTACK DATA CLEARED!")
print("=" * 50)
print(f"📊 Remaining attacks: {len(detector.attack_events)}")
print(f"🔵 Bluetooth attacks preserved: {len(bluetooth_attacks)}")
print("")
print("🎯 READY FOR WIFI ATTACK DEMONSTRATION:")
print("=" * 50)
print("   1. Open Module 4: http://localhost:8000/module4")
print("   2. Dashboard should show only Bluetooth attacks")
print("   3. WiFi attacks section should be clean/empty")
print("   4. Run your WiFi attacks")
print("   5. Refresh Module 4 to see new WiFi attacks detected")
print("")
print("🚀 System ready for fresh WiFi attack testing!")













"""
Clear all WiFi attack data - for demonstration purposes
Keep only Bluetooth attacks in the system
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from comprehensive_attack_detector import get_comprehensive_attack_detector

# Get the singleton instance
detector = get_comprehensive_attack_detector()

# Count current attacks
total_attacks = len(detector.attack_events)
wifi_attacks = [a for a in detector.attack_events if 'bluetooth' not in str(a.get('type', '')).lower() and 'bt_' not in str(a.get('type', ''))]
bluetooth_attacks = [a for a in detector.attack_events if 'bluetooth' in str(a.get('type', '')).lower() or 'bt_' in str(a.get('type', ''))]

print("🔍 CURRENT ATTACK STATUS")
print("=" * 50)
print(f"📊 Total attacks: {total_attacks}")
print(f"📡 WiFi/Network attacks: {len(wifi_attacks)}")
print(f"🔵 Bluetooth attacks: {len(bluetooth_attacks)}")
print("")

# Clear WiFi attacks - keep only Bluetooth attacks
detector.attack_events = bluetooth_attacks

# Clear WiFi-related pattern data
if 'wifi_attacks' in detector.attack_patterns:
    detector.attack_patterns['wifi_attacks'] = []
if 'network_attacks' in detector.attack_patterns:
    detector.attack_patterns['network_attacks'] = []
if 'security_vulnerabilities' in detector.attack_patterns:
    detector.attack_patterns['security_vulnerabilities'] = []

print("✅ WiFi ATTACK DATA CLEARED!")
print("=" * 50)
print(f"📊 Remaining attacks: {len(detector.attack_events)}")
print(f"🔵 Bluetooth attacks preserved: {len(bluetooth_attacks)}")
print("")
print("🎯 READY FOR WIFI ATTACK DEMONSTRATION:")
print("=" * 50)
print("   1. Open Module 4: http://localhost:8000/module4")
print("   2. Dashboard should show only Bluetooth attacks")
print("   3. WiFi attacks section should be clean/empty")
print("   4. Run your WiFi attacks")
print("   5. Refresh Module 4 to see new WiFi attacks detected")
print("")
print("🚀 System ready for fresh WiFi attack testing!")















