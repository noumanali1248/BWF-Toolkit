#!/usr/bin/env python3
"""
Clear all attack data - for demonstration purposes
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from comprehensive_attack_detector import get_comprehensive_attack_detector

# Get the singleton instance and clear it
detector = get_comprehensive_attack_detector()
detector.attack_events = []
detector.attack_patterns = {
    'wifi_attacks': [],
    'bluetooth_attacks': [],
    'network_attacks': [],
    'security_vulnerabilities': []
}

print("✅ All attack data cleared!")
print("📊 Current attack count: 0")
print("\n🎯 Ready for demonstration:")
print("   1. Open Module 4: http://localhost:8000/module4")
print("   2. Dashboard should show ZERO attacks")
print("   3. Run Blueson attack to see detections appear")













"""
Clear all attack data - for demonstration purposes
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from comprehensive_attack_detector import get_comprehensive_attack_detector

# Get the singleton instance and clear it
detector = get_comprehensive_attack_detector()
detector.attack_events = []
detector.attack_patterns = {
    'wifi_attacks': [],
    'bluetooth_attacks': [],
    'network_attacks': [],
    'security_vulnerabilities': []
}

print("✅ All attack data cleared!")
print("📊 Current attack count: 0")
print("\n🎯 Ready for demonstration:")
print("   1. Open Module 4: http://localhost:8000/module4")
print("   2. Dashboard should show ZERO attacks")
print("   3. Run Blueson attack to see detections appear")















