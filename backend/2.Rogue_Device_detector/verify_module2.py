#!/usr/bin/env python3
"""
Module 2 Verification Script
"""

import requests

def main():
    print("=== MODULE 2 VERIFICATION ===")
    
    # Test Module 1 Data
    print("1. Module 1 Data:")
    try:
        r1 = requests.get('http://localhost:8000/api/scan/results')
        d1 = r1.json()
        wifi_count = len(d1.get('wifi_networks', []))
        bt_count = len(d1.get('bluetooth_devices', []))
        print(f"   WiFi: {wifi_count}, Bluetooth: {bt_count}")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    # Test Module 2 Rogue Detection
    print("2. Module 2 Rogue Detection:")
    try:
        r2 = requests.get('http://localhost:8000/api/rogue-detection/devices')
        d2 = r2.json()
        print(f"   Rogue devices: {len(d2)}")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    # Test Module 2 Statistics
    print("3. Module 2 Statistics:")
    try:
        r3 = requests.get('http://localhost:8000/api/rogue-detection/statistics')
        d3 = r3.json()
        print(f"   Total devices: {d3.get('total_devices', 0)}")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    # Test Module 2 Status
    print("4. Module 2 Status:")
    try:
        r4 = requests.get('http://localhost:8000/api/rogue-detection/status')
        d4 = r4.json()
        print(f"   Available: {d4.get('available', False)}, Running: {d4.get('running', False)}")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    print("=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    main()

