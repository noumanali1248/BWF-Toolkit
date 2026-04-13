#!/usr/bin/env python3
"""
Fast Port Scanner Attack Simulation
Generates real TCP SYN packets that can be captured by TShark
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

# Target configuration
TARGET = "192.168.18.22"  # Local IP (will be detected by TShark)
PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 3000, 5000, 6379, 27017]

print("=" * 80)
print("🔍 FAST PORT SCAN ATTACK SIMULATION")
print("=" * 80)
print(f"\nTarget: {TARGET}")
print(f"Ports: {len(PORTS)} common ports")
print(f"Mode: Parallel TCP connection attempts\n")

input("Press ENTER to start fast port scan...")

def scan_port(port):
    """Attempt to connect to a port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((TARGET, port))
        sock.close()
        if result == 0:
            print(f"  [✅] Port {port}: OPEN")
            return True
        else:
            print(f"  [❌] Port {port}: CLOSED")
            return False
    except Exception as e:
        print(f"  [❌] Port {port}: ERROR ({e})")
        return False

print("🚀 Launching rapid port scan...\n")
start_time = time.time()

# Scan all ports in parallel
with ThreadPoolExecutor(max_workers=21) as executor:
    results = list(executor.map(scan_port, PORTS))

elapsed = time.time() - start_time
open_ports = sum(results)

print(f"\n{'=' * 80}")
print("✅ PORT SCAN COMPLETED")
print("=" * 80)
print(f"\nResults:")
print(f"  • Total ports scanned: {len(PORTS)}")
print(f"  • Open ports: {open_ports}")
print(f"  • Closed ports: {len(PORTS) - open_ports}")
print(f"  • Time elapsed: {elapsed:.2f} seconds")
print(f"\nExpected Detection:")
print(f"  • Module 3 should show PORT_SCAN alerts")
print(f"  • Module 4 should detect Port Scan Attack")
print(f"\nCheck Module 4 Dashboard: http://localhost:8000/module4")
print(f"Check Module 3 Stats: http://localhost:8000/api/live-capture/statistics\n")
