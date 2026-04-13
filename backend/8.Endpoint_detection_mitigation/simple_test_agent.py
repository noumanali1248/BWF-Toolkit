#!/usr/bin/env python3
"""Simple test agent that definitely works"""

import requests
import time
import socket
from datetime import datetime

agent_id = f"TEST-BWF-{socket.gethostname()}"
hostname = socket.gethostname()

print(f"\n{'='*60}")
print(f"🚀 Simple BWF Test Agent Starting")
print(f"{'='*60}")
print(f"Agent ID: {agent_id}")
print(f"Hostname: {hostname}")
print(f"{'='*60}\n")

# Register agent
print("📝 Registering agent...")
try:
    response = requests.post(
        "http://localhost:8000/api/module8/agents",
        json={
            "agent_id": agent_id,
            "hostname": hostname,
            "platform": "Linux",
            "system_info": {
                "type": "Wireless Security Monitor",
                "capabilities": ["wifi_scanning", "bluetooth_scanning"]
            }
        },
        timeout=5
    )
    if response.status_code == 200:
        print(f"✅ Agent registered successfully!")
    else:
        print(f"⚠️  Registration response: {response.status_code}")
        print(f"   {response.text}")
except Exception as e:
    print(f"❌ Registration error: {e}")
    exit(1)

print(f"\n{'='*60}")
print(f"✅ AGENT CONNECTED TO BWF TOOLKIT")
print(f"{'='*60}\n")
print(f"💡 Check dashboard: http://localhost:8000/module8")
print(f"   You should see agent: {agent_id}\n")
print(f"Press Ctrl+C to stop\n")

# Keep agent running and send periodic updates
try:
    iteration = 0
    while True:
        iteration += 1
        
        # Send fake wireless metrics
        metrics = {
            "wifi": {
                "total_networks": 5,
                "threat_level": "low"
            },
            "bluetooth": {
                "total_devices": 3,
                "threat_level": "low"  
            },
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            requests.post(
                f"http://localhost:8000/api/module8/agents/{agent_id}/metrics",
                json=metrics,
                timeout=3
            )
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Update #{iteration} sent ✓")
        except:
            pass
        
        time.sleep(10)
        
except KeyboardInterrupt:
    print(f"\n\n{'='*60}")
    print(f"🛑 Agent stopped")
    print(f"{'='*60}\n")
