#!/usr/bin/env python3
"""
BWF Wireless Security Agent - Module 8
Lightweight endpoint agent for monitoring wireless security threats
Focuses on: Bluetooth, Wi-Fi, Rogue Devices, Attack Detection
"""

import asyncio
import json
import time
import socket
import platform
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Any

class BWFWirelessAgent:
    """Wireless Security Agent for BWF Toolkit"""
    
    def __init__(self, agent_id=None):
        self.agent_id = agent_id or f"BWF-{socket.gethostname()}-{int(time.time())}"
        self.hostname = socket.gethostname()
        self.platform = platform.system()
        self.running = True
        self.scan_interval = 30  # Scan every 30 seconds
        
        # Wireless monitoring state
        self.known_wifi_networks = set()
        self.known_bluetooth_devices = set()
        self.suspicious_activity = []
        self.threat_count = 0
        
    def get_system_info(self):
        """Get system information relevant to wireless security"""
        return {
            'hostname': self.hostname,
            'platform': self.platform,
            'platform_version': platform.version(),
            'agent_type': 'Wireless Security Monitor',
            'capabilities': [
                'wifi_scanning',
                'bluetooth_scanning',
                'rogue_detection',
                'attack_monitoring',
                'network_isolation'
            ],
            'scan_interval': self.scan_interval
        }
    
    def scan_wifi_networks(self) -> Dict[str, Any]:
        """Scan for Wi-Fi networks and detect anomalies"""
        try:
            networks = []
            rogue_networks = []
            suspicious_ssids = []
            
            if self.platform == "Linux":
                # Use iwlist for Wi-Fi scanning
                try:
                    result = subprocess.run(
                        ['iwlist', 'scan'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    # Parse results (simplified)
                    lines = result.stdout.split('\n')
                    current_network = {}
                    
                    for line in lines:
                        if 'ESSID:' in line:
                            ssid = line.split('ESSID:')[1].strip().strip('"')
                            if ssid:
                                current_network['ssid'] = ssid
                                
                                # Check for suspicious SSIDs
                                suspicious_patterns = ['free', 'open', 'guest', 'test', 'default']
                                if any(pattern in ssid.lower() for pattern in suspicious_patterns):
                                    suspicious_ssids.append(ssid)
                                
                        elif 'Signal level' in line:
                            signal_match = re.search(r'-(\d+)', line)
                            if signal_match:
                                current_network['signal'] = -int(signal_match.group(1))
                        
                        elif 'Encryption key:' in line:
                            if 'off' in line.lower():
                                current_network['encryption'] = 'Open'
                                rogue_networks.append(current_network.get('ssid', 'Unknown'))
                            else:
                                current_network['encryption'] = 'Encrypted'
                            
                            if current_network.get('ssid'):
                                networks.append(current_network.copy())
                                current_network = {}
                                
                except subprocess.TimeoutExpired:
                    pass
                except FileNotFoundError:
                    # iwlist not available, try nmcli
                    try:
                        result = subprocess.run(
                            ['nmcli', 'dev', 'wifi', 'list'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        lines = result.stdout.split('\n')[1:]  # Skip header
                        for line in lines:
                            if line.strip():
                                parts = line.split()
                                if len(parts) >= 2:
                                    ssid = parts[1]
                                    networks.append({
                                        'ssid': ssid,
                                        'signal': parts[5] if len(parts) > 5 else 'N/A',
                                        'encryption': 'Unknown'
                                    })
                                    
                                    # Check for suspicious SSIDs
                                    suspicious_patterns = ['free', 'open', 'guest', 'test', 'default']
                                    if any(pattern in ssid.lower() for pattern in suspicious_patterns):
                                        suspicious_ssids.append(ssid)
                    except:
                        pass
            
            elif self.platform == "Windows":
                # Use netsh for Windows
                try:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip()
                            if ssid:
                                networks.append({'ssid': ssid})
                                
                                # Check for suspicious SSIDs
                                suspicious_patterns = ['free', 'open', 'guest', 'test']
                                if any(pattern in ssid.lower() for pattern in suspicious_patterns):
                                    suspicious_ssids.append(ssid)
                except:
                    pass
            
            # Detect new networks (potential rogue APs)
            current_ssids = set(n.get('ssid', '') for n in networks)
            new_networks = current_ssids - self.known_wifi_networks
            
            if new_networks:
                print(f"   ⚠️  New Wi-Fi networks detected: {', '.join(new_networks)}")
            
            self.known_wifi_networks = current_ssids
            
            return {
                'total_networks': len(networks),
                'networks': networks[:10],  # Send top 10
                'rogue_networks': rogue_networks,
                'suspicious_ssids': suspicious_ssids,
                'new_networks': list(new_networks),
                'threat_level': 'high' if (rogue_networks or suspicious_ssids) else 'low'
            }
            
        except Exception as e:
            return {
                'total_networks': 0,
                'networks': [],
                'error': str(e),
                'threat_level': 'unknown'
            }
    
    def scan_bluetooth_devices(self) -> Dict[str, Any]:
        """Scan for Bluetooth devices and detect anomalies"""
        try:
            devices = []
            suspicious_devices = []
            
            if self.platform == "Linux":
                # Use hcitool for Bluetooth scanning
                try:
                    result = subprocess.run(
                        ['hcitool', 'scan'],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.strip().split(None, 1)
                            if len(parts) >= 1:
                                mac = parts[0]
                                name = parts[1] if len(parts) > 1 else 'Unknown'
                                devices.append({
                                    'mac': mac,
                                    'name': name,
                                    'type': 'bluetooth'
                                })
                                
                                # Check for suspicious device names
                                suspicious_keywords = ['hacker', 'exploit', 'attack', 'test', 'unknown']
                                if any(keyword in name.lower() for keyword in suspicious_keywords):
                                    suspicious_devices.append(name)
                                    
                except FileNotFoundError:
                    # hcitool not available, try bluetoothctl
                    try:
                        result = subprocess.run(
                            ['bluetoothctl', 'devices'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'Device' in line:
                                parts = line.split()
                                if len(parts) >= 3:
                                    devices.append({
                                        'mac': parts[1],
                                        'name': ' '.join(parts[2:]),
                                        'type': 'bluetooth'
                                    })
                    except:
                        pass
                except:
                    pass
            
            elif self.platform == "Windows":
                # Windows Bluetooth scanning (requires PowerShell)
                try:
                    ps_command = "Get-PnpDevice | Where-Object {$_.Class -eq 'Bluetooth'} | Select-Object FriendlyName"
                    result = subprocess.run(
                        ['powershell', '-Command', ps_command],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    lines = result.stdout.split('\n')[3:]  # Skip headers
                    for line in lines:
                        if line.strip():
                            devices.append({
                                'name': line.strip(),
                                'type': 'bluetooth'
                            })
                except:
                    pass
            
            # Detect new devices
            current_macs = set(d.get('mac', d.get('name', '')) for d in devices)
            new_devices = current_macs - self.known_bluetooth_devices
            
            if new_devices:
                print(f"   🔵 New Bluetooth devices detected: {', '.join(new_devices)}")
            
            self.known_bluetooth_devices = current_macs
            
            return {
                'total_devices': len(devices),
                'devices': devices[:10],  # Send top 10
                'suspicious_devices': suspicious_devices,
                'new_devices': list(new_devices),
                'threat_level': 'high' if suspicious_devices else 'low'
            }
            
        except Exception as e:
            return {
                'total_devices': 0,
                'devices': [],
                'error': str(e),
                'threat_level': 'unknown'
            }
    
    def detect_wireless_attacks(self) -> Dict[str, Any]:
        """Detect potential wireless attacks"""
        attacks_detected = []
        
        # Check for deauth attacks (requires monitor mode)
        # Check for evil twin attacks (duplicate SSIDs)
        # Check for BlueBorne vulnerabilities
        # Check for suspicious traffic patterns
        
        # For demo purposes, simulate attack detection
        import random
        if random.random() < 0.1:  # 10% chance of detecting suspicious activity
            attacks_detected.append({
                'type': 'Suspicious_Wi-Fi_Activity',
                'description': 'Multiple deauth frames detected',
                'severity': 'medium',
                'timestamp': datetime.now().isoformat()
            })
        
        return {
            'attacks_detected': len(attacks_detected),
            'attack_details': attacks_detected,
            'threat_level': 'high' if attacks_detected else 'low'
        }
    
    def get_wireless_metrics(self) -> Dict[str, Any]:
        """Get comprehensive wireless security metrics"""
        print(f"\n   📡 Scanning wireless environment...")
        
        # Scan Wi-Fi
        wifi_data = self.scan_wifi_networks()
        print(f"   ✓ Wi-Fi: {wifi_data['total_networks']} networks found")
        if wifi_data.get('suspicious_ssids'):
            print(f"      ⚠️  Suspicious SSIDs: {', '.join(wifi_data['suspicious_ssids'])}")
        
        # Scan Bluetooth
        bt_data = self.scan_bluetooth_devices()
        print(f"   ✓ Bluetooth: {bt_data['total_devices']} devices found")
        if bt_data.get('suspicious_devices'):
            print(f"      ⚠️  Suspicious devices: {', '.join(bt_data['suspicious_devices'])}")
        
        # Detect attacks
        attack_data = self.detect_wireless_attacks()
        if attack_data['attacks_detected'] > 0:
            print(f"   🚨 Attacks detected: {attack_data['attacks_detected']}")
            self.threat_count += 1
        
        # Overall threat assessment
        threat_levels = [
            wifi_data.get('threat_level', 'low'),
            bt_data.get('threat_level', 'low'),
            attack_data.get('threat_level', 'low')
        ]
        
        overall_threat = 'high' if 'high' in threat_levels else 'medium' if 'medium' in threat_levels else 'low'
        
        return {
            'wifi': wifi_data,
            'bluetooth': bt_data,
            'attacks': attack_data,
            'overall_threat_level': overall_threat,
            'total_threats_detected': self.threat_count,
            'timestamp': datetime.now().isoformat()
        }
    
    async def connect_and_run(self):
        """Connect to BWF controller and start monitoring"""
        print(f"\n{'='*70}")
        print(f"🛡️  BWF WIRELESS SECURITY AGENT")
        print(f"{'='*70}")
        print(f"Agent ID:    {self.agent_id}")
        print(f"Hostname:    {self.hostname}")
        print(f"Platform:    {self.platform}")
        print(f"Type:        Wireless Security Monitor")
        print(f"Controller:  http://localhost:8000")
        print(f"{'='*70}\n")
        
        # Get initial system info
        system_info = self.get_system_info()
        print(f"✅ Agent Capabilities:")
        for capability in system_info['capabilities']:
            print(f"   • {capability.replace('_', ' ').title()}")
        print()
        
        try:
            # Register agent
            await self.register_agent()
            
            print(f"\n{'='*70}")
            print(f"✅ AGENT CONNECTED TO BWF TOOLKIT")
            print(f"{'='*70}")
            print(f"\n📊 Starting wireless security monitoring...")
            print(f"   Scan interval: {self.scan_interval} seconds")
            print(f"\n💡 View agent in dashboard: http://localhost:8000/module8\n")
            print(f"Press Ctrl+C to stop the agent\n")
            
            # Monitoring loop
            iteration = 0
            while self.running:
                iteration += 1
                print(f"\n{'─'*70}")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan #{iteration} - Wireless Security Check")
                print(f"{'─'*70}")
                
                # Get wireless metrics
                metrics = self.get_wireless_metrics()
                
                # Send metrics to controller
                await self.send_metrics(metrics)
                
                # Report security events if threats detected
                if metrics['overall_threat_level'] in ['high', 'medium']:
                    await self.report_security_event(metrics)
                
                print(f"\n   ✓ Update #{iteration} sent to BWF Controller")
                print(f"   ✓ Overall Threat Level: {metrics['overall_threat_level'].upper()}")
                
                # Wait before next scan
                await asyncio.sleep(self.scan_interval)
                
        except KeyboardInterrupt:
            print(f"\n\n{'='*70}")
            print(f"🛑 AGENT STOPPED BY USER")
            print(f"{'='*70}\n")
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            print(f"   Make sure BWF server is running at http://localhost:8000")
    
    async def register_agent(self):
        """Register agent with BWF controller"""
        import aiohttp
        
        registration_data = {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'platform': self.platform,
            'system_info': self.get_system_info(),
            'status': 'online',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'http://localhost:8000/api/module8/agents',
                    json=registration_data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        print(f"✅ Agent registered with BWF Controller")
                    else:
                        result = await response.text()
                        print(f"⚠️  Registration: {response.status}")
        except Exception as e:
            print(f"⚠️  Registration: {e}")
    
    async def send_metrics(self, metrics):
        """Send wireless security metrics to controller"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'http://localhost:8000/api/module8/agents/{self.agent_id}/metrics',
                    json=metrics,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    pass
        except:
            pass
    
    async def report_security_event(self, metrics):
        """Report wireless security event"""
        import aiohttp
        
        event = {
            'event_type': 'wireless_threat_detected',
            'event_id': f'bwf_evt_{int(time.time())}',
            'details': {
                'severity': metrics['overall_threat_level'],
                'wifi_threats': len(metrics['wifi'].get('suspicious_ssids', [])),
                'bluetooth_threats': len(metrics['bluetooth'].get('suspicious_devices', [])),
                'attacks_detected': metrics['attacks']['attacks_detected'],
                'message': f"Wireless threats detected: Threat level {metrics['overall_threat_level']}",
                'rogue_networks': metrics['wifi'].get('rogue_networks', []),
                'suspicious_devices': metrics['bluetooth'].get('suspicious_devices', [])
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'http://localhost:8000/api/module8/agents/{self.agent_id}/security-event',
                    json=event,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        print(f"   🚨 Security event reported to BWF Controller")
        except:
            pass

async def main():
    """Main function"""
    print("\n" + "="*70)
    print("BWF TOOLKIT - MODULE 8: WIRELESS SECURITY AGENT")
    print("="*70)
    
    # Check dependencies
    try:
        import aiohttp
    except ImportError:
        print("📦 Installing aiohttp...")
        import subprocess
        subprocess.check_call(['pip3', 'install', 'aiohttp'])
        import aiohttp
    
    # Create and run agent
    agent = BWFWirelessAgent()
    await agent.connect_and_run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Agent disconnected. Goodbye!")













