#!/usr/bin/env python3
"""
Real Attack Detection System
Analyzes actual network data from Modules 1, 2, and 3 to detect real attacks
"""

import logging
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealAttackDetector:
    """
    Real-time attack detection using actual network data
    """
    
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.attack_events = []
        self.device_profiles = {}
        self.attack_patterns = {
            'weak_security': [],
            'suspicious_devices': [],
            'network_anomalies': [],
            'bluetooth_attacks': []
        }
        
    def detect_real_attacks(self) -> List[Dict[str, Any]]:
        """Detect real attacks from actual network data"""
        attacks = []
        
        try:
            # Get real data from all modules
            wifi_data = self._get_wifi_data()
            bluetooth_data = self._get_bluetooth_data()
            packet_data = self._get_packet_data()
            
            # Analyze for real attacks
            attacks.extend(self._analyze_wifi_security_issues(wifi_data))
            attacks.extend(self._analyze_bluetooth_threats(bluetooth_data))
            attacks.extend(self._analyze_packet_anomalies(packet_data))
            attacks.extend(self._analyze_network_behavior(wifi_data, bluetooth_data))
            
            logger.info(f"Detected {len(attacks)} real attacks from network data")
            
        except Exception as e:
            logger.error(f"Error detecting real attacks: {e}")
        
        return attacks
    
    def _get_wifi_data(self) -> List[Dict[str, Any]]:
        """Get real WiFi data from Module 1"""
        try:
            response = requests.get(f"{self.base_url}/api/scan/results", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('wifi_networks', [])
        except Exception as e:
            logger.error(f"Error getting WiFi data: {e}")
        return []
    
    def _get_bluetooth_data(self) -> List[Dict[str, Any]]:
        """Get real Bluetooth data from Module 1"""
        try:
            response = requests.get(f"{self.base_url}/api/scan/results", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('bluetooth_devices', [])
        except Exception as e:
            logger.error(f"Error getting Bluetooth data: {e}")
        return []
    
    def _get_packet_data(self) -> List[Dict[str, Any]]:
        """Get real packet data from Module 3"""
        try:
            response = requests.get(f"{self.base_url}/api/live-capture/packets/suspicious", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('suspicious_packets', [])
        except Exception as e:
            logger.error(f"Error getting packet data: {e}")
        return []
    
    def _analyze_wifi_security_issues(self, wifi_networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze WiFi networks for security issues"""
        attacks = []
        
        for network in wifi_networks:
            # Check for weak security
            security = network.get('security', '').upper()
            rssi = network.get('rssi', -100)
            
            if 'WEP' in security or 'OPEN' in security or security == '':
                attack = {
                    'id': f"weak_security_{network.get('bssid', 'unknown')}",
                    'type': 'weak_security',
                    'severity': 'high',
                    'title': 'Weak WiFi Security Detected',
                    'message': f'Network "{network.get("ssid", "Unknown")}" has weak security: {security}',
                    'details': {
                        'ssid': network.get('ssid', 'Unknown'),
                        'bssid': network.get('bssid', 'Unknown'),
                        'security': security,
                        'rssi': rssi,
                        'channel': network.get('channel', 0),
                        'vendor': network.get('vendor', 'Unknown')
                    },
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Module 1 WiFi Scanner',
                    'recommendation': 'Avoid connecting to networks with weak security'
                }
                attacks.append(attack)
            
            # Check for weak signal with security issues
            if rssi > -70 and ('WEP' in security or 'OPEN' in security):
                attack = {
                    'id': f"weak_signal_security_{network.get('bssid', 'unknown')}",
                    'type': 'weak_signal_security',
                    'severity': 'medium',
                    'title': 'Weak Signal with Outdated Security',
                    'message': f'Network "{network.get("ssid", "Unknown")}" has weak signal and outdated security',
                    'details': {
                        'ssid': network.get('ssid', 'Unknown'),
                        'bssid': network.get('bssid', 'Unknown'),
                        'security': security,
                        'rssi': rssi,
                        'signal_strength': f"{rssi} dBm",
                        'channel': network.get('channel', 0)
                    },
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Module 1 WiFi Scanner',
                    'recommendation': 'Strong signal with weak security poses high risk'
                }
                attacks.append(attack)
        
        return attacks
    
    def _analyze_bluetooth_threats(self, bluetooth_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze Bluetooth devices for threats"""
        attacks = []
        
        for device in bluetooth_devices:
            name = device.get('name', '').lower()
            address = device.get('address', '')
            rssi = device.get('rssi', -100)
            
            # Check for suspicious device names
            suspicious_names = ['hack', 'attack', 'spy', 'surveillance', 'tracker', 'monitor']
            if any(suspicious in name for suspicious in suspicious_names):
                attack = {
                    'id': f"suspicious_bt_{address}",
                    'type': 'suspicious_bluetooth_device',
                    'severity': 'medium',
                    'title': 'Suspicious Bluetooth Device Detected',
                    'message': f'Bluetooth device with suspicious name: "{device.get("name", "Unknown")}"',
                    'details': {
                        'name': device.get('name', 'Unknown'),
                        'address': address,
                        'rssi': rssi,
                        'manufacturer': device.get('manufacturer', 'Unknown'),
                        'services': device.get('services', [])
                    },
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Module 1 Bluetooth Scanner',
                    'recommendation': 'Investigate this device - name suggests malicious intent'
                }
                attacks.append(attack)
            
            # Check for very strong Bluetooth signal (potential proximity attack)
            if rssi > -30:  # Very strong signal
                attack = {
                    'id': f"strong_bt_signal_{address}",
                    'type': 'strong_bluetooth_signal',
                    'severity': 'low',
                    'title': 'Very Strong Bluetooth Signal',
                    'message': f'Bluetooth device "{device.get("name", "Unknown")}" has very strong signal',
                    'details': {
                        'name': device.get('name', 'Unknown'),
                        'address': address,
                        'rssi': rssi,
                        'signal_strength': f"{rssi} dBm",
                        'manufacturer': device.get('manufacturer', 'Unknown')
                    },
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Module 1 Bluetooth Scanner',
                    'recommendation': 'Device is very close - verify it is legitimate'
                }
                attacks.append(attack)
        
        return attacks
    
    def _analyze_packet_anomalies(self, suspicious_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze packet data for anomalies"""
        attacks = []
        
        for packet in suspicious_packets:
            alert_type = packet.get('alert_type')
            if alert_type:
                attack = {
                    'id': f"packet_attack_{packet.get('src_ip', 'unknown')}_{int(time.time())}",
                    'type': 'packet_attack',
                    'severity': 'high' if alert_type in ['DOS_ATTACK', 'SYN_FLOOD'] else 'medium',
                    'title': f'{alert_type.replace("_", " ").title()} Detected',
                    'message': f'{alert_type} detected from {packet.get("src_ip", "unknown")}',
                    'details': {
                        'alert_type': alert_type,
                        'src_ip': packet.get('src_ip', 'unknown'),
                        'dst_ip': packet.get('dst_ip', 'unknown'),
                        'protocol': packet.get('protocol', 'unknown'),
                        'packet_count': packet.get('packet_count', 1),
                        'timestamp': packet.get('timestamp', datetime.now().isoformat())
                    },
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Module 3 Packet Capture',
                    'recommendation': f'Monitor traffic from {packet.get("src_ip", "unknown")} for {alert_type}'
                }
                attacks.append(attack)
        
        return attacks
    
    def _analyze_network_behavior(self, wifi_networks: List[Dict[str, Any]], bluetooth_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze overall network behavior for anomalies"""
        attacks = []
        
        # Check for too many open networks
        open_networks = [n for n in wifi_networks if 'OPEN' in n.get('security', '').upper() or n.get('security', '') == '']
        if len(open_networks) > 3:
            attack = {
                'id': f"too_many_open_networks_{int(time.time())}",
                'type': 'network_anomaly',
                'severity': 'medium',
                'title': 'Multiple Open WiFi Networks Detected',
                'message': f'Found {len(open_networks)} open WiFi networks in the area',
                'details': {
                    'open_networks_count': len(open_networks),
                    'total_networks': len(wifi_networks),
                    'open_networks': [{'ssid': n.get('ssid', 'Unknown'), 'bssid': n.get('bssid', 'Unknown')} for n in open_networks]
                },
                'timestamp': datetime.now().isoformat(),
                'source': 'Module 1 Network Analysis',
                'recommendation': 'Multiple open networks may indicate security issues in the area'
            }
            attacks.append(attack)
        
        # Check for unusual number of Bluetooth devices
        if len(bluetooth_devices) > 20:
            attack = {
                'id': f"too_many_bt_devices_{int(time.time())}",
                'type': 'bluetooth_anomaly',
                'severity': 'low',
                'title': 'High Number of Bluetooth Devices',
                'message': f'Detected {len(bluetooth_devices)} Bluetooth devices in the area',
                'details': {
                    'bluetooth_devices_count': len(bluetooth_devices),
                    'named_devices': len([d for d in bluetooth_devices if d.get('name', '').strip()]),
                    'unnamed_devices': len([d for d in bluetooth_devices if not d.get('name', '').strip()])
                },
                'timestamp': datetime.now().isoformat(),
                'source': 'Module 1 Bluetooth Analysis',
                'recommendation': 'High number of Bluetooth devices may indicate crowded environment'
            }
            attacks.append(attack)
        
        return attacks
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get statistics about detected attacks"""
        attacks = self.detect_real_attacks()
        
        stats = {
            'total_attacks': len(attacks),
            'by_severity': {
                'high': len([a for a in attacks if a.get('severity') == 'high']),
                'medium': len([a for a in attacks if a.get('severity') == 'medium']),
                'low': len([a for a in attacks if a.get('severity') == 'low'])
            },
            'by_type': {},
            'by_source': {}
        }
        
        # Count by type
        for attack in attacks:
            attack_type = attack.get('type', 'unknown')
            stats['by_type'][attack_type] = stats['by_type'].get(attack_type, 0) + 1
        
        # Count by source
        for attack in attacks:
            source = attack.get('source', 'unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
        
        return stats

# Global instance
_real_attack_detector = None

def get_real_attack_detector() -> RealAttackDetector:
    """Get or create global real attack detector instance"""
    global _real_attack_detector
    if _real_attack_detector is None:
        _real_attack_detector = RealAttackDetector()
    return _real_attack_detector

if __name__ == "__main__":
    # Test the real attack detector
    detector = get_real_attack_detector()
    attacks = detector.detect_real_attacks()
    
    print(f"Detected {len(attacks)} real attacks:")
    for attack in attacks:
        print(f"  - {attack['title']}: {attack['message']} (Severity: {attack['severity']})")
    
    stats = detector.get_attack_statistics()
    print(f"\nAttack Statistics:")
    print(f"  Total: {stats['total_attacks']}")
    print(f"  High: {stats['by_severity']['high']}")
    print(f"  Medium: {stats['by_severity']['medium']}")
    print(f"  Low: {stats['by_severity']['low']}")


