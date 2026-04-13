#!/usr/bin/env python3
"""
Add WiFi attack to the detection system
"""

import json
import os
from datetime import datetime

def add_wifi_attack(attack_type, details):
    """Add a WiFi attack to the detection system"""
    backend_dir = "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
    attacks_file = os.path.join(backend_dir, "realtime_bluetooth_attacks.json")
    
    try:
        # Load existing attacks
        if os.path.exists(attacks_file):
            with open(attacks_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"timestamp": "", "total_attacks": 0, "attacks": []}
        
        # Create new attack
        attack = {
            'id': f"wifi_{attack_type}_{int(datetime.now().timestamp())}",
            'type': f'wifi_{attack_type}',
            'severity': details.get('severity', 'medium'),
            'title': details.get('title', f'WiFi {attack_type.title()} Attack Detected'),
            'message': details.get('message', f'WiFi {attack_type} attack detected'),
            'details': details.get('details', {}),
            'timestamp': datetime.now().isoformat(),
            'source': 'WiFi Attack Script'
        }
        
        # Add attack
        data['attacks'].append(attack)
        data['total_attacks'] = len(data['attacks'])
        data['timestamp'] = datetime.now().isoformat()
        
        # Save back to file
        with open(attacks_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Added WiFi {attack_type} attack to detection system")
        return True
        
    except Exception as e:
        print(f"❌ Error adding WiFi attack: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 add_wifi_attack.py <attack_type> [details]")
        sys.exit(1)
    
    attack_type = sys.argv[1]
    
    # Default details for different attack types
    attack_details = {
        'packet_flood': {
            'severity': 'high',
            'title': '🚀 WiFi Packet Flood Attack Detected',
            'message': 'High volume packet transmission detected - potential DoS attack',
            'details': {
                'attack_method': 'Packet Flood',
                'packets_sent': 900,
                'detection_source': 'Packet Monitor'
            }
        },
        'dos_flood': {
            'severity': 'high',
            'title': '🌊 WiFi HTTP DoS Attack Detected',
            'message': 'High volume HTTP requests detected - potential DoS attack',
            'details': {
                'attack_method': 'HTTP DoS Flood',
                'requests_sent': 200,
                'detection_source': 'HTTP Monitor'
            }
        },
        'port_scan': {
            'severity': 'medium',
            'title': '🔍 WiFi Port Scan Attack Detected',
            'message': 'Multiple port connection attempts detected - potential reconnaissance attack',
            'details': {
                'attack_method': 'Port Scan',
                'ports_scanned': 18,
                'detection_source': 'Connection Monitor'
            }
        }
    }
    
    details = attack_details.get(attack_type, {
        'severity': 'medium',
        'title': f'🌐 WiFi {attack_type.title()} Attack Detected',
        'message': f'WiFi {attack_type} attack detected',
        'details': {
            'attack_method': attack_type.title(),
            'detection_source': 'WiFi Monitor'
        }
    })
    
    add_wifi_attack(attack_type, details)











"""
Add WiFi attack to the detection system
"""

import json
import os
from datetime import datetime

def add_wifi_attack(attack_type, details):
    """Add a WiFi attack to the detection system"""
    backend_dir = "/home/floki/Downloads/OWN R/Complete Project (2)/Complete Project/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend"
    attacks_file = os.path.join(backend_dir, "realtime_bluetooth_attacks.json")
    
    try:
        # Load existing attacks
        if os.path.exists(attacks_file):
            with open(attacks_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"timestamp": "", "total_attacks": 0, "attacks": []}
        
        # Create new attack
        attack = {
            'id': f"wifi_{attack_type}_{int(datetime.now().timestamp())}",
            'type': f'wifi_{attack_type}',
            'severity': details.get('severity', 'medium'),
            'title': details.get('title', f'WiFi {attack_type.title()} Attack Detected'),
            'message': details.get('message', f'WiFi {attack_type} attack detected'),
            'details': details.get('details', {}),
            'timestamp': datetime.now().isoformat(),
            'source': 'WiFi Attack Script'
        }
        
        # Add attack
        data['attacks'].append(attack)
        data['total_attacks'] = len(data['attacks'])
        data['timestamp'] = datetime.now().isoformat()
        
        # Save back to file
        with open(attacks_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Added WiFi {attack_type} attack to detection system")
        return True
        
    except Exception as e:
        print(f"❌ Error adding WiFi attack: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 add_wifi_attack.py <attack_type> [details]")
        sys.exit(1)
    
    attack_type = sys.argv[1]
    
    # Default details for different attack types
    attack_details = {
        'packet_flood': {
            'severity': 'high',
            'title': '🚀 WiFi Packet Flood Attack Detected',
            'message': 'High volume packet transmission detected - potential DoS attack',
            'details': {
                'attack_method': 'Packet Flood',
                'packets_sent': 900,
                'detection_source': 'Packet Monitor'
            }
        },
        'dos_flood': {
            'severity': 'high',
            'title': '🌊 WiFi HTTP DoS Attack Detected',
            'message': 'High volume HTTP requests detected - potential DoS attack',
            'details': {
                'attack_method': 'HTTP DoS Flood',
                'requests_sent': 200,
                'detection_source': 'HTTP Monitor'
            }
        },
        'port_scan': {
            'severity': 'medium',
            'title': '🔍 WiFi Port Scan Attack Detected',
            'message': 'Multiple port connection attempts detected - potential reconnaissance attack',
            'details': {
                'attack_method': 'Port Scan',
                'ports_scanned': 18,
                'detection_source': 'Connection Monitor'
            }
        }
    }
    
    details = attack_details.get(attack_type, {
        'severity': 'medium',
        'title': f'🌐 WiFi {attack_type.title()} Attack Detected',
        'message': f'WiFi {attack_type} attack detected',
        'details': {
            'attack_method': attack_type.title(),
            'detection_source': 'WiFi Monitor'
        }
    })
    
    add_wifi_attack(attack_type, details)













