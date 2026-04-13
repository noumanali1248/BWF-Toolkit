#!/usr/bin/env python3
"""
Enhanced Comprehensive Wi-Fi Scanner
Uses Npcap, Scapy, PyWiFi, and PyShark for advanced Wi-Fi scanning and packet capture
"""

import subprocess
import json
import csv
import time
import logging
import re
import threading
import queue
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import os
import sys

# Try to import optional dependencies
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp
    from scapy.layers.eapol import EAPOL
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

try:
    import pywifi
    from pywifi import const
    PYWiFi_AVAILABLE = True
except ImportError:
    PYWiFi_AVAILABLE = False
    print("Warning: PyWiFi not available. Install with: pip install pywifi")

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("Warning: PyShark not available. Install with: pip install pyshark")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedComprehensiveWiFiScanner:
    def __init__(self):
        self.wifi_networks = {}
        self.scanning = False
        self.start_time = None
        self.packet_queue = queue.Queue()
        self.captured_packets = []
        self.scan_thread = None
        self.packet_thread = None
        
        # Device classification patterns
        self.wifi_patterns = {
            'router': ['router', 'ap', 'access point', 'gateway', 'netgear', 'linksys', 'tp-link', 'asus', 'd-link', 'belkin'],
            'mobile': ['iphone', 'android', 'hotspot', 'tethering', 'samsung', 'huawei', 'xiaomi', 'oneplus', 'pixel'],
            'laptop': ['macbook', 'thinkpad', 'dell', 'hp', 'asus', 'acer', 'lenovo', 'surface'],
            'iot': ['smart', 'home', 'hub', 'bridge', 'camera', 'alexa', 'echo', 'google', 'nest', 'ring', 'philips'],
            'enterprise': ['eduroam', 'corporate', 'office', 'company', 'wifi', 'guest'],
            'public': ['guest', 'public', 'free', 'wifi', 'open', 'hotspot']
        }
        
        # MAC address vendor lookup (simplified)
        self.mac_vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:16:3E': 'Xen',
            '52:54:00': 'QEMU',
            'AC:DE:48': 'Private',
            '02:00:4C:4F:4F:50': 'Local',
            '00:1B:44': 'Apple',
            '00:23:12': 'Apple',
            '00:25:00': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:26:BB': 'Apple',
            '00:50:E2': 'Apple',
            '00:56:CD': 'Apple',
            '00:60:90': 'Apple',
            '00:90:27': 'Apple',
            '00:A0:40': 'Apple',
            '00:C0:4F': 'Apple',
            '00:D0:41': 'Apple',
            '00:E0:18': 'Apple',
            '08:00:07': 'Apple',
            '08:74:02': 'Apple',
            '0C:74:C2': 'Apple',
            '10:40:F3': 'Apple',
            '14:10:9F': 'Apple',
            '14:20:5E': 'Apple',
            '14:7D:DA': 'Apple',
            '14:99:E2': 'Apple',
            '18:65:90': 'Apple',
            '18:E7:F4': 'Apple',
            '1C:1B:0D': 'Apple',
            '1C:36:BB': 'Apple',
            '1C:AB:A7': 'Apple',
            '20:78:F0': 'Apple',
            '20:C9:D0': 'Apple',
            '24:A0:74': 'Apple',
            '24:AB:81': 'Apple',
            '24:E3:14': 'Apple',
            '28:37:37': 'Apple',
            '28:6A:B8': 'Apple',
            '28:CF:DA': 'Apple',
            '28:CF:E9': 'Apple',
            '28:E0:2C': 'Apple',
            '28:E7:CF': 'Apple',
            '2C:1F:23': 'Apple',
            '2C:33:7A': 'Apple',
            '2C:36:A0': 'Apple',
            '2C:41:38': 'Apple',
            '2C:44:FD': 'Apple',
            '2C:54:91': 'Apple',
            '2C:56:DC': 'Apple',
            '2C:5A:0F': 'Apple',
            '2C:5A:13': 'Apple',
            '2C:5D:93': 'Apple',
            '2C:5F:CF': 'Apple',
            '2C:61:F6': 'Apple',
            '2C:69:BA': 'Apple',
            '2C:6F:51': 'Apple',
            '2C:76:8A': 'Apple',
            '2C:7B:84': 'Apple',
            '2C:8A:72': 'Apple',
            '2C:AB:00': 'Apple',
            '2C:AB:25': 'Apple',
            '2C:B4:3A': 'Apple',
            '2C:BE:08': 'Apple',
            '2C:BE:EB': 'Apple',
            '2C:C2:60': 'Apple',
            '2C:D0:5A': 'Apple',
            '2C:D2:E7': 'Apple',
            '2C:D4:C2': 'Apple',
            '2C:D5:47': 'Apple',
            '2C:D5:48': 'Apple',
            '2C:D5:49': 'Apple',
            '2C:D5:4A': 'Apple',
            '2C:D5:4B': 'Apple',
            '2C:D5:4C': 'Apple',
            '2C:D5:4D': 'Apple',
            '2C:D5:4E': 'Apple',
            '2C:D5:4F': 'Apple',
            '2C:D5:50': 'Apple',
            '2C:D5:51': 'Apple',
            '2C:D5:52': 'Apple',
            '2C:D5:53': 'Apple',
            '2C:D5:54': 'Apple',
            '2C:D5:55': 'Apple',
            '2C:D5:56': 'Apple',
            '2C:D5:57': 'Apple',
            '2C:D5:58': 'Apple',
            '2C:D5:59': 'Apple',
            '2C:D5:5A': 'Apple',
            '2C:D5:5B': 'Apple',
            '2C:D5:5C': 'Apple',
            '2C:D5:5D': 'Apple',
            '2C:D5:5E': 'Apple',
            '2C:D5:5F': 'Apple',
            '2C:D5:60': 'Apple',
            '2C:D5:61': 'Apple',
            '2C:D5:62': 'Apple',
            '2C:D5:63': 'Apple',
            '2C:D5:64': 'Apple',
            '2C:D5:65': 'Apple',
            '2C:D5:66': 'Apple',
            '2C:D5:67': 'Apple',
            '2C:D5:68': 'Apple',
            '2C:D5:69': 'Apple',
            '2C:D5:6A': 'Apple',
            '2C:D5:6B': 'Apple',
            '2C:D5:6C': 'Apple',
            '2C:D5:6D': 'Apple',
            '2C:D5:6E': 'Apple',
            '2C:D5:6F': 'Apple',
            '2C:D5:70': 'Apple',
            '2C:D5:71': 'Apple',
            '2C:D5:72': 'Apple',
            '2C:D5:73': 'Apple',
            '2C:D5:74': 'Apple',
            '2C:D5:75': 'Apple',
            '2C:D5:76': 'Apple',
            '2C:D5:77': 'Apple',
            '2C:D5:78': 'Apple',
            '2C:D5:79': 'Apple',
            '2C:D5:7A': 'Apple',
            '2C:D5:7B': 'Apple',
            '2C:D5:7C': 'Apple',
            '2C:D5:7D': 'Apple',
            '2C:D5:7E': 'Apple',
            '2C:D5:7F': 'Apple',
            '2C:D5:80': 'Apple',
            '2C:D5:81': 'Apple',
            '2C:D5:82': 'Apple',
            '2C:D5:83': 'Apple',
            '2C:D5:84': 'Apple',
            '2C:D5:85': 'Apple',
            '2C:D5:86': 'Apple',
            '2C:D5:87': 'Apple',
            '2C:D5:88': 'Apple',
            '2C:D5:89': 'Apple',
            '2C:D5:8A': 'Apple',
            '2C:D5:8B': 'Apple',
            '2C:D5:8C': 'Apple',
            '2C:D5:8D': 'Apple',
            '2C:D5:8E': 'Apple',
            '2C:D5:8F': 'Apple',
            '2C:D5:90': 'Apple',
            '2C:D5:91': 'Apple',
            '2C:D5:92': 'Apple',
            '2C:D5:93': 'Apple',
            '2C:D5:94': 'Apple',
            '2C:D5:95': 'Apple',
            '2C:D5:96': 'Apple',
            '2C:D5:97': 'Apple',
            '2C:D5:98': 'Apple',
            '2C:D5:99': 'Apple',
            '2C:D5:9A': 'Apple',
            '2C:D5:9B': 'Apple',
            '2C:D5:9C': 'Apple',
            '2C:D5:9D': 'Apple',
            '2C:D5:9E': 'Apple',
            '2C:D5:9F': 'Apple',
            '2C:D5:A0': 'Apple',
            '2C:D5:A1': 'Apple',
            '2C:D5:A2': 'Apple',
            '2C:D5:A3': 'Apple',
            '2C:D5:A4': 'Apple',
            '2C:D5:A5': 'Apple',
            '2C:D5:A6': 'Apple',
            '2C:D5:A7': 'Apple',
            '2C:D5:A8': 'Apple',
            '2C:D5:A9': 'Apple',
            '2C:D5:AA': 'Apple',
            '2C:D5:AB': 'Apple',
            '2C:D5:AC': 'Apple',
            '2C:D5:AD': 'Apple',
            '2C:D5:AE': 'Apple',
            '2C:D5:AF': 'Apple',
            '2C:D5:B0': 'Apple',
            '2C:D5:B1': 'Apple',
            '2C:D5:B2': 'Apple',
            '2C:D5:B3': 'Apple',
            '2C:D5:B4': 'Apple',
            '2C:D5:B5': 'Apple',
            '2C:D5:B6': 'Apple',
            '2C:D5:B7': 'Apple',
            '2C:D5:B8': 'Apple',
            '2C:D5:B9': 'Apple',
            '2C:D5:BA': 'Apple',
            '2C:D5:BB': 'Apple',
            '2C:D5:BC': 'Apple',
            '2C:D5:BD': 'Apple',
            '2C:D5:BE': 'Apple',
            '2C:D5:BF': 'Apple',
            '2C:D5:C0': 'Apple',
            '2C:D5:C1': 'Apple',
            '2C:D5:C2': 'Apple',
            '2C:D5:C3': 'Apple',
            '2C:D5:C4': 'Apple',
            '2C:D5:C5': 'Apple',
            '2C:D5:C6': 'Apple',
            '2C:D5:C7': 'Apple',
            '2C:D5:C8': 'Apple',
            '2C:D5:C9': 'Apple',
            '2C:D5:CA': 'Apple',
            '2C:D5:CB': 'Apple',
            '2C:D5:CC': 'Apple',
            '2C:D5:CD': 'Apple',
            '2C:D5:CE': 'Apple',
            '2C:D5:CF': 'Apple',
            '2C:D5:D0': 'Apple',
            '2C:D5:D1': 'Apple',
            '2C:D5:D2': 'Apple',
            '2C:D5:D3': 'Apple',
            '2C:D5:D4': 'Apple',
            '2C:D5:D5': 'Apple',
            '2C:D5:D6': 'Apple',
            '2C:D5:D7': 'Apple',
            '2C:D5:D8': 'Apple',
            '2C:D5:D9': 'Apple',
            '2C:D5:DA': 'Apple',
            '2C:D5:DB': 'Apple',
            '2C:D5:DC': 'Apple',
            '2C:D5:DD': 'Apple',
            '2C:D5:DE': 'Apple',
            '2C:D5:DF': 'Apple',
            '2C:D5:E0': 'Apple',
            '2C:D5:E1': 'Apple',
            '2C:D5:E2': 'Apple',
            '2C:D5:E3': 'Apple',
            '2C:D5:E4': 'Apple',
            '2C:D5:E5': 'Apple',
            '2C:D5:E6': 'Apple',
            '2C:D5:E7': 'Apple',
            '2C:D5:E8': 'Apple',
            '2C:D5:E9': 'Apple',
            '2C:D5:EA': 'Apple',
            '2C:D5:EB': 'Apple',
            '2C:D5:EC': 'Apple',
            '2C:D5:ED': 'Apple',
            '2C:D5:EE': 'Apple',
            '2C:D5:EF': 'Apple',
            '2C:D5:F0': 'Apple',
            '2C:D5:F1': 'Apple',
            '2C:D5:F2': 'Apple',
            '2C:D5:F3': 'Apple',
            '2C:D5:F4': 'Apple',
            '2C:D5:F5': 'Apple',
            '2C:D5:F6': 'Apple',
            '2C:D5:F7': 'Apple',
            '2C:D5:F8': 'Apple',
            '2C:D5:F9': 'Apple',
            '2C:D5:FA': 'Apple',
            '2C:D5:FB': 'Apple',
            '2C:D5:FC': 'Apple',
            '2C:D5:FD': 'Apple',
            '2C:D5:FE': 'Apple',
            '2C:D5:FF': 'Apple'
        }
        
        # Initialize PyWiFi if available
        if PYWiFi_AVAILABLE:
            try:
                self.wifi = pywifi.PyWiFi()
                self.iface = self.wifi.interfaces()[0] if self.wifi.interfaces() else None
            except Exception as e:
                logger.warning(f"PyWiFi initialization failed: {e}")
                self.iface = None
        else:
            self.iface = None

    def classify_wifi_network(self, ssid: str, bssid: str) -> str:
        """Classify Wi-Fi network based on SSID and BSSID"""
        if not ssid:
            return "Hidden Network"
        
        ssid_lower = ssid.lower()
        
        for category, patterns in self.wifi_patterns.items():
            for pattern in patterns:
                if pattern in ssid_lower:
                    return category.title()
        
        # Check for common network types
        if 'eduroam' in ssid_lower:
            return "Enterprise"
        elif 'guest' in ssid_lower or 'public' in ssid_lower:
            return "Public"
        elif '5g' in ssid_lower or '5ghz' in ssid_lower:
            return "5GHz Network"
        elif '2.4' in ssid_lower or '2g' in ssid_lower:
            return "2.4GHz Network"
        else:
            return "Standard Network"
    
    def get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor information from MAC address"""
        if not mac_address or mac_address == 'Unknown':
            return 'Unknown'
        
        # Clean MAC address
        mac = mac_address.replace(':', '').replace('-', '').upper()
        if len(mac) >= 6:
            oui = mac[:6]
            # Convert to standard format
            oui_formatted = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"
            
            # Check our local database first
            if oui_formatted in self.mac_vendors:
                return self.mac_vendors[oui_formatted]
            
            # Try online lookup (simplified)
            try:
                import requests
                response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                pass
        
        return 'Unknown'

    def get_wifi_interfaces(self) -> List[str]:
        """Get available Wi-Fi interfaces"""
        interfaces = []
        
        # Try PyWiFi first
        if PYWiFi_AVAILABLE and self.iface:
            try:
                interfaces.append(self.iface.name())
            except:
                pass
        
        # Try Scapy
        if SCAPY_AVAILABLE:
            try:
                scapy_interfaces = scapy.get_if_list()
                for iface in scapy_interfaces:
                    if 'wlan' in iface.lower() or 'wifi' in iface.lower() or 'wireless' in iface.lower():
                        interfaces.append(iface)
            except:
                pass
        
        # Try netsh for Windows
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Name' in line and ':' in line:
                        interface_name = line.split(':')[1].strip()
                        if interface_name and interface_name not in interfaces:
                            interfaces.append(interface_name)
        except:
            pass
        
        # Try iw (Linux)
        if sys.platform.startswith('linux'):
            try:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    current = None
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line.startswith('Interface '):
                            name = line.split(' ', 1)[1].strip()
                            # Filter out p2p-dev interfaces and use main interface
                            if name and not name.startswith('p2p-dev-') and name not in interfaces:
                                interfaces.append(name)
            except Exception:
                pass
        
        return interfaces

    def scan_with_nmcli(self) -> List[Dict]:
        """Scan Wi-Fi networks using nmcli on Linux"""
        networks = []
        if not sys.platform.startswith('linux'):
            return networks
        try:
            # -t terse, fields for consistent parsing
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,CHAN,SECURITY,FREQ', 'dev', 'wifi', 'list'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                return networks
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                # Use regex to split by colon only if NOT preceded by a backslash
                # This handles escaped colons like '\:' which nmcli uses
                parts = re.split(r'(?<!\\):', line)
                
                # nmcli fields: SSID,BSSID,SIGNAL,CHAN,SECURITY,FREQ
                if len(parts) < 6:
                    continue
                
                # Unescape all parts (replace \: with :)
                parts = [p.replace(r'\:', ':').replace(r'\\', '\\') for p in parts]
                
                # Extract fields (order matters matching the nmcli command)
                ssid = parts[0].strip() or 'Hidden Network'
                bssid = parts[1].strip()
                signal = parts[2]
                chan = parts[3]
                security = parts[4]
                freq = parts[5]
                try:
                    signal_percent = int(signal)
                except Exception:
                    signal_percent = 0
                try:
                    channel = int(chan)
                except Exception:
                    channel = 0
                try:
                    frequency = int(freq)
                except Exception:
                    frequency = 0
                rssi = signal_percent - 100
                network_info = {
                    'ssid': ssid,
                    'bssid': bssid or 'Unknown',
                    'mac_address': bssid or 'Unknown',
                    'signal_strength': max(0, min(100, signal_percent)),
                    'rssi': rssi,
                    'channel': channel,
                    'frequency': frequency,
                    'security': security or 'Unknown',
                    'encryption': security or 'Unknown',
                    'auth': 'Open' if (security or '').lower() in ['open', 'none'] else 'WPA/WPA2',
                    'wps': 'Unknown',
                    'type': 'Infrastructure',
                    'vendor': self.get_vendor_from_mac(bssid) if bssid else 'Unknown',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'network_type': self.classify_wifi_network(ssid, bssid or 'Unknown'),
                    'method': 'nmcli'
                }
                networks.append(network_info)
        except Exception as e:
            logger.error(f"nmcli scan failed: {e}")
        return networks

    def scan_with_iwlist(self, interfaces: List[str]) -> List[Dict]:
        """Scan Wi-Fi networks using iwlist on Linux as a fallback"""
        networks = []
        if not sys.platform.startswith('linux'):
            return networks
        try:
            for iface in interfaces or []:
                try:
                    result = subprocess.run(['iwlist', iface, 'scan'], capture_output=True, text=True, timeout=20)
                except FileNotFoundError:
                    break
                if result.returncode != 0:
                    continue
                cell = {}
                for raw in result.stdout.split('\n'):
                    line = raw.strip()
                    if line.startswith('Cell '):
                        if cell:
                            networks.append(cell)
                        cell = {
                            'ssid': 'Hidden Network',
                            'bssid': 'Unknown',
                            'mac_address': 'Unknown',
                            'signal_strength': 0,
                            'rssi': -100,
                            'channel': 0,
                            'frequency': 0,
                            'security': 'Unknown',
                            'encryption': 'Unknown',
                            'auth': 'Unknown',
                            'type': 'Infrastructure',
                            'vendor': 'Unknown',
                            'first_seen': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat(),
                            'network_type': 'Standard Network',
                            'method': 'iwlist'
                        }
                    elif 'ESSID:' in line:
                        ssid_val = line.split('ESSID:')[1].strip().strip('"')
                        cell['ssid'] = ssid_val or 'Hidden Network'
                        cell['network_type'] = self.classify_wifi_network(cell['ssid'], cell.get('bssid', 'Unknown'))
                    elif line.startswith('Quality=') and 'Signal level=' in line:
                        try:
                            # Example: Quality=70/70  Signal level=-39 dBm
                            sig = line.split('Signal level=')[1].split(' ')[0]
                            rssi = int(sig)
                            cell['rssi'] = rssi
                            cell['signal_strength'] = max(0, min(100, 100 + rssi))
                        except Exception:
                            pass
                    elif line.startswith('Frequency:'):
                        try:
                            freq_part = line.split('Frequency:')[1]
                            mhz = freq_part.split(' ')[0]
                            frequency = float(mhz) * 1000 if 'GHz' in freq_part else float(mhz)
                            cell['frequency'] = int(frequency)
                        except Exception:
                            pass
                    elif 'Channel ' in line or line.startswith('Channel:'):
                        try:
                            ch = re.findall(r'Channel\s*:?\s*(\d+)', line)
                            if ch:
                                cell['channel'] = int(ch[0])
                        except Exception:
                            pass
                    elif 'Address:' in line:
                        bssid = line.split('Address:')[1].strip()
                        cell['bssid'] = bssid
                        cell['mac_address'] = bssid
                        cell['vendor'] = self.get_vendor_from_mac(bssid)
                    elif 'Encryption key:' in line:
                        enc = line.split('Encryption key:')[1].strip()
                        if enc.lower() == 'off':
                            cell['security'] = 'Open'
                            cell['encryption'] = 'None'
                            cell['auth'] = 'Open'
                        else:
                            cell['security'] = 'WEP/WPA/WPA2'
                            cell['encryption'] = 'Unknown'
                            cell['auth'] = 'WPA/WPA2'
                if cell:
                    networks.append(cell)
        except Exception as e:
            logger.error(f"iwlist scan failed: {e}")
        return networks

    def scan_with_pywifi(self) -> List[Dict]:
        """Scan Wi-Fi networks using PyWiFi"""
        networks = []
        
        if not PYWiFi_AVAILABLE or not self.iface:
            return networks
        
        try:
            self.iface.scan()
            time.sleep(5)  # Wait for scan to complete
            
            scan_results = self.iface.scan_results()
            
            for network in scan_results:
                try:
                    ssid = network.ssid if network.ssid else "Hidden Network"
                    bssid = network.bssid if network.bssid else "Unknown"
                    
                    # Get signal strength
                    signal_strength = 0
                    if hasattr(network, 'signal'):
                        signal_strength = network.signal
                    elif hasattr(network, 'rssi'):
                        signal_strength = network.rssi
                    
                    # Convert signal to percentage
                    signal_percent = max(0, min(100, 100 + signal_strength))
                    
                    # Get security information
                    security = "Open"
                    if hasattr(network, 'akm') and network.akm:
                        if const.AKM_TYPE_WPA2PSK in network.akm:
                            security = "WPA2-Personal"
                        elif const.AKM_TYPE_WPAPSK in network.akm:
                            security = "WPA-Personal"
                        elif const.AKM_TYPE_WPA2 in network.akm:
                            security = "WPA2-Enterprise"
                        elif const.AKM_TYPE_WPA in network.akm:
                            security = "WPA-Enterprise"
                    
                    # Get frequency
                    frequency = 0
                    if hasattr(network, 'freq'):
                        frequency = network.freq
                    
                    # Calculate channel
                    channel = 0
                    if frequency:
                        if 2412 <= frequency <= 2484:
                            channel = (frequency - 2412) // 5 + 1
                        elif 5170 <= frequency <= 5825:
                            channel = (frequency - 5170) // 5 + 34
                    
                    network_info = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'mac_address': bssid,
                        'signal_strength': signal_percent,
                        'rssi': signal_strength,
                        'channel': channel,
                        'frequency': frequency,
                        'security': security,
                        'encryption': security,
                        'auth': 'Open' if security == 'Open' else 'WPA/WPA2',
                        'wps': 'Unknown',
                        'type': 'Infrastructure',
                        'vendor': 'Unknown',
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'network_type': self.classify_wifi_network(ssid, bssid),
                        'method': 'PyWiFi'
                    }
                    
                    networks.append(network_info)
                    logger.info(f"WiFi: {ssid} ({bssid}) - {signal_percent}%")
                    
                except Exception as e:
                    logger.warning(f"Error processing PyWiFi network: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"PyWiFi scan failed: {e}")
        
        return networks

    def scan_with_scapy(self, interface: str, timeout: int = 10) -> List[Dict]:
        """Scan Wi-Fi networks using Scapy"""
        networks = []
        
        if not SCAPY_AVAILABLE:
            return networks
        
        try:
            logger.info(f"Scanning with Scapy on interface: {interface} (timeout: {timeout}s)")
            
            # Sniff for beacon frames
            def packet_handler(packet):
                try:
                    if packet.haslayer(Dot11Beacon):
                        beacon = packet[Dot11Beacon]
                        
                        # Get SSID
                        ssid = beacon.info.decode('utf-8') if beacon.info else "Hidden Network"
                        
                        # Get BSSID
                        bssid = packet[Dot11].addr3
                        
                        # Get signal strength (RSSI)
                        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
                        signal_percent = max(0, min(100, 100 + rssi))
                        
                        # Get channel
                        channel = 0
                        if hasattr(beacon, 'cap'):
                            cap = beacon.cap
                            if hasattr(cap, 'channel'):
                                channel = cap.channel
                        
                        # Get frequency
                        frequency = 0
                        if channel:
                            if 1 <= channel <= 14:
                                frequency = 2412 + (channel - 1) * 5
                            elif 36 <= channel <= 165:
                                frequency = 5000 + (channel - 36) * 5
                        
                        # Get security information
                        security = "Open"
                        if hasattr(beacon, 'cap'):
                            cap = beacon.cap
                            if hasattr(cap, 'privacy') and cap.privacy:
                                if hasattr(cap, 'wpa') and cap.wpa:
                                    security = "WPA"
                                elif hasattr(cap, 'wpa2') and cap.wpa2:
                                    security = "WPA2"
                                else:
                                    security = "WEP"
                        
                        network_info = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'mac_address': bssid,
                            'signal_strength': signal_percent,
                            'rssi': rssi,
                            'channel': channel,
                            'frequency': frequency,
                            'security': security,
                            'encryption': security,
                            'auth': 'Open' if security == 'Open' else 'WPA/WPA2',
                            'wps': 'Unknown',
                            'type': 'Infrastructure',
                            'vendor': 'Unknown',
                            'first_seen': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat(),
                            'network_type': self.classify_wifi_network(ssid, bssid),
                            'method': 'Scapy'
                        }
                        
                        networks.append(network_info)
                        logger.info(f"Scapy: {ssid} ({bssid}) - {signal_percent}%")
                
                except Exception as e:
                    logger.warning(f"Error processing Scapy packet: {e}")
            
            # Sniff for specified duration
            scapy.sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)
            
        except Exception as e:
            logger.error(f"Scapy scan failed: {e}")
        
        return networks

    def scan_with_pyshark(self, interface: str, timeout: int = 10) -> List[Dict]:
        """Scan Wi-Fi networks using PyShark"""
        networks = []
        
        if not PYSHARK_AVAILABLE:
            return networks
        
        try:
            logger.info(f"Scanning with PyShark on interface: {interface} (timeout: {timeout}s)")
            
            # Create capture
            capture = pyshark.LiveCapture(interface=interface, bpf_filter='wlan type mgt subtype beacon')
            
            # Capture for specified duration
            start_time = time.time()
            for packet in capture.sniff_continuously():
                if time.time() - start_time > timeout:
                    break
                
                try:
                    if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'ssid'):
                        ssid = packet.wlan.ssid if packet.wlan.ssid else "Hidden Network"
                        bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else "Unknown"
                        
                        # Get signal strength
                        signal_strength = 0
                        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'signal_dbm'):
                            rssi = int(packet.wlan_radio.signal_dbm)
                            signal_strength = max(0, min(100, 100 + rssi))
                        
                        # Get channel
                        channel = 0
                        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'channel'):
                            channel = int(packet.wlan_radio.channel)
                        
                        # Get frequency
                        frequency = 0
                        if hasattr(packet, 'wlan_radio') and hasattr(packet.wlan_radio, 'frequency'):
                            frequency = int(packet.wlan_radio.frequency)
                        
                        # Get security information
                        security = "Open"
                        if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'capabilities'):
                            caps = packet.wlan.capabilities
                            if 'privacy' in caps:
                                security = "WEP"
                            if 'wpa' in caps:
                                security = "WPA"
                            if 'wpa2' in caps:
                                security = "WPA2"
                        
                        network_info = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'mac_address': bssid,
                            'signal_strength': signal_strength,
                            'rssi': rssi if 'rssi' in locals() else -100,
                            'channel': channel,
                            'frequency': frequency,
                            'security': security,
                            'encryption': security,
                            'auth': 'Open' if security == 'Open' else 'WPA/WPA2',
                            'wps': 'Unknown',
                            'type': 'Infrastructure',
                            'vendor': 'Unknown',
                            'first_seen': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat(),
                            'network_type': self.classify_wifi_network(ssid, bssid),
                            'method': 'PyShark'
                        }
                        
                        networks.append(network_info)
                        logger.info(f"PyShark: {ssid} ({bssid}) - {signal_strength}%")
                
                except Exception as e:
                    logger.warning(f"Error processing PyShark packet: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"PyShark scan failed: {e}")
        
        return networks

    def scan_with_netsh(self) -> List[Dict]:
        """Scan Wi-Fi networks using Windows netsh with advanced information"""
        networks = []
        
        try:
            logger.info("Scanning with netsh...")
            
            # Get available networks
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'All User Profile' in line and ':' in line:
                        ssid = line.split(':')[1].strip()
                        if ssid:
                            # Get detailed profile information
                            profile_result = subprocess.run(['netsh', 'wlan', 'show', 'profile', f'name="{ssid}"', 'key=clear'], 
                                                          capture_output=True, text=True, timeout=10)
                            
                            network_info = {
                                'ssid': ssid,
                                'bssid': 'Unknown',
                                'mac_address': 'Unknown',
                                'signal_strength': 0,
                                'rssi': -100,
                                'channel': 1,
                                'frequency': 'Unknown',
                                'security': 'Unknown',
                                'encryption': 'Unknown',
                                'auth': 'Unknown',
                                'wps': 'Unknown',
                                'type': 'Saved Profile',
                                'vendor': 'Unknown',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'network_type': 'Saved Network',
                                'method': 'PowerShell Profile Scan',
                                'profile_details': profile_result.stdout if profile_result.returncode == 0 else 'Failed to get details'
                            }
                            networks.append(network_info)
                            logger.info(f"netsh: {ssid} (Saved Profile)")
            
            # Get currently visible networks
            visible_result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                                          capture_output=True, text=True, timeout=15)
            
            if visible_result.returncode == 0:
                lines = visible_result.stdout.split('\n')
                current_network = {}
                
                for line in lines:
                    line = line.strip()
                    if 'SSID' in line and ':' in line and 'BSSID' not in line:
                        if current_network:
                            networks.append(current_network)
                        ssid = line.split(':')[1].strip()
                        current_network = {
                            'ssid': ssid,
                            'bssid': 'Unknown',
                            'mac_address': 'Unknown',
                            'signal_strength': 0,
                            'rssi': -100,
                            'channel': 1,
                            'frequency': 'Unknown',
                            'security': 'Unknown',
                            'encryption': 'Unknown',
                            'auth': 'Unknown',
                            'wps': 'Unknown',
                            'type': 'Infrastructure',
                            'vendor': 'Unknown',
                            'first_seen': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat(),
                            'network_type': self.classify_wifi_network(ssid, 'Unknown'),
                            'method': 'netsh visible networks'
                        }
                    elif 'BSSID' in line and ':' in line:
                        bssid = line.split(':')[1].strip()
                        current_network['bssid'] = bssid
                        current_network['mac_address'] = bssid
                        current_network['vendor'] = self.get_vendor_from_mac(bssid)
                    elif 'Signal' in line and ':' in line:
                        signal = line.split(':')[1].strip().replace('%', '')
                        try:
                            current_network['signal_strength'] = int(signal)
                            current_network['rssi'] = int(signal) - 100
                        except:
                            pass
                    elif 'Radio type' in line and ':' in line:
                        radio_type = line.split(':')[1].strip()
                        current_network['radio_type'] = radio_type
                    elif 'Channel' in line and ':' in line:
                        channel = line.split(':')[1].strip()
                        try:
                            current_network['channel'] = int(channel)
                            # Calculate frequency
                            if 1 <= int(channel) <= 14:
                                current_network['frequency'] = 2412 + (int(channel) - 1) * 5
                            elif 36 <= int(channel) <= 165:
                                current_network['frequency'] = 5000 + (int(channel) - 36) * 5
                        except:
                            pass
                    elif 'Authentication' in line and ':' in line:
                        auth = line.split(':')[1].strip()
                        current_network['auth'] = auth
                        current_network['security'] = auth
                    elif 'Encryption' in line and ':' in line:
                        encryption = line.split(':')[1].strip()
                        current_network['encryption'] = encryption
                
                if current_network:
                    networks.append(current_network)
        
        except Exception as e:
            logger.error(f"netsh scan failed: {e}")
        
        return networks

    def scan_with_powershell(self) -> List[Dict]:
        """Advanced Wi-Fi scan using PowerShell for maximum information"""
        networks = []
        
        try:
            logger.info("Scanning with PowerShell...")
            
            # PowerShell script to get comprehensive Wi-Fi information
            ps_script = """
            $networks = @()
            $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile"
            foreach ($profile in $wifiProfiles) {
                $ssid = ($profile -split ":")[1].Trim()
                $profileDetails = netsh wlan show profile name="$ssid" key=clear
                $networks += [PSCustomObject]@{
                    SSID = $ssid
                    Type = "Saved Profile"
                    Details = $profileDetails
                }
            }
            
            $visibleNetworks = netsh wlan show networks mode=bssid
            $networks += [PSCustomObject]@{
                SSID = "Visible Networks"
                Type = "Currently Visible"
                Details = $visibleNetworks
            }
            
            $interfaces = netsh wlan show interfaces
            $networks += [PSCustomObject]@{
                SSID = "Interface Info"
                Type = "Interface Details"
                Details = $interfaces
            }
            
            $networks | ConvertTo-Json -Depth 3
            """
            
            result = subprocess.run(['powershell', '-Command', ps_script], 
                                  capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                try:
                    import json
                    ps_data = json.loads(result.stdout)
                    
                    for item in ps_data:
                        if item['Type'] == 'Saved Profile':
                            network_info = {
                                'ssid': item['SSID'],
                                'bssid': 'Unknown',
                                'mac_address': 'Unknown',
                                'signal_strength': 0,
                                'rssi': -100,
                                'channel': 1,
                                'frequency': 'Unknown',
                                'security': 'Unknown',
                                'encryption': 'Unknown',
                                'auth': 'Unknown',
                                'wps': 'Unknown',
                                'type': 'Saved Profile',
                                'vendor': 'Unknown',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'network_type': 'Saved Network',
                                'method': 'PowerShell Advanced',
                                'raw_details': item['Details']
                            }
                            networks.append(network_info)
                            logger.info(f"PowerShell: {item['SSID']} (Advanced Profile)")
                            
                except json.JSONDecodeError:
                    # Fallback: parse as text
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip().strip('"')
                            if ssid and ssid not in ['Visible Networks', 'Interface Info']:
                                network_info = {
                                    'ssid': ssid,
                                    'bssid': 'Unknown',
                                    'mac_address': 'Unknown',
                                    'signal_strength': 0,
                                    'rssi': -100,
                                    'channel': 1,
                                    'frequency': 'Unknown',
                                    'security': 'Unknown',
                                    'encryption': 'Unknown',
                                    'auth': 'Unknown',
                                    'wps': 'Unknown',
                                    'type': 'PowerShell Detected',
                                    'vendor': 'Unknown',
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'network_type': self.classify_wifi_network(ssid, 'Unknown'),
                                    'method': 'PowerShell Advanced',
                                    'raw_output': result.stdout
                                }
                                networks.append(network_info)
                                logger.info(f"PowerShell: {ssid} (Advanced Detection)")
        
        except Exception as e:
            logger.error(f"PowerShell scan failed: {e}")
        
        return networks

    def scan_with_wmic(self) -> List[Dict]:
        """Scan using WMIC for additional system information"""
        networks = []
        
        try:
            logger.info("Scanning with WMIC...")
            
            # Get network adapter information
            result = subprocess.run(['wmic', 'path', 'win32_networkadapter', 'where', 'NetConnectionStatus=2', 'get', 'Name,MACAddress,NetConnectionID'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and 'Name' not in line and 'MACAddress' not in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = ' '.join(parts[:-2]) if len(parts) > 2 else parts[0]
                            mac = parts[-2] if len(parts) >= 2 else 'Unknown'
                            connection_id = parts[-1] if len(parts) >= 1 else 'Unknown'
                            
                            if 'wireless' in name.lower() or 'wifi' in name.lower() or 'wlan' in name.lower():
                                network_info = {
                                    'ssid': 'System Interface',
                                    'bssid': mac,
                                    'mac_address': mac,
                                    'signal_strength': 0,
                                    'rssi': -100,
                                    'channel': 1,
                                    'frequency': 'Unknown',
                                    'security': 'Unknown',
                                    'encryption': 'Unknown',
                                    'auth': 'Unknown',
                                    'wps': 'Unknown',
                                    'type': 'Network Adapter',
                                    'vendor': 'Unknown',
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'network_type': 'System Interface',
                                    'method': 'WMIC',
                                    'adapter_name': name,
                                    'connection_id': connection_id
                                }
                                networks.append(network_info)
                                logger.info(f"WMIC: {name} ({mac})")
        
        except Exception as e:
            logger.error(f"WMIC scan failed: {e}")
        
        return networks

    def packet_capture_thread(self, interface: str):
        """Thread for packet capture using Scapy"""
        if not SCAPY_AVAILABLE:
            return
        
        try:
            logger.info(f"Starting packet capture on {interface}")
            
            def packet_handler(packet):
                try:
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src': packet.src if hasattr(packet, 'src') else 'Unknown',
                        'dst': packet.dst if hasattr(packet, 'dst') else 'Unknown',
                        'protocol': packet.proto if hasattr(packet, 'proto') else 'Unknown',
                        'size': len(packet),
                        'type': 'Wi-Fi' if packet.haslayer(Dot11) else 'Ethernet'
                    }
                    
                    # Add Wi-Fi specific information
                    if packet.haslayer(Dot11):
                        dot11 = packet[Dot11]
                        packet_info.update({
                            'wifi_type': dot11.type,
                            'wifi_subtype': dot11.subtype,
                            'wifi_addr1': dot11.addr1,
                            'wifi_addr2': dot11.addr2,
                            'wifi_addr3': dot11.addr3,
                            'wifi_addr4': dot11.addr4
                        })
                    
                    self.packet_queue.put(packet_info)
                    self.captured_packets.append(packet_info)
                    
                except Exception as e:
                    logger.warning(f"Error processing packet: {e}")
            
            # Sniff packets
            scapy.sniff(iface=interface, prn=packet_handler, store=0)
            
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")

    def start_comprehensive_scan(self, duration=30):
        """Start comprehensive Wi-Fi scan using all available methods"""
        if self.scanning:
            logger.warning("Scan already in progress")
            return
        
        self.scanning = True
        self.start_time = datetime.now()
        self.wifi_networks = {}
        
        logger.info("Starting comprehensive Wi-Fi scan for ALL nearby Wi-Fi devices...")
        logger.info("Scanning for ALL nearby Wi-Fi devices using multiple methods...")
        
        # Get available interfaces
        interfaces = self.get_wifi_interfaces()
        logger.info(f"Available interfaces: {interfaces}")
        
        # Start packet capture thread
        if interfaces and SCAPY_AVAILABLE:
            self.packet_thread = threading.Thread(
                target=self.packet_capture_thread, 
                args=(interfaces[0],)
            )
            self.packet_thread.daemon = True
            self.packet_thread.start()
        
        # Start scanning thread
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(duration, interfaces))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _scan_worker(self, duration, interfaces):
        """Worker thread for scanning"""
        try:
            # Method 1: PyWiFi scan
            logger.info("Scanning Wi-Fi using PyWiFi...")
            pywifi_networks = self.scan_with_pywifi()
            for network in pywifi_networks:
                self.wifi_networks[network['bssid']] = network
            logger.info(f"PyWiFi scan found {len(pywifi_networks)} networks")
            
            # Linux-native scans
            if sys.platform.startswith('linux'):
                logger.info("Scanning Wi-Fi using nmcli (Linux)...")
                nmcli_networks = self.scan_with_nmcli()
                for network in nmcli_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
                logger.info("nmcli scan completed")

                logger.info("Scanning Wi-Fi using iwlist (Linux fallback)...")
                iwlist_networks = self.scan_with_iwlist(interfaces)
                for network in iwlist_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
                logger.info("iwlist scan completed")

            # Method 2: Scapy scan
            if SCAPY_AVAILABLE and interfaces:
                logger.info("Scanning Wi-Fi using Scapy...")
                # Calculate timeout per interface to fit within duration
                # Reserve 5 seconds for other scans and overhead
                available_time = max(5, duration - 5)
                per_interface_timeout = max(5, int(available_time / len(interfaces)))
                
                for interface in interfaces:
                    scapy_networks = self.scan_with_scapy(interface, timeout=per_interface_timeout)
                    for network in scapy_networks:
                        if network['bssid'] not in self.wifi_networks:
                            self.wifi_networks[network['bssid']] = network
                logger.info(f"Scapy scan completed")
            
            # Method 3: PyShark scan
            if PYSHARK_AVAILABLE and interfaces:
                logger.info("Scanning Wi-Fi using PyShark...")
                # Calculate timeout per interface to fit within duration
                # Reserve 5 seconds for other scans and overhead
                available_time = max(5, duration - 5)
                per_interface_timeout = max(5, int(available_time / len(interfaces)))
                
                for interface in interfaces:
                    pyshark_networks = self.scan_with_pyshark(interface, timeout=per_interface_timeout)
                    for network in pyshark_networks:
                        if network['bssid'] not in self.wifi_networks:
                            self.wifi_networks[network['bssid']] = network
                logger.info(f"PyShark scan completed")
            
            # Windows-specific scans only on Windows
            if sys.platform.startswith('win'):
                # Method 4: netsh scan
                logger.info("Scanning Wi-Fi using netsh...")
                netsh_networks = self.scan_with_netsh()
                for network in netsh_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
                logger.info(f"netsh scan completed")
                
                # Method 5: PowerShell advanced scan
                logger.info("Scanning Wi-Fi using PowerShell...")
                ps_networks = self.scan_with_powershell()
                for network in ps_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
                logger.info(f"PowerShell scan completed")
                
                # Method 6: WMIC system scan
                logger.info("Scanning system interfaces using WMIC...")
                wmic_networks = self.scan_with_wmic()
                for network in wmic_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
                logger.info(f"WMIC scan completed")
            
            # Wait for additional discovery
            logger.info(f"Waiting {duration} seconds for additional network discovery...")
            time.sleep(duration)
            
            # Final scan based on platform
            if sys.platform.startswith('linux'):
                logger.info("Performing final nmcli scan...")
                final_networks = self.scan_with_nmcli()
                for network in final_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
            elif sys.platform.startswith('win'):
                logger.info("Performing final netsh scan...")
                final_networks = self.scan_with_netsh()
                for network in final_networks:
                    if network['bssid'] not in self.wifi_networks:
                        self.wifi_networks[network['bssid']] = network
            
            logger.info("Comprehensive scan completed")
            logger.info(f"Found {len(self.wifi_networks)} Wi-Fi networks")
            
        except Exception as e:
            logger.error(f"Scan worker error: {e}")
        finally:
            self.scanning = False

    def stop_scan(self):
        """Stop the comprehensive scan"""
        logger.info("Stopping comprehensive scan...")
        self.scanning = False
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)
        
        if self.packet_thread and self.packet_thread.is_alive():
            self.packet_thread.join(timeout=5)
        
        logger.info("Scan interrupted by user")

    def get_scan_results(self) -> Dict:
        """Get comprehensive scan results"""
        networks = list(self.wifi_networks.values())
        
        # Calculate statistics
        total_networks = len(networks)
        hidden_networks = sum(1 for net in networks if not net.get('ssid', '').strip() or net.get('ssid') == 'Hidden Network')
        open_networks = sum(1 for net in networks if net.get('security', '').lower() in ['open', 'none'])
        secured_networks = total_networks - open_networks
        
        # Device type classification
        device_types = defaultdict(int)
        for network in networks:
            device_type = network.get('network_type', 'Unknown')
            device_types[device_type] += 1
        
        # Method breakdown
        methods = defaultdict(int)
        for network in networks:
            method = network.get('method', 'Unknown')
            methods[method] += 1
        
        results = {
            'wifi_networks': networks,
            'statistics': {
                'total_networks': total_networks,
                'hidden_networks': hidden_networks,
                'open_networks': open_networks,
                'secured_networks': secured_networks,
                'device_types': dict(device_types),
                'scan_methods': dict(methods)
            },
            'scan_info': {
                'scanning': self.scanning,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            },
            'packet_capture': {
                'total_packets': len(self.captured_packets),
                'packets': self.captured_packets[-100:]  # Last 100 packets
            }
        }
        
        return results

    def export_results(self, format='json'):
        """Export scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format.lower() == 'json':
            filename = f'comprehensive_wifi_scan_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(self.get_scan_results(), f, indent=2)
            logger.info(f"Results exported to {filename}")
        
        elif format.lower() == 'csv':
            filename = f'wifi_networks_{timestamp}.csv'
            networks = list(self.wifi_networks.values())
            
            if networks:
                # Get all possible fieldnames from all networks
                all_fieldnames = set()
                for network in networks:
                    all_fieldnames.update(network.keys())
                all_fieldnames = sorted(list(all_fieldnames))
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=all_fieldnames)
                    writer.writeheader()
                    for network in networks:
                        # Fill missing fields with empty strings
                        row = {field: network.get(field, '') for field in all_fieldnames}
                        writer.writerow(row)
                logger.info(f"Results exported to {filename}")
        
        return filename

    def print_results(self):
        """Print scan results in a formatted table"""
        networks = list(self.wifi_networks.values())
        
        if not networks:
            print("No Wi-Fi networks found")
            return
        
        print(f"\nComprehensive Wi-Fi Scan Results:")
        print(f"Total Networks Found: {len(networks)}")
        
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            print(f"Scan Duration: {duration:.1f} seconds")
        
        print(f"\nWi-Fi Networks Found:")
        print("-" * 120)
        print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<8} {'Channel':<8} {'Security':<15} {'Type':<15} {'Method':<15}")
        print("-" * 120)
        
        for i, network in enumerate(networks, 1):
            ssid = network.get('ssid', 'N/A')[:24]
            bssid = network.get('bssid', 'N/A')[:17]
            signal = f"{network.get('signal_strength', 0)}%"
            channel = str(network.get('channel', 'N/A'))
            security = network.get('security', 'N/A')[:14]
            net_type = network.get('network_type', 'N/A')[:14]
            method = network.get('method', 'N/A')[:14]
            
            print(f"{i:<3} {ssid:<25} {bssid:<18} {signal:<8} {channel:<8} {security:<15} {net_type:<15} {method:<15}")
        
        print("-" * 120)
        
        # Show additional details for each network
        print(f"\nDetailed Network Information:")
        print("=" * 80)
        
        for i, network in enumerate(networks, 1):
            print(f"\n{i}. {network.get('ssid', 'N/A')}")
            print(f"   BSSID: {network.get('bssid', 'N/A')}")
            print(f"   MAC Address: {network.get('mac_address', 'N/A')}")
            print(f"   Signal Strength: {network.get('signal_strength', 0)}%")
            print(f"   RSSI: {network.get('rssi', -100)} dBm")
            print(f"   Channel: {network.get('channel', 'N/A')}")
            print(f"   Frequency: {network.get('frequency', 'N/A')} MHz")
            print(f"   Security: {network.get('security', 'N/A')}")
            print(f"   Encryption: {network.get('encryption', 'N/A')}")
            print(f"   Authentication: {network.get('auth', 'N/A')}")
            print(f"   Network Type: {network.get('network_type', 'N/A')}")
            print(f"   Detection Method: {network.get('method', 'N/A')}")
            print(f"   First Seen: {network.get('first_seen', 'N/A')}")
            print(f"   Last Seen: {network.get('last_seen', 'N/A')}")
            
            # Show additional fields if available
            if 'radio_type' in network:
                print(f"   Radio Type: {network['radio_type']}")
            if 'adapter_name' in network:
                print(f"   Adapter Name: {network['adapter_name']}")
            if 'connection_id' in network:
                print(f"   Connection ID: {network['connection_id']}")
            if 'vendor' in network and network['vendor'] != 'Unknown':
                print(f"   Vendor: {network['vendor']}")
            
            print("-" * 40)

def main():
    """Main function for testing"""
    print("Enhanced Comprehensive Wi-Fi Scanner")
    print("=" * 50)
    
    scanner = EnhancedComprehensiveWiFiScanner()
    
    try:
        # Start comprehensive scan
        scanner.start_comprehensive_scan(duration=30)
        
        # Wait for scan to complete
        while scanner.scanning:
            time.sleep(1)
        
        # Print results
        scanner.print_results()
        
        # Export results
        scanner.export_results('json')
        scanner.export_results('csv')
        
    except KeyboardInterrupt:
        scanner.stop_scan()
        print("\nScan interrupted by user")
    
    except Exception as e:
        logger.error(f"Error: {e}")
    
    finally:
        print("\nScan completed")

if __name__ == "__main__":
    main()
