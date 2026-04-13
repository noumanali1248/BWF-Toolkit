#!/usr/bin/env python3
"""
Enhanced Module 8: Windows Endpoint Security Agent
Features:
- Bluetooth monitoring and device detection (Bleak)
- WiFi device scanning and nearby devices
- Syslog collection for specific processes
- MAC address blocking with popup notifications
- Real-time WebSocket communication with central toolkit
"""

import os
import sys
import json
import time
import platform
import socket
import hashlib
import hmac
import logging
import threading
import subprocess
import psutil
import asyncio
import websockets
import base64
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from collections import defaultdict, deque
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from collections import defaultdict, deque
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Platform-specific imports
try:
    import bleak  # Bluetooth scanning for Windows/Linux/macOS
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    logging.warning("Bleak not available - Bluetooth scanning disabled")

# Windows-specific imports
if platform.system() == 'Windows':
    try:
        import win32api
        import win32con
        import win32gui
        import wmi
        WINDOWS_LIBS_AVAILABLE = True
    except ImportError:
        WINDOWS_LIBS_AVAILABLE = False
        logging.warning("Windows libraries not available")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)



class BluetoothMonitor:
    """Bluetooth device detection and monitoring"""
    
    def __init__(self):
        self.devices = {}
        self.scan_interval = 30  # seconds
        self.running = False
        
    async def scan_bluetooth_devices(self) -> List[Dict[str, Any]]:
        """Scan for nearby Bluetooth devices using bleak"""
        if not BLEAK_AVAILABLE:
            return []
        
        devices = []
        
        try:
            from bleak import BleakScanner
            
            logger.info("Scanning for Bluetooth devices...")
            
            # Windows-specific workaround for threading issues
            if platform.system() == 'Windows':
                # Run the scan in a thread pool to avoid asyncio/COM threading conflicts
                import concurrent.futures
                
                def sync_scan():
                    """Synchronous wrapper for Bluetooth scan"""
                    try:
                        # Create a new event loop for this thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        
                        async def _scan():
                            return await BleakScanner.discover(timeout=10.0)
                        
                        result = loop.run_until_complete(_scan())
                        loop.close()
                        return result
                    except Exception as e:
                        logger.error(f"Bluetooth scan error in thread: {e}")
                        return []
                
                # Run in thread pool
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(sync_scan)
                    discovered_devices = future.result(timeout=15)
            else:
                # Linux/Mac - use normal async scan
                discovered_devices = await BleakScanner.discover(timeout=10.0)
            
            for device in discovered_devices:
                device_info = {
                    'mac_address': device.address,
                    'name': device.name or 'Unknown',
                    'rssi': device.rssi if hasattr(device, 'rssi') else None,
                    'timestamp': datetime.now().isoformat(),
                    'device_type': 'bluetooth'
                }
                
                devices.append(device_info)
                self.devices[device.address] = device_info
                
            logger.info(f"Found {len(devices)} Bluetooth devices")
            
        except ImportError as e:
            logger.error(f"Bleak import error: {e}")
        except Exception as e:
            logger.error(f"Bluetooth scan error: {e}", exc_info=True)
        
        return devices
    

class WiFiMonitor:
    """WiFi device detection and nearby network scanning"""
    
    def __init__(self):
        self.networks = {}
        self.devices = {}
        
    def scan_wifi_networks(self) -> List[Dict[str, Any]]:
        """Scan for nearby WiFi networks"""
        networks = []
        
        try:
            if platform.system() == 'Windows':
                # Windows WiFi scanning using netsh
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                networks = self._parse_windows_wifi(result.stdout)
                
            elif platform.system() == 'Linux':
                # Linux WiFi scanning using iwlist
                try:
                    result = subprocess.run(
                        ['sudo', 'iwlist', 'scanning'],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    networks = self._parse_linux_wifi(result.stdout)
                except:
                    # Try nmcli as fallback
                    result = subprocess.run(
                        ['nmcli', 'dev', 'wifi', 'list'],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    networks = self._parse_nmcli_wifi(result.stdout)
            
            logger.info(f"Found {len(networks)} WiFi networks")
            
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
        
        return networks
    
    def _parse_windows_wifi(self, output: str) -> List[Dict[str, Any]]:
        """Parse Windows netsh WiFi output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('SSID'):
                if current_network and 'ssid' in current_network:
                    networks.append(current_network)
                current_network = {}
                ssid = line.split(':', 1)[1].strip()
                current_network['ssid'] = ssid
                current_network['timestamp'] = datetime.now().isoformat()
                
            elif 'BSSID' in line and ':' in line:
                bssid = line.split(':', 1)[1].strip()
                current_network['mac_address'] = bssid
                
            elif 'Signal' in line:
                signal = line.split(':', 1)[1].strip().replace('%', '')
                try:
                    current_network['signal_strength'] = int(signal)
                except:
                    pass
                    
            elif 'Channel' in line:
                channel = line.split(':', 1)[1].strip()
                current_network['channel'] = channel
        
        if current_network and 'ssid' in current_network:
            networks.append(current_network)
        
        return networks
    
    def _parse_linux_wifi(self, output: str) -> List[Dict[str, Any]]:
        """Parse Linux iwlist WiFi output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Address:' in line:
                if current_network and 'mac_address' in current_network:
                    networks.append(current_network)
                current_network = {}
                mac = line.split('Address:')[1].strip()
                current_network['mac_address'] = mac
                current_network['timestamp'] = datetime.now().isoformat()
                
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip().strip('"')
                current_network['ssid'] = ssid
                
            elif 'Signal level=' in line:
                signal = line.split('Signal level=')[1].split()[0]
                current_network['signal_strength'] = signal
                
            elif 'Channel:' in line:
                channel = line.split('Channel:')[1].strip()
                current_network['channel'] = channel
        
        if current_network and 'mac_address' in current_network:
            networks.append(current_network)
        
        return networks
    
    def _parse_nmcli_wifi(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmcli WiFi output"""
        networks = []
        
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                network = {
                    'ssid': parts[0] if parts[0] != '--' else 'Hidden',
                    'mac_address': parts[1] if len(parts) > 1 else 'Unknown',
                    'signal_strength': parts[5] if len(parts) > 5 else 'Unknown',
                    'timestamp': datetime.now().isoformat()
                }
                networks.append(network)
        
        return networks
    
    def get_connected_devices(self) -> List[Dict[str, Any]]:
        """Get devices connected to local network"""
        devices = []
        
        try:
            if platform.system() == 'Windows':
                # Use arp to get connected devices
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                devices = self._parse_arp_output(result.stdout)
                
            elif platform.system() == 'Linux':
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                devices = self._parse_arp_output(result.stdout)
            
            # Enrich devices with vendor and hostname info
            for device in devices:
                # Add MAC vendor
                device['vendor'] = self._get_mac_vendor(device['mac_address'])
                
                # Add hostname
                device['hostname'] = self._resolve_hostname(device['ip_address'])
                
                # Add device type guess
                device['device_type'] = self._guess_device_type(device)
            
            logger.info(f"Found {len(devices)} connected devices")
            
        except Exception as e:
            logger.error(f"Error getting connected devices: {e}")
        
        return devices
    
    def _get_mac_vendor(self, mac_address: str) -> str:
        """Get vendor name from MAC address OUI"""
        # Common vendor OUI prefixes (first 8 characters: XX:XX:XX)
        vendors = {
            # Virtual Machines
            '00:0c:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1c:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:16:3e': 'Xen',
            '00:15:5d': 'Microsoft Hyper-V',
            
            # Routers & Network Equipment
            '84:3c:99': 'TP-Link',
            '00:0d:b9': 'Netgear',
            '00:1f:33': 'Netgear',
            '00:24:b2': 'Netgear',
            '00:0f:b5': 'Netgear',
            '00:26:f2': 'Netgear',
            '00:14:6c': 'Netgear',
            '00:18:4d': 'Netgear',
            '00:1b:2f': 'Netgear',
            '00:1e:2a': 'Netgear',
            '00:22:3f': 'Netgear',
            '00:09:5b': 'Netgear',
            
            # Computer Manufacturers
            '64:5d:86': 'Dell',
            '00:1a:a0': 'Dell',
            '00:14:22': 'Dell',
            '00:1c:23': 'Dell',
            '00:21:70': 'Dell',
            '00:24:e8': 'Dell',
            'd8:0a:e6': 'HP',
            '00:1f:29': 'HP',
            '00:23:7d': 'HP',
            '00:26:55': 'HP',
            '3c:d9:2b': 'HP',
            '00:1b:78': 'Lenovo',
            '00:21:cc': 'Lenovo',
            '54:ee:75': 'Lenovo',
            
            # Apple
            'ac:de:48': 'Apple',
            '00:03:93': 'Apple',
            '00:0a:95': 'Apple',
            '00:0d:93': 'Apple',
            '00:14:51': 'Apple',
            '00:16:cb': 'Apple',
            '00:17:f2': 'Apple',
            '00:19:e3': 'Apple',
            '00:1b:63': 'Apple',
            '00:1c:b3': 'Apple',
            '00:1d:4f': 'Apple',
            '00:1e:52': 'Apple',
            '00:1f:5b': 'Apple',
            '00:1f:f3': 'Apple',
            '00:21:e9': 'Apple',
            '00:22:41': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6c': 'Apple',
            '00:23:df': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:25:4b': 'Apple',
            '00:25:bc': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4a': 'Apple',
            '00:26:b0': 'Apple',
            '00:26:bb': 'Apple',
            
            # Other
            '00:1a:11': 'Google',
            '28:6a:ba': 'Amazon',
            'b8:27:eb': 'Raspberry Pi Foundation',
            'dc:a6:32': 'Raspberry Pi Foundation',
            'e4:5f:01': 'Raspberry Pi Foundation',
        }
        
        # Get first 8 characters (XX:XX:XX format)
        oui = mac_address[:8].lower()
        return vendors.get(oui, 'Unknown Vendor')
    
    def _resolve_hostname(self, ip_address: str) -> str:
        """Resolve IP address to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return 'Unknown'
    
    def _guess_device_type(self, device: Dict[str, Any]) -> str:
        """Guess device type based on IP, MAC, hostname"""
        ip = device.get('ip_address', '')
        mac = device.get('mac_address', '').lower()
        hostname = device.get('hostname', '').lower()
        vendor = device.get('vendor', '').lower()
        
        # Router/Gateway (usually .1)
        if ip.endswith('.1'):
            return 'Router/Gateway'
        
        # Virtual machines
        if any(v in vendor for v in ['vmware', 'virtualbox', 'qemu', 'parallels', 'xen', 'hyper-v']):
            return 'Virtual Machine'
        
        # Raspberry Pi
        if 'raspberry' in vendor:
            return 'Raspberry Pi'
        
        # Mobile devices
        if any(h in hostname for h in ['iphone', 'ipad', 'android', 'mobile']):
            return 'Mobile Device'
        
        # Apple devices
        if 'apple' in vendor or any(h in hostname for h in ['macbook', 'imac', 'mac-']):
            return 'Apple Device'
        
        # Network equipment
        if any(v in vendor for v in ['netgear', 'tp-link', 'cisco', 'linksys', 'd-link']):
            return 'Network Equipment'
        
        # Computers
        if any(h in hostname for h in ['desktop', 'laptop', 'pc-', 'workstation']):
            return 'Computer'
        
        # Default
        return 'Unknown Device'
    
    def _parse_arp_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ARP table output"""
        devices = []
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            # Look for MAC addresses
            parts = line.split()
            mac_address = None
            ip_address = None
            
            for part in parts:
                # Match MAC address pattern
                if '-' in part and len(part.replace('-', '')) == 12:
                    mac_address = part.replace('-', ':')
                elif ':' in part and len(part.replace(':', '')) == 12:
                    mac_address = part
                
                # Match IP address
                if '.' in part and part.replace('.', '').replace(' ', '').isdigit():
                    ip_address = part
            
            if mac_address and ip_address:
                # Filter out broadcast and multicast addresses
                mac_lower = mac_address.lower()
                
                # Skip broadcast MAC (ff:ff:ff:ff:ff:ff)
                if mac_lower == 'ff:ff:ff:ff:ff:ff':
                    continue
                
                # Skip multicast MACs (01:00:5e:xx:xx:xx for IPv4 multicast)
                if mac_lower.startswith('01:00:5e'):
                    continue
                
                # Skip broadcast IP (255.255.255.255)
                if ip_address == '255.255.255.255':
                    continue
                
                # Skip multicast IPs (224.0.0.0 - 239.255.255.255)
                try:
                    first_octet = int(ip_address.split('.')[0])
                    if 224 <= first_octet <= 239:
                        continue
                except:
                    pass
                
                device = {
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'timestamp': datetime.now().isoformat()
                }
                devices.append(device)
        
        return devices


class SyslogCollector:
    """Collect process activity logs (Process Start/Stop events)"""
    
    def __init__(self):
        self.log_buffer = deque(maxlen=1000)
        self.running_processes = {}  # PID -> Name
        self._init_process_list()
        
    def _init_process_list(self):
        """Initialize list of running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    self.running_processes[proc.info['pid']] = proc.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            logger.error(f"Error initializing process list: {e}")
            
    def collect_process_logs(self, process_names: List[str] = None) -> List[Dict[str, Any]]:
        """Return a snapshot of currently running processes"""
        logs = []
        
        try:
            # Get current processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Create a log entry for each running process
                    # We use a unique ID based on PID and time to ensure it's treated as a new log if needed
                    # But since the user wants a snapshot, we might just send the list.
                    # However, the backend/frontend likely expects a list of log entries.
                    
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'log_level': 'INFO',
                        'message': f"{proc.info['name']} (PID: {proc.info['pid']})",
                        'source': 'process_snapshot'
                    }
                    logs.append(log_entry)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort by name
            logs.sort(key=lambda x: x['message'].lower())
            
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
        
        return logs

    def _collect_windows_logs(self, process_names: List[str]) -> List[Dict[str, Any]]:
        """Deprecated: Windows Event Logs (replaced by process monitoring)"""
        return []

    def _collect_linux_logs(self, process_names: List[str]) -> List[Dict[str, Any]]:
        """Deprecated: Linux logs (replaced by process monitoring)"""
        return []


class MACBlocker:
    """MAC address blocking functionality with popup notifications"""
    
    def __init__(self):
        self.blocked_macs = set()
        self.block_db = 'blocked_macs.db'
        self._init_database()
        
    def _init_database(self):
        """Initialize database for blocked MACs"""
        conn = sqlite3.connect(self.block_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_macs (
                mac_address TEXT PRIMARY KEY,
                reason TEXT,
                timestamp TEXT,
                blocked_by TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def block_mac_address(self, mac_address: str, reason: str = '') -> Dict[str, Any]:
        """Block a MAC address"""
        self.blocked_macs.add(mac_address)
        
        # Store in database
        conn = sqlite3.connect(self.block_db)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT OR REPLACE INTO blocked_macs (mac_address, reason, timestamp, blocked_by) VALUES (?, ?, ?, ?)',
            (mac_address, reason, datetime.now().isoformat(), 'central_toolkit')
        )
        
        conn.commit()
        conn.close()
        
        # Show popup notification
        self._show_block_notification(mac_address, reason)
        
        # Apply firewall rule
        success = self._apply_firewall_block(mac_address)
        
        logger.warning(f"Blocked MAC address: {mac_address} - {reason}")
        
        return {
            'status': 'blocked',
            'mac_address': mac_address,
            'reason': reason,
            'firewall_applied': success,
            'timestamp': datetime.now().isoformat()
        }
    
    def _show_block_notification(self, mac_address: str, reason: str):
        """Show popup notification for blocked MAC"""
        try:
            if platform.system() == 'Windows' and WINDOWS_LIBS_AVAILABLE:
                # Windows notification
                message = f"MAC Address Blocked!\n\nAddress: {mac_address}\nReason: {reason}"
                win32api.MessageBox(0, message, 'Security Alert', win32con.MB_ICONWARNING | win32con.MB_OK)
                
            elif platform.system() == 'Linux':
                # Linux notification using notify-send
                subprocess.run(
                    ['notify-send', 'Security Alert', f'Blocked MAC: {mac_address}\nReason: {reason}'],
                    timeout=5
                )
                
            else:
                logger.info(f"Popup notification: Blocked {mac_address} - {reason}")
                
        except Exception as e:
            logger.error(f"Notification error: {e}")
    
    def _apply_firewall_block(self, mac_address: str) -> bool:
        """Apply firewall rule to block MAC address"""
        try:
            if platform.system() == 'Windows':
                # Windows firewall rule
                rule_name = f"Block_MAC_{mac_address.replace(':', '_')}"
                
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name={rule_name}', 'dir=in', 'action=block',
                     f'remoteip=any', 'protocol=any'],
                    timeout=10
                )
                
                return True
                
            elif platform.system() == 'Linux':
                # Linux iptables rule
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac',
                     '--mac-source', mac_address, '-j', 'DROP'],
                    timeout=10
                )
                
                return True
                
        except Exception as e:
            logger.error(f"Firewall block error: {e}")
            return False
    
    def unblock_mac_address(self, mac_address: str) -> Dict[str, Any]:
        """Unblock a MAC address"""
        if mac_address in self.blocked_macs:
            self.blocked_macs.remove(mac_address)
        
        # Remove from database
        conn = sqlite3.connect(self.block_db)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_macs WHERE mac_address = ?', (mac_address,))
        conn.commit()
        conn.close()
        
        logger.info(f"Unblocked MAC address: {mac_address}")
        
        return {
            'status': 'unblocked',
            'mac_address': mac_address,
            'timestamp': datetime.now().isoformat()
        }


class EnhancedWindowsAgent:
    """Enhanced Windows Endpoint Security Agent with all features"""
    
    def __init__(self, controller_url: str, auth_token: str, agent_id: str = None, use_encryption: bool = False):
        """Initialize the enhanced agent"""
        self.controller_url = controller_url
        self.auth_token = auth_token
        self.agent_id = agent_id or self._generate_agent_id()
        self.websocket = None
        self.running = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 999999
        self.reconnect_delay = 5
        
        # Encryption (disabled by default for compatibility)
        self.use_encryption = use_encryption
        if self.use_encryption:
            self.encryption_key = self._derive_encryption_key()
            logger.info("[SECURE] Encryption enabled")
        else:
            self.encryption_key = None
            logger.info("[INSECURE] Encryption disabled (plain JSON mode)")
        
        # System information
        self.system_info = self._collect_system_info()
        
        # Initialize monitors
        self.bluetooth_monitor = BluetoothMonitor()
        self.wifi_monitor = WiFiMonitor()
        self.syslog_collector = SyslogCollector()
        self.mac_blocker = MACBlocker()
        
        # Monitoring threads
        self.heartbeat_interval = 30
        self.monitor_interval = 60  # Monitor every minute
        
        logger.info(f"Enhanced Windows Agent initialized (ID: {self.agent_id})")
        logger.info(f"Platform: {self.system_info.get('platform')}")
        logger.info(f"Bluetooth available: {BLEAK_AVAILABLE}")
        
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        hostname = socket.gethostname()
        unique_string = f"{hostname}_{platform.system()}_{int(time.time())}"
        agent_id = hashlib.md5(unique_string.encode()).hexdigest()[:16]
        return f"agent_{agent_id}"
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from auth token"""
        password = self.auth_token.encode()
        salt = b'endpoint_security_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _encrypt_message(self, message: str) -> str:
        """Encrypt message (only if encryption is enabled)"""
        if not self.use_encryption or self.encryption_key is None:
            return message  # Return plain message
        
        try:
            f = Fernet(self.encryption_key)
            encrypted = f.encrypt(message.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return message
    
    def _decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt message (only if encryption is enabled)"""
        # Handle empty messages first
        if not encrypted_message or encrypted_message.strip() == '':
            logger.debug("Received empty message")
            return ''
        
        # If encryption is disabled, return message as-is
        if not self.use_encryption or self.encryption_key is None:
            logger.debug("Encryption disabled, returning plain message")
            return encrypted_message
        
        try:
            f = Fernet(self.encryption_key)
            decoded = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = f.decrypt(decoded)
            logger.debug("Message decrypted successfully")
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            logger.error(f"Message type: {type(encrypted_message)}, length: {len(encrypted_message)}")
            logger.error(f"First 100 chars: '{encrypted_message[:100]}'")
            # Try to return as plain text in case controller sent unencrypted message
            logger.warning("Attempting to use message as plain text")
            return encrypted_message
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information"""
        try:
            # Get IP and MAC address
            import uuid
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                ip_address = "Unknown"
            
            mac = uuid.getnode()
            mac_address = ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(40, -8, -8)])
            
            return {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'python_version': platform.python_version(),
                'agent_version': '2.0.0-enhanced',
                'ip_address': ip_address,
                'mac_address': mac_address,
                'features': {
                    'bluetooth': BLEAK_AVAILABLE,
                    'wifi': True,
                    'syslog': True,
                    'mac_blocking': True
                }
            }
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}
    
    async def _monitor_bluetooth_devices(self):
        """Continuously monitor Bluetooth devices"""
        while self.running:
            try:
                # Scan using bleak
                if BLEAK_AVAILABLE:
                    logger.info("Starting Bluetooth scan...")
                    devices = await self.bluetooth_monitor.scan_bluetooth_devices()
                    
                    # Always send update, even if empty (to show "0 devices found")
                    await self._send_device_update('bluetooth', devices)
                    logger.info(f"Sent {len(devices)} Bluetooth devices to controller")
                
                await asyncio.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Bluetooth monitoring error: {e}", exc_info=True)
                await asyncio.sleep(self.monitor_interval)
    
    async def _monitor_wifi_networks(self):
        """Continuously monitor WiFi networks"""
        while self.running:
            try:
                # Scan WiFi networks
                networks = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.wifi_monitor.scan_wifi_networks
                )
                
                if networks:
                    await self._send_device_update('wifi', networks)
                
                # Get connected devices
                devices = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.wifi_monitor.get_connected_devices
                )
                
                if devices:
                    await self._send_device_update('connected_devices', devices)
                
                await asyncio.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"WiFi monitoring error: {e}")
                await asyncio.sleep(self.monitor_interval)
    
    async def _collect_syslogs(self):
        """Continuously collect process snapshots"""
        while self.running:
            try:
                # Collect snapshot of all running processes
                # We don't filter by name anymore as we want a full snapshot
                logs = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.syslog_collector.collect_process_logs,
                    None
                )
                
                if logs:
                    # Send as syslog update
                    # Note: This might flood the logs if sent too frequently.
                    # The user requested "only currently running processes".
                    # If the frontend appends, it will duplicate.
                    # But we can't change frontend here easily.
                    # We'll send it every 60 seconds (monitor_interval).
                    await self._send_syslog_update(logs)
                
                await asyncio.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Syslog collection error: {e}")
                await asyncio.sleep(self.monitor_interval)
    
    async def _send_device_update(self, device_type: str, devices: List[Dict[str, Any]]):
        """Send device update to toolkit"""
        try:
            message = {
                'type': 'device_update',
                'agent_id': self.agent_id,
                'device_type': device_type,
                'devices': devices,
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted_message = self._encrypt_message(json.dumps(message))
            await self.websocket.send(encrypted_message)
            
            logger.info(f"Sent {len(devices)} {device_type} devices to toolkit")
            
        except Exception as e:
            logger.error(f"Error sending device update: {e}")
    
    async def _send_syslog_update(self, logs: List[Dict[str, Any]]):
        """Send syslog update to toolkit"""
        try:
            message = {
                'type': 'syslog_update',
                'agent_id': self.agent_id,
                'logs': logs,
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted_message = self._encrypt_message(json.dumps(message))
            await self.websocket.send(encrypted_message)
            
            logger.info(f"Sent {len(logs)} syslogs to toolkit")
            
        except Exception as e:
            logger.error(f"Error sending syslog update: {e}")
    
    
    async def _send_heartbeat(self):
        """Send periodic heartbeat"""
        while self.running:
            try:
                if self.websocket:
                    # Collect current metrics
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory_percent = psutil.virtual_memory().percent
                    
                    heartbeat_message = {
                        'type': 'heartbeat',
                        'agent_id': self.agent_id,
                        'timestamp': datetime.now().isoformat(),
                        'status': 'alive',
                        'metrics': {
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory_percent,
                            'bluetooth_devices': len(self.bluetooth_monitor.devices),
                            'wifi_networks': len(self.wifi_monitor.networks)
                        }
                    }
                    
                    encrypted_message = self._encrypt_message(json.dumps(heartbeat_message))
                    await self.websocket.send(encrypted_message)
                    
                await asyncio.sleep(self.heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def _register_with_controller(self):
        """Register agent with controller"""
        try:
            registration_message = {
                'type': 'agent_registration',
                'agent_id': self.agent_id,
                'hostname': self.system_info.get('hostname', 'Unknown'),
                'platform': self.system_info.get('platform', 'Unknown'),
                'system_info': self.system_info,
                'ip_address': self.system_info.get('ip_address', 'Unknown'),
                'mac_address': self.system_info.get('mac_address', 'Unknown'),
                'timestamp': datetime.now().isoformat()
            }
            
            # Encrypt only if encryption is enabled
            message_to_send = self._encrypt_message(json.dumps(registration_message))
            await self.websocket.send(message_to_send)
            
            logger.info(f"[SUCCESS] Registration sent to controller (encrypted: {self.use_encryption})")
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
    
    async def _handle_command(self, command: Dict[str, Any]):
        """Handle incoming command from controller"""
        command_id = command.get('command_id', 'unknown')
        action = command.get('action', '')
        params = command.get('params', {})
        
        logger.info(f"Received command: {action} (ID: {command_id})")
        
        try:
            result = {}
            
            if action == 'block_mac':
                mac_address = params.get('mac_address', '')
                vendor = params.get('vendor', 'Unknown Vendor')
                ip_address = params.get('ip_address', 'Unknown IP')
                reason = params.get('reason', 'Commanded by central toolkit')
                
                # Show Windows popup notification with vendor info
                try:
                    import win32api
                    import win32con
                    
                    # Create popup message
                    popup_title = "BWF Toolkit - MAC Address Block"
                    popup_message = f"""The central toolkit has requested to block this device:

MAC Address: {mac_address}
Vendor: {vendor}
IP Address: {ip_address}

Reason: {reason}

This device will be blocked from network access."""
                    
                    # Show popup (MB_ICONWARNING | MB_OK)
                    win32api.MessageBox(0, popup_message, popup_title, win32con.MB_ICONWARNING | win32con.MB_OK)
                    logger.info(f"Displayed popup for blocking {vendor} device ({mac_address})")
                    
                except Exception as popup_error:
                    logger.warning(f"Could not show popup: {popup_error}")
                
                # Block the MAC address
                result = self.mac_blocker.block_mac_address(mac_address, reason)
                result['vendor'] = vendor
                result['popup_shown'] = True
                
            elif action == 'unblock_mac':
                mac_address = params.get('mac_address', '')
                result = self.mac_blocker.unblock_mac_address(mac_address)
                
            elif action == 'scan_bluetooth':
                if BLEAK_AVAILABLE:
                    devices = await self.bluetooth_monitor.scan_bluetooth_devices()
                    result = {'devices': devices, 'count': len(devices)}
                else:
                    result = {'error': 'Bluetooth scanning not available'}
                    
            elif action == 'scan_wifi':
                networks = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.wifi_monitor.scan_wifi_networks
                )
                result = {'networks': networks, 'count': len(networks)}
                
            elif action == 'collect_syslogs':
                process_names = params.get('processes', ['bluetooth', 'wlan'])
                logs = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.syslog_collector.collect_process_logs,
                    process_names
                )
                result = {'logs': logs, 'count': len(logs)}
                
            
            elif action == 'shutdown_agent':
                reason = params.get('reason', 'Shutdown requested by administrator')
                logger.warning(f"Shutdown requested: {reason}")
                
                # Show popup (blocking until user clicks OK)
                try:
                    if platform.system() == 'Windows':
                        import ctypes
                        # MB_OK = 0x0, MB_ICONWARNING = 0x30, MB_SYSTEMMODAL = 0x1000
                        ctypes.windll.user32.MessageBoxW(0, f"Administrator has requested a shutdown.\n\nReason: {reason}\n\nClick OK to proceed.", "System Shutdown", 0x30 | 0x1000)
                    else:
                        logger.info(f"Popup not supported on {platform.system()}, proceeding with shutdown")
                except Exception as e:
                    logger.error(f"Error showing popup: {e}")
                
                # Execute shutdown
                try:
                    if platform.system() == 'Windows':
                        subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
                    else:
                        subprocess.run(["shutdown", "-h", "now"], check=True)
                    result = {'status': 'shutdown_initiated', 'reason': reason}
                except Exception as e:
                    logger.error(f"Error executing shutdown: {e}")
                    result = {'error': f'Shutdown failed: {e}'}
                
            else:
                result = {'error': f'Unknown action: {action}'}
            
            result['status'] = 'success' if 'error' not in result else 'error'
            result['action'] = action
            result['timestamp'] = datetime.now().isoformat()
            
            await self._send_command_response(command_id, result)
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            await self._send_command_response(command_id, {
                'status': 'error',
                'message': str(e),
                'action': action,
                'timestamp': datetime.now().isoformat()
            })
    
    async def _send_command_response(self, command_id: str, result: Dict[str, Any]):
        """Send command response to controller"""
        try:
            response_message = {
                'type': 'command_response',
                'command_id': command_id,
                'agent_id': self.agent_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted_message = self._encrypt_message(json.dumps(response_message))
            await self.websocket.send(encrypted_message)
            
            logger.info(f"Response sent for command {command_id}")
            
        except Exception as e:
            logger.error(f"Error sending response: {e}")
    
    async def connect(self):
        """Connect to controller with auto-reconnect"""
        ws_url = f"{self.controller_url}/ws/{self.agent_id}"
        
        while self.reconnect_attempts < self.max_reconnect_attempts:
            try:
                logger.info(f"Connecting to controller: {ws_url}")
                
                async with websockets.connect(ws_url) as websocket:
                    self.websocket = websocket
                    self.running = True
                    self.reconnect_attempts = 0
                    
                    logger.info("Connected to controller successfully")
                    
                    # Register with controller
                    await self._register_with_controller()
                    
                    # Start monitoring tasks
                    heartbeat_task = asyncio.create_task(self._send_heartbeat())
                    bluetooth_task = asyncio.create_task(self._monitor_bluetooth_devices())
                    wifi_task = asyncio.create_task(self._monitor_wifi_networks())
                    syslog_task = asyncio.create_task(self._collect_syslogs())
                    
                    # Listen for commands
                    try:
                        async for message in websocket:
                            try:
                                # Log raw message type for debugging
                                logger.debug(f"Received message type: {type(message)}, length: {len(message) if message else 0}")
                                
                                # Handle empty messages
                                if not message or (isinstance(message, str) and message.strip() == ''):
                                    logger.debug("Skipping empty message")
                                    continue
                                
                                # Decrypt message
                                decrypted_message = self._decrypt_message(message)
                                
                                # Validate decrypted message
                                if not decrypted_message or decrypted_message.strip() == '':
                                    logger.debug("Skipping empty decrypted message")
                                    continue
                                
                                # Log first 200 chars of decrypted message for debugging
                                logger.debug(f"Decrypted message preview: {decrypted_message[:200]}")
                                
                                # Parse JSON
                                try:
                                    command = json.loads(decrypted_message)
                                except json.JSONDecodeError as json_err:
                                    logger.error(f"JSON decode error: {json_err}")
                                    logger.error(f"Failed to parse message. First 200 chars: '{decrypted_message[:200]}'")
                                    logger.error(f"Message length: {len(decrypted_message)}")
                                    continue
                                
                                # Handle command
                                await self._handle_command(command)
                                
                            except Exception as e:
                                logger.error(f"Message handling error: {e}", exc_info=True)
                                
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("Connection closed by server")
                        
                    finally:
                        heartbeat_task.cancel()
                        bluetooth_task.cancel()
                        wifi_task.cancel()
                        syslog_task.cancel()
                        
            except Exception as e:
                self.reconnect_attempts += 1
                logger.error(f"Connection error (attempt {self.reconnect_attempts}): {e}")
                
                if self.reconnect_attempts < self.max_reconnect_attempts:
                    logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                    await asyncio.sleep(self.reconnect_delay)
                    self.reconnect_delay = min(self.reconnect_delay * 1.5, 60)
                else:
                    logger.error("Max reconnection attempts reached")
                    break
        
        self.running = False
    
    def run(self):
        """Run the agent"""
        logger.info("=" * 60)
        logger.info("Starting Enhanced Windows Endpoint Security Agent")
        logger.info("=" * 60)
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"Platform: {self.system_info.get('platform')}")
        logger.info(f"Hostname: {self.system_info.get('hostname')}")
        logger.info(f"Bluetooth Support: {BLEAK_AVAILABLE}")
        logger.info(f"WiFi Support: Enabled")
        logger.info(f"Syslog Collection: Enabled")
        logger.info(f"MAC Blocking: Enabled")
        logger.info("=" * 60)
        
        try:
            asyncio.run(self.connect())
        except KeyboardInterrupt:
            logger.info("Agent stopped by user")
        except Exception as e:
            logger.error(f"Agent error: {e}")
        finally:
            self.running = False
            logger.info("Agent shutdown complete")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Windows Endpoint Security Agent')
    parser.add_argument('--controller', '--server', default='ws://192.168.1.14:8000',
                       help='Controller WebSocket URL (default: ws://192.168.1.14:8000)')
    parser.add_argument('--token', default='default_token_change_me',
                       help='Authentication token')
    parser.add_argument('--agent-id', default=None,
                       help='Agent ID (auto-generated if not provided)')
    parser.add_argument('--encrypt', action='store_true',
                       help='Enable message encryption (disabled by default for compatibility)')
    
    args = parser.parse_args()
    
    # Create and run agent
    agent = EnhancedWindowsAgent(
        controller_url=args.controller,
        auth_token=args.token,
        agent_id=args.agent_id,
        use_encryption=args.encrypt
    )
    
    agent.run()


if __name__ == "__main__":
    main()



