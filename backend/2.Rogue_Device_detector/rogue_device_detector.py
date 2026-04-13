#!/usr/bin/env python3
"""
Module 2: Rogue Device & Threat Detection
Advanced rogue device detection with IEEE 802.11 & 802.15.1 compliance
"""

import os
import json
import time
import sqlite3
import logging
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rogue_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RogueDevice:
    """Rogue device data structure"""
    device_id: str
    mac_address: str
    device_name: str
    device_type: str  # wifi, bluetooth
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    signal_strength: Optional[int] = None
    security_type: Optional[str] = None
    first_seen: str = None
    last_seen: str = None
    threat_level: str = "medium"  # low, medium, high, critical
    threat_reasons: List[str] = None
    is_rogue: bool = True
    confidence_score: float = 0.0
    vendor: Optional[str] = None
    frequency: Optional[int] = None
    channel: Optional[int] = None

@dataclass
class ThreatAlert:
    """Threat alert data structure"""
    alert_id: str
    timestamp: str
    threat_type: str
    severity: str
    device_mac: str
    device_name: str
    threat_details: Dict[str, Any]
    risk_score: float
    status: str = "active"
    source_module: str = "Module2"

class RogueDeviceDetector:
    """Advanced rogue device detection system"""
    
    def __init__(self, config_file: str = 'rogue_detection_config.json'):
        self.config = self._load_config(config_file)
        self.database_path = self.config.get('database_path', 'rogue_detection.db')
        self.known_devices = set()
        self.rogue_devices = {}
        self.threat_alerts = []
        self.detection_running = False
        self.last_scan_time = None
        
        # Detection rules - Enhanced for comprehensive rogue AP detection
        self.suspicious_ssids = [
            # Free/Public WiFi indicators (High Priority)
            'free', 'wifi', 'free wifi', 'open wifi', 'freewifi', 'free_wifi',
            'free wifi here', 'free wifi zone', 'free internet', 'free hotspot',
            'guest', 'public', 'hotspot', 'open', 'public wifi', 'public hotspot',
            'open network', 'open wifi', 'open internet', 'open hotspot',
            # Airport/Hotel/Public Place spoofing (High Priority)
            'airport', 'airport wifi', 'airport free wifi', 'airport wifi free',
            'hotel', 'hotel wifi', 'hotel free wifi', 'hotel guest wifi',
            'coffee', 'starbucks', 'mcdonalds', 'mcdonalds wifi', 'mcdonalds free wifi',
            'library', 'hospital', 'mall', 'station', 'train', 'bus', 'metro',
            # Common ISP/Provider spoofing (Medium Priority)
            'attwifi', 'xfinitywifi', 'comcast', 'verizon', 'spectrum', 'charter',
            'cox', 'optimum', 'frontier', 'centurylink', 'windstream',
            # Generic router names (Evil Twin indicators)
            'linksys', 'netgear', 'dlink', 'tplink', 'asus', 'belkin', 'cisco',
            'admin', 'router', 'default', 'setup', 'config', 'test', 'demo',
            # Suspicious patterns (Medium Priority)
            'secure', 'login', 'network', 'wireless', 'internet', 'wifi setup',
            'connect', 'access', 'web', 'portal', 'captive', 'redirect',
            # Common honeypot names
            'honeypot', 'honey', 'trap', 'bait', 'fake', 'spoof', 'clone'
        ]
        
        self.suspicious_vendors = [
            'unknown', 'private', 'randomized', 'locally administered'
        ]
        
        # MAC address patterns for detection
        self.mac_patterns = {
            'randomized': re.compile(r'^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$'),
            'locally_administered': re.compile(r'^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$')
        }
        
        # Allowed Corporate Vendors (Rule 4)
        self.allowed_vendors = ['cisco', 'ubiquiti', 'huawei', 'tp-link', 'aruba', 'juniper', 'mist', 'fortinet']
        
        # Device History for MAC Loop Detection (Rule 7)
        self.device_history = {}  # {device_name: [list_of_macs]}
        
        # Suspicious Bluetooth Keywords (Rule 6 + Recommendations)
        self.suspicious_bluetooth_keywords = [
            'flipper', 'zero', 'pwnagotchi', 'pineapple', 'rubber', 'ducky', 
            'badusb', 'hack', 'attack', 'clone', 'spy', 'sniff'
        ]
        
        # Initialize database
        self._init_database()
        
        # Load known devices
        self._load_known_devices()
        
        logger.info("Rogue Device Detector initialized")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            'database_path': 'rogue_detection.db',
            'scan_interval': 30,
            'threat_threshold': 0.7,
            'max_devices': 1000,
            'retention_days': 30,
            'module1_api_url': 'http://127.0.0.1:8000/api/scan/results',
            'detection_rules': {
                'check_open_networks': True,
                'check_suspicious_ssids': True,
                'check_mac_randomization': True,
                'check_signal_anomalies': True,
                'check_behavioral_patterns': True
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Could not load config file {config_file}: {e}")
        
        return default_config
    
    def _init_database(self):
        """Initialize SQLite database for rogue detection"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            # Known devices table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS known_devices (
                    device_id TEXT PRIMARY KEY,
                    mac_address TEXT UNIQUE,
                    device_name TEXT,
                    device_type TEXT,
                    ssid TEXT,
                    bssid TEXT,
                    vendor TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_trusted BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Rogue devices table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rogue_devices (
                    device_id TEXT PRIMARY KEY,
                    mac_address TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    ssid TEXT,
                    bssid TEXT,
                    signal_strength INTEGER,
                    security_type TEXT,
                    threat_level TEXT,
                    threat_reasons TEXT,
                    confidence_score REAL,
                    vendor TEXT,
                    frequency INTEGER,
                    channel INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    device_mac TEXT,
                    device_name TEXT,
                    threat_details TEXT,
                    risk_score REAL,
                    status TEXT DEFAULT 'active',
                    source_module TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Detection logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    device_mac TEXT,
                    message TEXT,
                    severity TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
        finally:
            conn.close()
    
    def _load_known_devices(self):
        """Load known/trusted devices from database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT mac_address FROM known_devices WHERE is_trusted = 1")
            self.known_devices = {row[0] for row in cursor.fetchall()}
            logger.info(f"Loaded {len(self.known_devices)} known devices")
        except Exception as e:
            logger.error(f"Error loading known devices: {e}")
        finally:
            conn.close()
    
    def _get_module1_data(self) -> Dict[str, Any]:
        """Fetch latest scan data from Module 1 API"""
        # DEMO MODE: Check for simulation file
        sim_file = 'simulation_data.json'
        if os.path.exists(sim_file):
            try:
                with open(sim_file, 'r') as f:
                    data = json.load(f)
                logger.info("DEMO MODE: Loaded simulation data from " + sim_file)
                return data
            except Exception as e:
                logger.error(f"Failed to load simulation data: {e}")
        
        try:
            # First try direct access to global scan results (bypasses authentication)
            # First try direct access to global scan results (bypasses authentication)
            try:
                # Try to import from parent directory (backend)
                import sys
                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                from main import scan_results
                
                if scan_results:
                    data = scan_results
                    logger.info("Module 1 Data Retrieved via Direct Access")
                    
                    # Log all received data for monitoring
                    wifi_count = len(data.get('wifi_networks', []))
                    bluetooth_count = len(data.get('bluetooth_devices', []))
                    
                    logger.info(f"Module 1 Data Retrieved: {wifi_count} WiFi networks, {bluetooth_count} Bluetooth devices")
                    
                    # Log detailed device information
                    if data.get('wifi_networks'):
                        for i, network in enumerate(data['wifi_networks'][:5]):  # Log first 5
                            logger.info(f"WiFi Network {i+1}: {network.get('ssid', 'Unknown')} - {network.get('bssid', 'Unknown')} - {network.get('security', 'Unknown')}")
                    
                    if data.get('bluetooth_devices'):
                        for i, device in enumerate(data['bluetooth_devices'][:5]):  # Log first 5
                            logger.info(f"Bluetooth Device {i+1}: {device.get('name', 'Unknown')} - {device.get('address', 'Unknown')} - RSSI: {device.get('rssi', 'Unknown')}")
                    
                    return data
            except Exception as direct_error:
                logger.warning(f"Direct access failed: {direct_error}")
            
            # Fallback to API call
            response = requests.get(self.config['module1_api_url'], timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Log all received data for monitoring
                wifi_count = len(data.get('wifi_networks', []))
                bluetooth_count = len(data.get('bluetooth_devices', []))
                
                logger.info(f"Module 1 Data Retrieved via API: {wifi_count} WiFi networks, {bluetooth_count} Bluetooth devices")
                
                # Log detailed device information
                if data.get('wifi_networks'):
                    for i, network in enumerate(data['wifi_networks'][:5]):  # Log first 5
                        logger.info(f"WiFi Network {i+1}: {network.get('ssid', 'Unknown')} - {network.get('bssid', 'Unknown')} - {network.get('security', 'Unknown')}")
                
                if data.get('bluetooth_devices'):
                    for i, device in enumerate(data['bluetooth_devices'][:5]):  # Log first 5
                        logger.info(f"Bluetooth Device {i+1}: {device.get('name', 'Unknown')} - {device.get('address', 'Unknown')} - RSSI: {device.get('rssi', 'Unknown')}")
                
                return data
            else:
                logger.warning(f"Module 1 API returned status {response.status_code}")
                return {}
        except Exception as e:
            logger.error(f"Error getting Module 1 data: {e}")
            return {}
    
    def _analyze_wifi_network(self, network: Dict[str, Any], all_networks: List[Dict[str, Any]] = None) -> List[str]:
        """Analyze WiFi network for rogue characteristics"""
        threats = []
        ssid = network.get('ssid', '').strip()
        ssid_lower = ssid.lower()
        bssid = network.get('bssid', '')
        signal = network.get('signal_strength', -100)
        security = network.get('security', '').lower()
        if self.config['detection_rules']['check_open_networks']:
            security = network.get('security', '').lower()
            if security in ['open', 'none', '']:
                threats.append("Open network detected")
        
        # Enhanced suspicious SSID detection
        if self.config['detection_rules']['check_suspicious_ssids']:
            # High priority suspicious patterns
            high_priority_patterns = [
                'free wifi', 'free wifi here', 'free wifi zone', 'free internet',
                'airport wifi', 'airport free wifi', 'hotel wifi', 'hotel free wifi',
                'open network', 'open wifi', 'public wifi', 'public hotspot',
                'mcdonalds wifi', 'mcdonalds free wifi', 'starbucks wifi'
            ]
            
            # Medium priority suspicious patterns
            medium_priority_patterns = [
                'free', 'wifi', 'guest', 'public', 'hotspot', 'open',
                'airport', 'hotel', 'coffee', 'library', 'hospital', 'mall',
                'attwifi', 'xfinitywifi', 'comcast', 'verizon', 'spectrum'
            ]
            
            # Check for high priority patterns (immediate rogue classification)
            for pattern in high_priority_patterns:
                if pattern in ssid_lower:
                    threats.append(f"HIGH PRIORITY Suspicious SSID: {ssid}")
                    break
            
            # Check for medium priority patterns
            if not any(pattern in ssid_lower for pattern in high_priority_patterns):
                for pattern in medium_priority_patterns:
                    if pattern in ssid_lower:
                        threats.append(f"MEDIUM PRIORITY Suspicious SSID: {ssid}")
                        break
        
        # 1. Evil Twin Detection (Rule 1)
        # Condition: Same SSID but different security, vendor, channel band, or signal diff > 30dBm
        if all_networks and len(all_networks) > 1:
            for other_network in all_networks:
                other_bssid = other_network.get('bssid', '').lower()
                current_bssid = bssid.lower()
                
                # Skip invalid BSSIDs to avoid false positives
                invalid_bssids = ['unknown', 'none', '', '00:00:00:00:00:00']
                if current_bssid in invalid_bssids or other_bssid in invalid_bssids:
                    continue
                
                if (other_bssid != current_bssid and 
                    other_network.get('ssid', '').strip() == ssid and 
                    ssid.strip()):
                    
                    other_security = other_network.get('security', '').lower()
                    other_signal = other_network.get('signal_strength', -100)
                    
                    is_open = lambda s: s in ['open', 'none', '']
                    
                    # Check Security Mismatch
                    if not is_open(security.lower()) and is_open(other_security):
                        # Use slightly different message to avoid duplication in loop
                        msg = f"EVIL TWIN: Open network mimicking encrypted SSID '{ssid}'"
                        if msg not in threats: threats.append(msg)
                    
                    # Check Signal Difference > 30dBm
                    signal_diff = abs(signal - other_signal)
                    if signal_diff > 30:
                        msg = f"EVIL TWIN: Signal anomaly ({signal_diff}dBm diff) for SSID '{ssid}'"
                        if msg not in threats: threats.append(msg)

        # 2. Open Network with Sensitive Name (Rule 2)
        # Condition: SSID includes Corp/Office etc BUT security is Open
        sensitive_keywords = ['corp', 'office', 'enterprise', 'admin', 'secure', 'internal', 'staff', 'finance']
        if list(filter(lambda k: k in ssid_lower, sensitive_keywords)):
            if security.lower() in ['open', 'none', '']:
                threats.append(f"HIGH RISK: Sensitive SSID '{ssid}' is Unsecured/Open")

        # 3. Hidden SSID + Very Strong RSSI (Rule 3)
        # Condition: SSID is empty/hidden AND RSSI >= -40 dBm
        if (not ssid or ssid_lower in ['hidden', '<hidden>', '', 'hidden network']):
            if signal >= -40:
                threats.append(f"SUSPICIOUS: Hidden AP with very strong signal ({signal}dBm)")
            else:
                threats.append("Hidden SSID network")

        # 4. Vendor / OUI Mismatch (Rule 4)
        # Condition: SSID matches environment but Vendor not in allowed list
        # We assume 'environment' means containing corporate keywords for this implementation
        if any(k in ssid_lower for k in sensitive_keywords):
            network_vendor = network.get('vendor', '').lower()
            if network_vendor and not any(av in network_vendor for av in self.allowed_vendors):
                 threats.append(f"VENDOR MISMATCH: Corporate SSID '{ssid}' with unexpected vendor '{network.get('vendor')}'")

        # 5. Channel Out-of-Place (Rule 5)
        # Condition: Illegal (12-14) or Unexpected channels
        try:
            ch = int(network.get('channel', 0))
            if ch in [12, 13, 14]:
                threats.append(f"ILLEGAL CHANNEL: AP on restricted channel {ch}")
            if ch == 165: # Example from rule
                threats.append(f"UNEXPECTED CHANNEL: AP on channel {ch}")
        except:
            pass
            
        return threats
    
    def _analyze_bluetooth_device(self, device: Dict[str, Any]) -> List[str]:
        """
        Enhanced Bluetooth device analysis for rogue characteristics
        Based on IEEE 802.15.1 and wireless security best practices
        """
        threats = []
        
        name = device.get('name', '').lower()
        mac = device.get('address', '')
        rssi = device.get('rssi', 0)
        manufacturer = device.get('manufacturer', '').lower()
        device_type = device.get('device_type', '').lower()
        services = device.get('services', [])
        
        # 6. Suspicious Bluetooth HID/Keyboard Impersonation (Rule 6)
        # Condition: Advertises HID (keyboard/mouse) unexpectedly
        # Implementation: "HID", "Input", "Keyboard" in service list AND RSSI > -50
        service_names = []
        if services:
            for s in services:
                if isinstance(s, dict): service_names.append(s.get('name', '').lower())
                else: service_names.append(str(s).lower())
        
        is_hid = any(k in str(services).lower() for k in ['hid', 'input', 'keyboard', 'human interface'])
        if is_hid:
            if rssi > -50:
                 threats.append("CRITICAL: Suspicious HID Device (Potential Rubber Ducky/Keylogger) nearby")
            else:
                 threats.append("Suspicious HID Device detected")

        # 7. MAC Randomization Spoof Loop (Rule 7)
        # Condition: Same device name/services but MAC changes multiple times in 3 mins
        if name and name not in ['unknown', '']:
            if name not in self.device_history:
                self.device_history[name] = []
            
            # Add current MAC and timestamp
            self.device_history[name].append({'mac': mac, 'time': time.time()})
            
            # Prune old entries (> 3 mins)
            cutoff = time.time() - 180
            self.device_history[name] = [entry for entry in self.device_history[name] if entry['time'] > cutoff]
            
            # Count unique MACs
            unique_macs = set(e['mac'] for e in self.device_history[name])
            if len(unique_macs) >= 3:
                threats.append(f"SPOOF LOOP: Device '{name}' changed MAC {len(unique_macs)} times in 3 mins")

        # 8. High RSSI Abnormality (Rule 8)
        # Condition: RSSI > -30 for unknown device
        is_unknown = name in ['unknown', 'unnamed', '', 'unknown ble device']
        if is_unknown and rssi > -30:
            threats.append("CRITICAL: Unknown device in extreme proximity (RSSI > -30dBm)")

        # 9. Suspicious Name Keywords (Enhanced)
        for keyword in self.suspicious_bluetooth_keywords:
            if keyword in name:
                threats.append(f"HIGH PRIORITY: Suspicious Bluetooth device name contains '{keyword}'")
                break
        
        # 10. Vendor Mismatch
        if 'samsung' in name and manufacturer not in ['unknown', 'samsung']:
            threats.append("Vendor mismatch: Device name doesn't match manufacturer")
        elif 'apple' in name or 'iphone' in name and manufacturer not in ['unknown', 'apple']:
             threats.append("Vendor mismatch: Apple device name but different manufacturer")
                
        # 1. Unknown/Unnamed Devices (Medium Priority)
        # Skip this check if it's a known reputable manufacturer (reduces false positive noise)
        trusted_manufacturers = ['apple', 'microsoft', 'samsung', 'google', 'intel', 'amazon']
        is_trusted_mfg = any(tm in manufacturer for tm in trusted_manufacturers)
        
        if (not name or name in ['unknown', 'unnamed', '', 'unknown ble device', 'unknown device']) and not is_trusted_mfg:
            threats.append("Unknown/Unnamed Bluetooth device (potential unauthorized device)")
        
        # 11. Unknown Manufacturer with Many Services
        if manufacturer == 'unknown' and services and len(services) > 5:
            threats.append("Unknown manufacturer with multiple services (potential attack device)")
        
        return threats
    
    def _check_mac_randomization(self, mac_address: str) -> bool:
        """Check if MAC address appears to be randomized"""
        if not mac_address:
            return False
        
        # Check if second character is 2, 6, A, or E (locally administered)
        if len(mac_address) >= 2:
            second_char = mac_address[1].upper()
            if second_char in ['2', '6', 'A', 'E']:
                return True
        
        return False
    
    def _calculate_threat_score(self, threats: List[str], device_type: str) -> float:
        """Calculate threat score based on detected threats"""
        base_score = 0.0
        
        for threat in threats:
            if "HIGH PRIORITY Suspicious SSID" in threat:
                base_score += 0.8  # High priority suspicious SSIDs are very concerning
            elif "DUPLICATE SSID DETECTED" in threat:
                base_score += 0.9  # Duplicate SSIDs are extremely concerning (Evil Twin)
            elif "MEDIUM PRIORITY Suspicious SSID" in threat:
                base_score += 0.5  # Medium priority suspicious SSIDs
            elif "Open network" in threat:
                base_score += 0.3
            elif "Hidden network" in threat:
                base_score += 0.5
            elif "Unknown" in threat:
                base_score += 0.3
            elif "Suspicious device name" in threat:
                base_score += 0.6
            elif "signal" in threat.lower():
                base_score += 0.2
            else:
                base_score += 0.3
        
        # Adjust for device type
        if device_type == 'wifi':
            base_score *= 1.2  # WiFi networks are more concerning
        
        return min(base_score, 1.0)
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level based on score"""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _store_rogue_device(self, device: RogueDevice):
        """Store rogue device in database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO rogue_devices 
                (device_id, mac_address, device_name, device_type, ssid, bssid,
                 signal_strength, security_type, threat_level, threat_reasons,
                 confidence_score, vendor, frequency, channel, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id,
                device.mac_address,
                device.device_name,
                device.device_type,
                device.ssid,
                device.bssid,
                device.signal_strength,
                device.security_type,
                device.threat_level,
                json.dumps(device.threat_reasons),
                device.confidence_score,
                device.vendor,
                device.frequency,
                device.channel,
                device.first_seen,
                device.last_seen
            ))
            
            conn.commit()
            logger.info(f"Stored rogue device: {device.device_id}")
            
        except Exception as e:
            logger.error(f"Error storing rogue device: {e}")
        finally:
            conn.close()
    
    def _store_threat_alert(self, alert: ThreatAlert):
        """Store threat alert in database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO threat_alerts 
                (alert_id, timestamp, threat_type, severity, device_mac, device_name,
                 threat_details, risk_score, status, source_module)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.timestamp,
                alert.threat_type,
                alert.severity,
                alert.device_mac,
                alert.device_name,
                json.dumps(alert.threat_details),
                alert.risk_score,
                alert.status,
                alert.source_module
            ))
            
            conn.commit()
            logger.info(f"Stored threat alert: {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error storing threat alert: {e}")
        finally:
            conn.close()
    
    def _log_detection_event(self, event_type: str, device_mac: str, message: str, severity: str = "INFO"):
        """Log detection event"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO detection_logs (timestamp, event_type, device_mac, message, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                event_type,
                device_mac,
                message,
                severity
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error logging detection event: {e}")
        finally:
            conn.close()
    
    def _store_monitoring_logs(self, monitoring_logs: List[Dict[str, Any]]):
        """Store comprehensive monitoring logs"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            # Create monitoring logs table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_type TEXT,
                    device_name TEXT,
                    mac_address TEXT,
                    threat_level TEXT,
                    is_rogue BOOLEAN,
                    message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert monitoring logs
            for log in monitoring_logs:
                cursor.execute("""
                    INSERT INTO monitoring_logs 
                    (timestamp, device_type, device_name, mac_address, threat_level, is_rogue, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    log['timestamp'],
                    log['device_type'],
                    log['device_name'],
                    log['mac_address'],
                    log['threat_level'],
                    log['is_rogue'],
                    log['message']
                ))
            
            conn.commit()
            logger.info(f"Stored {len(monitoring_logs)} monitoring logs")
            
        except Exception as e:
            logger.error(f"Error storing monitoring logs: {e}")
        finally:
            conn.close()
    
    def get_monitoring_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent monitoring logs"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT timestamp, device_type, device_name, mac_address, 
                       threat_level, is_rogue, message
                FROM monitoring_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'timestamp': row[0],
                    'device_type': row[1],
                    'device_name': row[2],
                    'mac_address': row[3],
                    'threat_level': row[4],
                    'is_rogue': bool(row[5]),
                    'message': row[6]
                })
            
            return logs
            
        except Exception as e:
            logger.error(f"Error getting monitoring logs: {e}")
            return []
        finally:
            conn.close()
    
    def get_all_devices_analysis(self) -> Dict[str, Any]:
        """Get comprehensive analysis of all devices"""
        return self.monitor_all_devices()
    
    def monitor_all_devices(self) -> Dict[str, Any]:
        """Monitor all devices from Module 1 and analyze each one"""
        logger.info("Starting comprehensive device monitoring")
        
        # Get data from Module 1
        module1_data = self._get_module1_data()
        if not module1_data:
            logger.warning("No data received from Module 1")
            return {
                'total_devices': 0,
                'wifi_networks': [],
                'bluetooth_devices': [],
                'rogue_devices': [],
                'monitoring_logs': [],
                'statistics': {}
            }
        
        current_time = datetime.now().isoformat()
        monitoring_logs = []
        all_devices_analysis = []
        
        # Analyze ALL WiFi networks
        wifi_networks = module1_data.get('wifi_networks', [])
        logger.info(f"Analyzing {len(wifi_networks)} WiFi networks")
        
        # Track BSSID/MAC duplicates for Evil Twin detection
        bssid_tracker = {}
        mac_tracker = {}
        ssid_tracker = {}
        
        for i, network in enumerate(wifi_networks):
            mac = network.get('bssid', f'wifi_{i}')
            ssid = network.get('ssid', 'Unknown')
            
            # Track for duplicate detection
            if mac:
                if mac not in bssid_tracker:
                    bssid_tracker[mac] = []
                bssid_tracker[mac].append(network)
            
            if ssid and ssid != 'Unknown':
                if ssid not in ssid_tracker:
                    ssid_tracker[ssid] = []
                ssid_tracker[ssid].append(network)
            
            # Analyze each network (pass all networks for duplicate SSID detection)
            threats = self._analyze_wifi_network(network, wifi_networks)
            
            # Add duplicate BSSID/MAC check
            if mac in bssid_tracker and len(bssid_tracker[mac]) > 1:
                threats.append("Duplicate BSSID detected (potential Evil Twin AP)")
            
            # Add duplicate SSID with different BSSID check
            if ssid in ssid_tracker and len(ssid_tracker[ssid]) > 1:
                different_bssids = len(set(n.get('bssid') for n in ssid_tracker[ssid]))
                if different_bssids > 1:
                    threats.append(f"Multiple APs with same SSID (Evil Twin / Rogue AP attack)")
            
            threat_score = self._calculate_threat_score(threats, 'wifi')
            threat_level = self._determine_threat_level(threat_score)
            
            is_rogue = threat_level in ['high', 'critical']
            
            # Create RogueDevice object
            device_id = hashlib.md5(f"{mac}_{ssid}".encode()).hexdigest()
            rogue_device = RogueDevice(
                device_id=device_id,
                mac_address=mac,
                device_name=ssid,
                device_type='wifi',
                ssid=ssid,
                bssid=mac,
                signal_strength=network.get('signal_strength'),
                security_type=network.get('security'),
                first_seen=current_time,
                last_seen=current_time,
                threat_level=threat_level,
                threat_reasons=threats,
                is_rogue=is_rogue,
                confidence_score=threat_score,
                vendor=network.get('vendor', 'Unknown'),
                frequency=network.get('frequency'),
                channel=network.get('channel')
            )
            
            # Store if rogue or suspicious
            if is_rogue or threat_level == 'medium':
                self._store_rogue_device(rogue_device)
                self.rogue_devices[device_id] = asdict(rogue_device)
                
                # Create alert for critical threats
                if threat_level == 'critical':
                    alert_id = f"ALERT_{int(time.time())}_{device_id[:8]}"
                    alert = ThreatAlert(
                        alert_id=alert_id,
                        timestamp=current_time,
                        threat_type="Rogue WiFi AP",
                        severity="CRITICAL",
                        device_mac=mac,
                        device_name=ssid,
                        threat_details={"reasons": threats},
                        risk_score=threat_score
                    )
                    self._store_threat_alert(alert)
                    self.threat_alerts.append(asdict(alert))
            
            # Add to monitoring logs
            log_entry = {
                'timestamp': current_time,
                'device_type': 'WiFi',
                'device_name': ssid,
                'mac_address': mac,
                'threat_level': threat_level,
                'is_rogue': is_rogue,
                'message': f"Scanned: {len(threats)} threats found"
            }
            monitoring_logs.append(log_entry)
            all_devices_analysis.append(asdict(rogue_device))
        
        # Analyze ALL Bluetooth devices
        bluetooth_devices = module1_data.get('bluetooth_devices', [])
        logger.info(f"Analyzing {len(bluetooth_devices)} Bluetooth devices")
        
        for i, device in enumerate(bluetooth_devices):
            mac = device.get('address', f'bt_{i}')
            name = device.get('name', 'Unknown')
            
            threats = self._analyze_bluetooth_device(device)
            threat_score = self._calculate_threat_score(threats, 'bluetooth')
            threat_level = self._determine_threat_level(threat_score)
            
            is_rogue = threat_level in ['high', 'critical']
            
            # Create RogueDevice object
            device_id = hashlib.md5(f"{mac}_{name}".encode()).hexdigest()
            rogue_device = RogueDevice(
                device_id=device_id,
                mac_address=mac,
                device_name=name,
                device_type='bluetooth',
                signal_strength=device.get('rssi'),
                first_seen=current_time,
                last_seen=current_time,
                threat_level=threat_level,
                threat_reasons=threats,
                is_rogue=is_rogue,
                confidence_score=threat_score,
                vendor=device.get('manufacturer', 'Unknown')
            )
            
            # Store if rogue or suspicious
            if is_rogue or threat_level == 'medium':
                self._store_rogue_device(rogue_device)
                self.rogue_devices[device_id] = asdict(rogue_device)
                
                # Create alert for critical threats
                if threat_level == 'critical':
                    alert_id = f"ALERT_{int(time.time())}_{device_id[:8]}"
                    alert = ThreatAlert(
                        alert_id=alert_id,
                        timestamp=current_time,
                        threat_type="Rogue Bluetooth Device",
                        severity="CRITICAL",
                        device_mac=mac,
                        device_name=name,
                        threat_details={"reasons": threats},
                        risk_score=threat_score
                    )
                    self._store_threat_alert(alert)
                    self.threat_alerts.append(asdict(alert))
            
            # Add to monitoring logs
            log_entry = {
                'timestamp': current_time,
                'device_type': 'Bluetooth',
                'device_name': name,
                'mac_address': mac,
                'threat_level': threat_level,
                'is_rogue': is_rogue,
                'message': f"Scanned: {len(threats)} threats found"
            }
            monitoring_logs.append(log_entry)
            all_devices_analysis.append(asdict(rogue_device))
        
        # Store monitoring logs
        self._store_monitoring_logs(monitoring_logs)
        
        return {
            'total_devices': len(all_devices_analysis),
            'wifi_networks': wifi_networks,
            'bluetooth_devices': bluetooth_devices,
            'rogue_devices': list(self.rogue_devices.values()),
            'monitoring_logs': monitoring_logs,
            'statistics': {
                'scanned_wifi': len(wifi_networks),
                'scanned_bluetooth': len(bluetooth_devices),
                'rogue_count': len(self.rogue_devices),
                'alert_count': len(self.threat_alerts)
            }
        }
    
    def get_rogue_devices(self) -> List[Dict[str, Any]]:
        """Get all detected rogue devices"""
        return list(self.rogue_devices.values())
    
    def get_threat_events(self) -> List[Dict[str, Any]]:
        """Get all threat events/alerts"""
        return self.threat_alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stats = {
            'total_rogue_devices': 0,
            'total_alerts': 0,
            'high_severity_alerts': 0,
            'wifi_threats': 0,
            'bluetooth_threats': 0
        }
        
        try:
            # Count rogue devices
            cursor.execute("SELECT COUNT(*) FROM rogue_devices")
            stats['total_rogue_devices'] = cursor.fetchone()[0]
            
            # Count alerts
            cursor.execute("SELECT COUNT(*) FROM threat_alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            # Count high severity alerts
            cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE severity = 'CRITICAL' OR severity = 'HIGH'")
            stats['high_severity_alerts'] = cursor.fetchone()[0]
            
            # Count by type
            cursor.execute("SELECT COUNT(*) FROM rogue_devices WHERE device_type = 'wifi'")
            stats['wifi_threats'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM rogue_devices WHERE device_type = 'bluetooth'")
            stats['bluetooth_threats'] = cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
        finally:
            conn.close()
            
        return stats

if __name__ == "__main__":
    # Test the detector
    detector = RogueDeviceDetector()
    print("Rogue Device Detector initialized")
    print(f"Known devices: {len(detector.known_devices)}")
    
    # Run a test analysis
    analysis = detector.monitor_all_devices()
    print(f"Analysis complete: {analysis['total_devices']} devices scanned")
    print(f"Rogue devices found: {len(analysis['rogue_devices'])}")
