#!/usr/bin/env python3
"""
Module 3: Real Packet Capture & Analysis System
Advanced packet sniffing and analysis for BWF Toolkit

Features:
- Real packet capture using Scapy and PyShark
- Integration with Module 1 network data
- Advanced anomaly detection
- Real-time packet analysis
- Actual PCAP file generation
- Network interface monitoring
"""

import os
import sys
import time
import json
import sqlite3
import threading
import subprocess
import platform
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable
import logging
from collections import defaultdict, deque
import hashlib
import csv

# Third-party imports for real packet capture
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.bluetooth import *
    import psutil
    SCAPY_AVAILABLE = True
    try:
        import netifaces
        NETIFACES_AVAILABLE = True
    except ImportError:
        NETIFACES_AVAILABLE = False
        print("netifaces not available - using alternative interface detection")
except ImportError as e:
    import traceback
    traceback.print_exc()
    print(f"Scapy not available: {e}")
    SCAPY_AVAILABLE = False
    NETIFACES_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print("PyShark not available")
    PYSHARK_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'module3_packet_capture.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealPacketCapture:
    """Real packet capture and analysis system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.db_path = self.config.get('database_path', 'real_packet_capture.db')
        self.capture_dir = self.config.get('capture_dir', './captures')
        self.running = False
        self.capture_threads = []
        self.packet_buffer = deque(maxlen=10000)  # Buffer for real-time analysis
        self.anomaly_detector = RealAnomalyDetector()
        self.network_monitor = NetworkInterfaceMonitor()
        
        # Create capture directory
        os.makedirs(self.capture_dir, exist_ok=True)
        
        # Initialize database
        self._initialize_database()
        
        # Get Module 1 network data (Wi‑Fi SSIDs/BSSIDs and named BLE devices)
        self.module1_networks = self._get_module1_networks()
        
        logger.info("Real Packet Capture system initialized")
    
    def _initialize_database(self):
        """Initialize database for real packet metadata"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create comprehensive packet metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packet_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_mac TEXT,
                    dst_mac TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    bssid TEXT,
                    ssid TEXT,
                    frame_type TEXT,
                    packet_size INTEGER,
                    rssi INTEGER,
                    channel INTEGER,
                    frequency INTEGER,
                    encryption TEXT,
                    packet_info TEXT,
                    flags TEXT,
                    pcap_file TEXT,
                    sha256_hash TEXT UNIQUE,
                    is_anomaly BOOLEAN DEFAULT 0,
                    anomaly_type TEXT,
                    anomaly_score REAL,
                    real_source TEXT DEFAULT 'packet_capture',
                    interface_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create anomaly detection results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    packet_count INTEGER,
                    affected_networks TEXT,
                    affected_devices TEXT,
                    detection_method TEXT,
                    confidence_score REAL,
                    mitigation_recommendations TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create network statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    total_packets INTEGER,
                    total_bytes INTEGER,
                    protocol_distribution TEXT,
                    top_talkers TEXT,
                    bandwidth_utilization REAL,
                    error_rate REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def _get_module1_networks(self) -> List[Dict[str, Any]]:
        """Get network data from Module 1"""
        try:
            # Try to import and get data from Module 1
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from main import scan_results
            
            if scan_results:
                wifi_networks = scan_results.get('wifi_networks', [])
                # Only include named bluetooth devices per Module 1 policy
                bluetooth_devices = [d for d in scan_results.get('bluetooth_devices', []) if d.get('name','').strip()]
                
                # Convert to unified format for packet capture targeting
                networks = []
                
                # Add WiFi networks
                for network in wifi_networks:
                    networks.append({
                        'type': 'wifi',
                        'ssid': network.get('ssid', ''),
                        'bssid': network.get('bssid', ''),
                        'channel': network.get('channel', 0),
                        'frequency': network.get('frequency', 0),
                        'security': network.get('security', ''),
                        'signal_strength': network.get('signal_strength', 0)
                    })
                
                # Add Bluetooth devices
                for device in bluetooth_devices:
                    networks.append({
                        'type': 'bluetooth',
                        'address': device.get('address', ''),
                        'name': device.get('name', ''),
                        'rssi': device.get('rssi', 0),
                        'services': device.get('services', [])
                    })
                
                logger.info(f"Retrieved {len(networks)} networks from Module 1")
                return networks
            else:
                logger.warning("No Module 1 data available")
                return []
                
        except Exception as e:
            logger.error(f"Error getting Module 1 networks: {e}")
            return []

    def refresh_module1_networks(self, scan_results: Dict[str, Any]) -> None:
        """Refresh cached Module 1 networks from provided scan_results"""
        try:
            networks: List[Dict[str, Any]] = []
            wifi_networks = scan_results.get('wifi_networks', []) if isinstance(scan_results, dict) else []
            bluetooth_devices = [d for d in scan_results.get('bluetooth_devices', []) if d.get('name','').strip()] if isinstance(scan_results, dict) else []
            for network in wifi_networks:
                networks.append({
                    'type': 'wifi',
                    'ssid': network.get('ssid', ''),
                    'bssid': network.get('bssid', ''),
                    'channel': network.get('channel', 0),
                    'frequency': network.get('frequency', 0),
                    'security': network.get('security', ''),
                    'signal_strength': network.get('signal_strength', 0)
                })
            for device in bluetooth_devices:
                networks.append({
                    'type': 'bluetooth',
                    'address': device.get('address', ''),
                    'name': device.get('name', ''),
                    'rssi': device.get('rssi', 0),
                    'services': device.get('services', [])
                })
            self.module1_networks = networks
            logger.info(f"Refreshed Module 1 networks for capture targeting: {len(networks)} items")
        except Exception as e:
            logger.error(f"Error refreshing Module 1 networks: {e}")
    
    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """Get real network interfaces from the system"""
        try:
            interfaces = []
            
            if NETIFACES_AVAILABLE:
                # Use netifaces if available
                for interface in netifaces.interfaces():
                    # Filter out p2p-dev interfaces and other virtual interfaces
                    if interface.startswith('p2p-dev-') or interface.startswith('docker') or interface.startswith('br-'):
                        continue
                    try:
                        # Get interface details
                        addrs = netifaces.ifaddresses(interface)
                        interface_info = {
                            'name': interface,
                            'type': 'unknown',
                            'status': 'unknown',
                            'mac_address': '',
                            'ip_addresses': [],
                            'supports_promiscuous': False
                        }
                        
                        # Determine interface type
                        if interface.startswith('wlan') or interface.startswith('wifi') or 'wireless' in interface.lower():
                            interface_info['type'] = 'Wi-Fi'
                        elif interface.startswith('eth') or interface.startswith('en') or 'ethernet' in interface.lower():
                            interface_info['type'] = 'Ethernet'
                        elif interface.startswith('lo') or interface == 'loopback':
                            interface_info['type'] = 'Loopback'
                        elif interface.startswith('bluetooth') or interface.startswith('bt'):
                            interface_info['type'] = 'Bluetooth'
                        
                        # Get MAC address
                        if netifaces.AF_LINK in addrs:
                            interface_info['mac_address'] = addrs[netifaces.AF_LINK][0].get('addr', '')
                        
                        # Get IP addresses
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                interface_info['ip_addresses'].append(addr.get('addr', ''))
                        
                        # Check if interface supports promiscuous mode
                        interface_info['supports_promiscuous'] = self._check_promiscuous_support(interface)
                        
                        # Check interface status
                        interface_info['status'] = self._get_interface_status(interface)
                        
                        interfaces.append(interface_info)
                        
                    except Exception as e:
                        logger.warning(f"Error getting details for interface {interface}: {e}")
                        continue
            else:
                # Alternative method using psutil and system commands
                interfaces = self._get_interfaces_alternative()
            
            # Enhanced interface detection using system commands
            interfaces.extend(self._detect_wireless_interfaces())
            
            logger.info(f"Found {len(interfaces)} network interfaces")
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []
    
    def _detect_wireless_interfaces(self) -> List[Dict[str, Any]]:
        """Detect wireless interfaces using system commands"""
        try:
            wireless_interfaces = []
            
            if platform.system() == "Linux":
                # Use iw to detect wireless interfaces
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_interface = None
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('Interface'):
                            # Extract interface name
                            interface_name = line.split()[1]
                            current_interface = {
                                'name': interface_name,
                                'type': 'Wi-Fi',
                                'status': 'Active',
                                'mac_address': '',
                                'ip_addresses': [],
                                'supports_promiscuous': True,
                                'supports_monitor': True
                            }
                            wireless_interfaces.append(current_interface)
                        elif current_interface and 'addr' in line:
                            # Extract MAC address
                            mac_addr = line.split('addr')[1].strip()
                            current_interface['mac_address'] = mac_addr
                
                # Also check for Bluetooth interfaces
                bt_result = subprocess.run(['hciconfig'], capture_output=True, text=True, timeout=5)
                if bt_result.returncode == 0:
                    for line in bt_result.stdout.split('\n'):
                        if 'hci' in line and 'UP' in line:
                            interface_name = line.split(':')[0].strip()
                            wireless_interfaces.append({
                                'name': interface_name,
                                'type': 'Bluetooth',
                                'status': 'Active',
                                'mac_address': '',
                                'ip_addresses': [],
                                'supports_promiscuous': False,
                                'supports_monitor': False
                            })
            
            return wireless_interfaces
            
        except Exception as e:
            logger.warning(f"Error detecting wireless interfaces: {e}")
            return []
    
    def _get_interfaces_alternative(self) -> List[Dict[str, Any]]:
        """Alternative method to get network interfaces without netifaces"""
        try:
            interfaces = []
            
            # Use psutil to get network interfaces
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface_name in net_io.keys():
                try:
                    interface_info = {
                        'name': interface_name,
                        'type': 'unknown',
                        'status': 'Active',
                        'mac_address': '',
                        'ip_addresses': [],
                        'supports_promiscuous': True  # Assume support
                    }
                    
                    # Determine interface type based on name
                    if 'wlan' in interface_name.lower() or 'wifi' in interface_name.lower() or 'wireless' in interface_name.lower():
                        interface_info['type'] = 'Wi-Fi'
                    elif 'eth' in interface_name.lower() or 'ethernet' in interface_name.lower():
                        interface_info['type'] = 'Ethernet'
                    elif 'lo' in interface_name.lower() or 'loopback' in interface_name.lower():
                        interface_info['type'] = 'Loopback'
                    elif 'bluetooth' in interface_name.lower() or 'bt' in interface_name.lower():
                        interface_info['type'] = 'Bluetooth'
                    else:
                        interface_info['type'] = 'Network'
                    
                    # Try to get IP addresses using system commands
                    try:
                        if platform.system() == "Windows":
                            # Use netsh on Windows
                            result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'address', interface_name], 
                                                  capture_output=True, text=True)
                            if result.returncode == 0:
                                # Parse IP addresses from netsh output
                                lines = result.stdout.split('\n')
                                for line in lines:
                                    if 'IP Address' in line and ':' in line:
                                        ip = line.split(':')[1].strip()
                                        if ip and ip != '0.0.0.0':
                                            interface_info['ip_addresses'].append(ip)
                        else:
                            # Use ip command on Linux
                            result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                                                  capture_output=True, text=True)
                            if result.returncode == 0:
                                # Parse IP addresses from ip output
                                lines = result.stdout.split('\n')
                                for line in lines:
                                    if 'inet ' in line and not '127.0.0.1' in line:
                                        parts = line.split()
                                        if len(parts) >= 2:
                                            ip = parts[1].split('/')[0]
                                            interface_info['ip_addresses'].append(ip)
                    except Exception:
                        pass  # Continue without IP addresses
                    
                    interfaces.append(interface_info)
                    
                except Exception as e:
                    logger.warning(f"Error processing interface {interface_name}: {e}")
                    continue
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error in alternative interface detection: {e}")
            return []
    
    def _check_promiscuous_support(self, interface: str) -> bool:
        """Check if interface supports promiscuous mode"""
        try:
            if platform.system() == "Windows":
                # On Windows, check if we can set promiscuous mode
                return True  # Assume support for now
            else:
                # On Linux/Mac, check interface capabilities
                try:
                    result = subprocess.run(['ethtool', interface], capture_output=True, text=True)
                    return 'Promiscuous' in result.stdout
                except:
                    return True  # Assume support if ethtool not available
        except:
            return True
    
    def _get_interface_status(self, interface: str) -> str:
        """Get real interface status"""
        try:
            if platform.system() == "Windows":
                # Use netsh on Windows
                result = subprocess.run(['netsh', 'interface', 'show', 'interface', interface], 
                                      capture_output=True, text=True)
                if 'Enabled' in result.stdout:
                    return 'Active'
                else:
                    return 'Inactive'
            else:
                # Use ip command on Linux
                result = subprocess.run(['ip', 'link', 'show', interface], 
                                      capture_output=True, text=True)
                if 'UP' in result.stdout:
                    return 'Active'
                else:
                    return 'Inactive'
        except:
            return 'Unknown'
    
    def start_capture(self, interfaces: List[str] = None, duration: int = 300) -> bool:
        """Start real packet capture on specified interfaces"""
        try:
            if self.running:
                logger.warning("Capture already running")
                return False
            
            if not SCAPY_AVAILABLE:
                logger.error("Scapy not available - cannot perform packet capture")
                return False
            
            self.running = True
            
            # Get interfaces to capture on
            if not interfaces:
                available_interfaces = self.get_available_interfaces()
                interfaces = [iface['name'] for iface in available_interfaces 
                            if iface['status'] == 'Active' and iface['supports_promiscuous']]
            
            if not interfaces:
                logger.error("No suitable interfaces found for capture")
                self.running = False
                return False
            
            # Configure anomaly detector with local MACs to prevent self-detection
            try:
                local_macs = []
                all_interfaces = self.get_available_interfaces()
                for iface in all_interfaces:
                    if iface.get('mac_address'):
                        local_macs.append(iface['mac_address'])
                self.anomaly_detector.set_local_macs(local_macs)
            except Exception as e:
                logger.warning(f"Failed to set local MACs for anomaly detector: {e}")

            logger.info(f"Starting packet capture on interfaces: {interfaces}")
            
            # Start capture threads for each interface
            for interface in interfaces:
                capture_thread = threading.Thread(
                    target=self._capture_interface,
                    args=(interface, duration),
                    daemon=True
                )
                capture_thread.start()
                self.capture_threads.append(capture_thread)
            
            # Start real-time analysis thread
            analysis_thread = threading.Thread(
                target=self._real_time_analysis,
                daemon=True
            )
            analysis_thread.start()
            self.capture_threads.append(analysis_thread)
            
            logger.info("Packet capture started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            self.running = False
            return False
    
    def _capture_interface(self, interface: str, duration: int):
        """Capture packets on a specific interface with proper monitor mode configuration"""
        try:
            logger.info(f"Starting capture on interface: {interface}")
            
            # Generate PCAP filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = f"capture_{interface}_{timestamp}.pcap"
            pcap_path = os.path.join(self.capture_dir, pcap_filename)
            
            # Create packet processor
            packet_processor = PacketProcessor(interface, pcap_path, self.packet_buffer, list(self.module1_networks))
            
            # Configure interface for optimal packet capture
            self._configure_interface_for_capture(interface)
            
            # Start packet capture with enhanced Scapy configuration
            try:
                # Use more robust sniffing with proper error handling
                sniff(
                    iface=interface,
                    prn=packet_processor.process_packet,
                    timeout=duration,
                    store=False,  # Don't store packets in memory, process in real-time
                    monitor=True,  # Enable monitor mode if supported
                    promisc=True,  # Enable promiscuous mode
                    filter="",  # Capture all packets
                    stop_filter=lambda x: False  # Continue until timeout
                )
            except Exception as sniff_error:
                logger.warning(f"Advanced sniffing failed for {interface}, trying basic mode: {sniff_error}")
                # Fallback to basic sniffing
                sniff(
                    iface=interface,
                    prn=packet_processor.process_packet,
                    timeout=duration,
                    store=False
                )
            
            logger.info(f"Capture completed on interface: {interface}")
            
        except Exception as e:
            logger.error(f"Error capturing on interface {interface}: {e}")
    
    def _configure_interface_for_capture(self, interface: str):
        """Configure network interface for optimal packet capture"""
        try:
            if platform.system() == "Linux":
                # Set interface to promiscuous mode
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'on'], 
                             capture_output=True, check=False)
                
                # Bring interface up
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                             capture_output=True, check=False)
                
                # For WiFi interfaces, try to set monitor mode
                if interface.startswith('wl') or 'wifi' in interface.lower():
                    try:
                        # Try to set monitor mode (requires proper drivers)
                        subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'control'], 
                                     capture_output=True, check=False)
                        logger.info(f"Attempted to set monitor mode on {interface}")
                    except Exception as monitor_error:
                        logger.warning(f"Monitor mode not available for {interface}: {monitor_error}")
                
                logger.info(f"Configured interface {interface} for packet capture")
                
        except Exception as e:
            logger.warning(f"Interface configuration failed for {interface}: {e}")
    
    def _real_time_analysis(self):
        """Real-time packet analysis and anomaly detection"""
        try:
            logger.info("Starting real-time packet analysis")
            
            while self.running:
                if self.packet_buffer:
                    # Process buffered packets
                    packets_to_analyze = []
                    while self.packet_buffer:
                        packets_to_analyze.append(self.packet_buffer.popleft())
                    
                    # Analyze packets for anomalies
                    anomalies = self.anomaly_detector.analyze_packets(packets_to_analyze)
                    
                    # Store anomalies in database
                    if anomalies:
                        self._store_anomalies(anomalies)
                    
                    # Update network statistics
                    self._update_network_statistics(packets_to_analyze)
                
                time.sleep(1)  # Check every second
            
            logger.info("Real-time analysis stopped")
            
        except Exception as e:
            logger.error(f"Error in real-time analysis: {e}")
    
    def _store_anomalies(self, anomalies: List[Dict[str, Any]]):
        """Store detected anomalies in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for anomaly in anomalies:
                cursor.execute("""
                    INSERT INTO anomaly_results 
                    (timestamp, anomaly_type, severity, description, packet_count, 
                     affected_networks, affected_devices, detection_method, confidence_score, 
                     mitigation_recommendations)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    anomaly.get('timestamp', datetime.now().isoformat()),
                    anomaly.get('type', 'UNKNOWN'),
                    anomaly.get('severity', 'MEDIUM'),
                    anomaly.get('description', ''),
                    anomaly.get('packet_count', 0),
                    json.dumps(anomaly.get('affected_networks', [])),
                    json.dumps(anomaly.get('affected_devices', [])),
                    anomaly.get('detection_method', 'REAL_TIME_ANALYSIS'),
                    anomaly.get('confidence_score', 0.5),
                    json.dumps(anomaly.get('mitigation_recommendations', []))
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Stored {len(anomalies)} anomalies in database")
            
        except Exception as e:
            logger.error(f"Error storing anomalies: {e}")
    
    def _update_network_statistics(self, packets: List[Any]):
        """Update network statistics based on captured packets"""
        try:
            if not packets:
                return
            
            # Calculate statistics
            total_packets = len(packets)
            total_bytes = sum(len(packet) for packet in packets if hasattr(packet, '__len__'))
            
            # Protocol distribution
            protocol_dist = defaultdict(int)
            for packet in packets:
                if hasattr(packet, 'type'):
                    protocol_dist[packet.type] += 1
            
            # Top talkers (MAC addresses)
            mac_counts = defaultdict(int)
            for packet in packets:
                if hasattr(packet, 'src'):
                    mac_counts[packet.src] += 1
                if hasattr(packet, 'dst'):
                    mac_counts[packet.dst] += 1
            
            top_talkers = dict(sorted(mac_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            
            # Store statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO network_statistics 
                (timestamp, interface_name, total_packets, total_bytes, 
                 protocol_distribution, top_talkers, bandwidth_utilization, error_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                'multiple',  # Will be updated per interface
                total_packets,
                total_bytes,
                json.dumps(dict(protocol_dist)),
                json.dumps(top_talkers),
                0.0,  # Will be calculated
                0.0   # Will be calculated
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating network statistics: {e}")
    
    def stop_capture(self) -> bool:
        """Stop packet capture"""
        try:
            if not self.running:
                logger.warning("Capture not running")
                return False
            
            self.running = False
            
            # Wait for threads to finish
            for thread in self.capture_threads:
                thread.join(timeout=5)
            
            self.capture_threads.clear()
            
            logger.info("Packet capture stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            return False
    
    def get_capture_status(self) -> Dict[str, Any]:
        """Get real capture status"""
        try:
            # Get packet count from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM packet_metadata")
            packet_count = cursor.fetchone()[0]
            
            # Get recent packet count (last hour)
            one_hour_ago = datetime.now() - timedelta(hours=1)
            cursor.execute("SELECT COUNT(*) FROM packet_metadata WHERE timestamp > ?", 
                          (one_hour_ago.isoformat(),))
            recent_count = cursor.fetchone()[0]
            
            # Get anomaly count
            cursor.execute("SELECT COUNT(*) FROM anomaly_results")
            anomaly_count = cursor.fetchone()[0]
            
            # Get PCAP files
            pcap_files = []
            if os.path.exists(self.capture_dir):
                pcap_files = [f for f in os.listdir(self.capture_dir) if f.endswith('.pcap')]
            
            conn.close()
            
            return {
                "running": self.running,
                "total_packets": packet_count,
                "recent_packets": recent_count,
                "anomalies_detected": anomaly_count,
                "pcap_files": len(pcap_files),
                "capture_directory": self.capture_dir,
                "database_path": self.db_path,
                "interfaces_monitored": len(self.capture_threads) - 1,  # Subtract analysis thread
                "real_data_only": True
            }
            
        except Exception as e:
            logger.error(f"Error getting capture status: {e}")
            return {
                "running": False,
                "error": str(e),
                "real_data_only": True
            }
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent captured packets from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM packet_metadata 
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            
            columns = [description[0] for description in cursor.description]
            packets = []
            
            for row in cursor.fetchall():
                packet = dict(zip(columns, row))
                packets.append(packet)
            
            conn.close()
            return packets
            
        except Exception as e:
            logger.error(f"Error getting recent packets: {e}")
            return []
    
    def get_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get detected anomalies from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM anomaly_results 
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            
            columns = [description[0] for description in cursor.description]
            anomalies = []
            
            for row in cursor.fetchall():
                anomaly = dict(zip(columns, row))
                # Parse JSON fields
                try:
                    anomaly['affected_networks'] = json.loads(anomaly.get('affected_networks', '[]'))
                    anomaly['affected_devices'] = json.loads(anomaly.get('affected_devices', '[]'))
                    anomaly['mitigation_recommendations'] = json.loads(anomaly.get('mitigation_recommendations', '[]'))
                except:
                    pass
                anomalies.append(anomaly)
            
            conn.close()
            return anomalies
            
        except Exception as e:
            logger.error(f"Error getting anomalies: {e}")
            return []
    
    def export_data(self, format_type: str = "csv", hours: int = 24) -> Optional[str]:
        """Export captured data in specified format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format_type.lower() == "csv":
                filename = f"real_packet_capture_{timestamp}.csv"
                filepath = os.path.join(self.capture_dir, filename)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get recent data
                cutoff_time = datetime.now() - timedelta(hours=hours)
                cursor.execute("SELECT * FROM packet_metadata WHERE timestamp > ?", 
                              (cutoff_time.isoformat(),))
                
                columns = [description[0] for description in cursor.description]
                rows = cursor.fetchall()
                
                conn.close()
                
                # Write CSV
                with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(columns)
                    writer.writerows(rows)
                
                logger.info(f"Exported data to {filepath}")
                return filename
                
            elif format_type.lower() == "json":
                filename = f"real_packet_capture_{timestamp}.json"
                filepath = os.path.join(self.capture_dir, filename)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cutoff_time = datetime.now() - timedelta(hours=hours)
                cursor.execute("SELECT * FROM packet_metadata WHERE timestamp > ?", 
                              (cutoff_time.isoformat(),))
                
                columns = [description[0] for description in cursor.description]
                rows = cursor.fetchall()
                
                conn.close()
                
                # Convert to JSON
                data = [dict(zip(columns, row)) for row in rows]
                
                with open(filepath, 'w', encoding='utf-8') as jsonfile:
                    json.dump(data, jsonfile, indent=2, default=str)
                
                logger.info(f"Exported data to {filepath}")
                return filename
            
            return None
            
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            return None


class PacketProcessor:
    """Process individual packets during capture"""
    
    def __init__(self, interface: str, pcap_path: str, packet_buffer: deque, targets: List[Dict[str, Any]]):
        self.interface = interface
        self.pcap_path = pcap_path
        self.packet_buffer = packet_buffer
        self.db_path = 'real_packet_capture.db'
        self.packet_count = 0
        self.targets = targets or []
    
    def process_packet(self, packet):
        """Process a single captured packet"""
        try:
            self.packet_count += 1
            
            # Add to buffer for real-time analysis
            self.packet_buffer.append(packet)
            
            # Extract packet metadata
            metadata = self._extract_packet_metadata(packet)

            # Tag packet against Module 1 targets (SSID/BSSID or BLE address)
            try:
                if self.targets:
                    matched_wifi = []
                    matched_bt = []
                    bssid = metadata.get('bssid') or metadata.get('src_mac') or ''
                    ssid = metadata.get('ssid', '')
                    src = metadata.get('src_mac', '')
                    dst = metadata.get('dst_mac', '')
                    for t in self.targets:
                        if t.get('type') == 'wifi':
                            tbssid = t.get('bssid','')
                            tssid = t.get('ssid','')
                            if tbssid and (tbssid.lower() == bssid.lower() or tbssid.lower() in [src.lower(), dst.lower()]):
                                matched_wifi.append({'ssid': tssid, 'bssid': tbssid})
                            elif tssid and ssid and tssid == ssid:
                                matched_wifi.append({'ssid': tssid, 'bssid': tbssid})
                        elif t.get('type') == 'bluetooth':
                            addr = t.get('address','')
                            if addr and addr.lower() in [src.lower(), dst.lower()]:
                                matched_bt.append({'address': addr, 'name': t.get('name','')})
                    if matched_wifi or matched_bt:
                        metadata['targets_matched'] = json.dumps({'wifi': matched_wifi, 'bluetooth': matched_bt})
                    else:
                        metadata['targets_matched'] = json.dumps({'wifi': [], 'bluetooth': []})
            except Exception:
                metadata['targets_matched'] = json.dumps({'wifi': [], 'bluetooth': []})
            
            # Store in database
            self._store_packet_metadata(metadata)
            
            # Write to PCAP file
            self._write_to_pcap(packet)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_metadata(self, packet) -> Dict[str, Any]:
        """Extract comprehensive metadata from packet"""
        try:
            metadata = {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'Unknown',
                'src_mac': '',
                'dst_mac': '',
                'src_ip': '',
                'dst_ip': '',
                'src_port': None,
                'dst_port': None,
                'bssid': '',
                'ssid': '',
                'frame_type': '',
                'packet_size': len(packet),
                'rssi': None,
                'channel': None,
                'frequency': None,
                'encryption': '',
                'packet_info': '',
                'flags': '',
                'interface_name': self.interface,
                'sha256_hash': ''
            }
            
            # Calculate packet hash
            packet_bytes = bytes(packet)
            metadata['sha256_hash'] = hashlib.sha256(packet_bytes).hexdigest()
            
            # Extract layer information
            if packet.haslayer(Ether):
                metadata['src_mac'] = packet[Ether].src
                metadata['dst_mac'] = packet[Ether].dst
                metadata['protocol'] = packet[Ether].type
            
            if packet.haslayer(IP):
                metadata['src_ip'] = packet[IP].src
                metadata['dst_ip'] = packet[IP].dst
                metadata['protocol'] = 'IP'
            
            if packet.haslayer(TCP):
                metadata['src_port'] = packet[TCP].sport
                metadata['dst_port'] = packet[TCP].dport
                metadata['protocol'] = 'TCP'
            
            if packet.haslayer(UDP):
                metadata['src_port'] = packet[UDP].sport
                metadata['dst_port'] = packet[UDP].dport
                metadata['protocol'] = 'UDP'
            
            # ARP specific information
            if packet.haslayer(ARP):
                metadata['protocol'] = 'ARP'
                metadata['src_ip'] = packet[ARP].psrc
                metadata['dst_ip'] = packet[ARP].pdst
                metadata['src_mac'] = packet[ARP].hwsrc
                metadata['dst_mac'] = packet[ARP].hwdst
                
                op = packet[ARP].op
                if op == 1:
                    metadata['frame_type'] = 'ARP Request'
                    metadata['packet_info'] = f"Who has {metadata['dst_ip']}? Tell {metadata['src_ip']}"
                elif op == 2:
                    metadata['frame_type'] = 'ARP Reply'
                    metadata['packet_info'] = f"{metadata['src_ip']} is at {metadata['src_mac']}"
                
                # DEBUG: Log ARP packet
                logger.info(f"DEBUG: Extracted ARP packet: {metadata['packet_info']} from {metadata['src_mac']}")
            
            # WiFi specific information
            if packet.haslayer(Dot11):
                metadata['protocol'] = 'Wi-Fi'
                metadata['bssid'] = packet[Dot11].addr3 if hasattr(packet[Dot11], 'addr3') else ''
                
                if packet.haslayer(Dot11Beacon):
                    metadata['frame_type'] = 'Beacon'
                    if hasattr(packet[Dot11Beacon], 'info'):
                        metadata['ssid'] = packet[Dot11Beacon].info.decode('utf-8', errors='ignore')
                elif packet.haslayer(Dot11ProbeReq):
                    metadata['frame_type'] = 'Probe Request'
                elif packet.haslayer(Dot11ProbeResp):
                    metadata['frame_type'] = 'Probe Response'
                elif packet.haslayer(Dot11AssoReq):
                    metadata['frame_type'] = 'Association Request'
                elif packet.haslayer(Dot11AssoResp):
                    metadata['frame_type'] = 'Association Response'
                
                # Extract signal strength if available
                if hasattr(packet[Dot11], 'dBm_AntSignal'):
                    metadata['rssi'] = packet[Dot11].dBm_AntSignal
            
            # Bluetooth specific information
            if packet.haslayer(Bluetooth):
                metadata['protocol'] = 'Bluetooth'
                metadata['frame_type'] = 'Bluetooth'
            
            # Create packet info string
            info_parts = []
            if metadata['src_mac']:
                info_parts.append(f"From: {metadata['src_mac']}")
            if metadata['dst_mac']:
                info_parts.append(f"To: {metadata['dst_mac']}")
            if metadata['frame_type']:
                info_parts.append(f"Type: {metadata['frame_type']}")
            if metadata['ssid']:
                info_parts.append(f"SSID: {metadata['ssid']}")
            
            metadata['packet_info'] = ', '.join(info_parts)

            # Derive channel/frequency if possible from radiotap (when present)
            try:
                if packet.haslayer(RadioTap):
                    if hasattr(packet[RadioTap], 'ChannelFrequency'):
                        metadata['frequency'] = int(packet[RadioTap].ChannelFrequency)
                    if hasattr(packet[RadioTap], 'Channel'):
                        metadata['channel'] = int(packet[RadioTap].Channel)
            except Exception:
                pass
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting packet metadata: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'Unknown',
                'packet_size': len(packet) if hasattr(packet, '__len__') else 0,
                'interface_name': self.interface,
                'packet_info': f'Error processing packet: {str(e)}',
                'sha256_hash': ''
            }
    
    def _store_packet_metadata(self, metadata: Dict[str, Any]):
        """Store packet metadata in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extend schema insert with optional targets_matched if column exists
            try:
                cursor.execute("PRAGMA table_info(packet_metadata)")
                cols = [r[1] for r in cursor.fetchall()]
                has_targets = 'targets_matched' in cols
            except Exception:
                has_targets = False

            if has_targets:
                cursor.execute("""
                INSERT OR IGNORE INTO packet_metadata 
                (timestamp, protocol, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                 bssid, ssid, frame_type, packet_size, rssi, channel, frequency, encryption,
                 packet_info, flags, pcap_file, sha256_hash, interface_name, targets_matched)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata['timestamp'], metadata['protocol'], metadata['src_mac'], 
                metadata['dst_mac'], metadata['src_ip'], metadata['dst_ip'],
                metadata['src_port'], metadata['dst_port'], metadata['bssid'], 
                metadata['ssid'], metadata['frame_type'], metadata['packet_size'],
                metadata['rssi'], metadata['channel'], metadata['frequency'],
                metadata['encryption'], metadata['packet_info'], metadata['flags'],
                os.path.basename(self.pcap_path), metadata['sha256_hash'], metadata['interface_name'],
                metadata.get('targets_matched','{}')
            ))
            else:
                cursor.execute("""
                INSERT OR IGNORE INTO packet_metadata 
                (timestamp, protocol, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                 bssid, ssid, frame_type, packet_size, rssi, channel, frequency, encryption,
                 packet_info, flags, pcap_file, sha256_hash, interface_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata['timestamp'], metadata['protocol'], metadata['src_mac'], 
                metadata['dst_mac'], metadata['src_ip'], metadata['dst_ip'],
                metadata['src_port'], metadata['dst_port'], metadata['bssid'], 
                metadata['ssid'], metadata['frame_type'], metadata['packet_size'],
                metadata['rssi'], metadata['channel'], metadata['frequency'],
                metadata['encryption'], metadata['packet_info'], metadata['flags'],
                os.path.basename(self.pcap_path), metadata['sha256_hash'], metadata['interface_name']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing packet metadata: {e}")
    
    def _write_to_pcap(self, packet):
        """Write packet to PCAP file"""
        try:
            # Use Scapy's wrpcap to append packet to file
            wrpcap(self.pcap_path, packet, append=True)
        except Exception as e:
            logger.error(f"Error writing packet to PCAP: {e}")


class RealAnomalyDetector:
    """Real anomaly detection based on actual packet analysis"""
    
    def __init__(self):
        self.packet_rates = defaultdict(lambda: deque(maxlen=100))
        self.protocol_counts = defaultdict(int)
        self.mac_counts = defaultdict(int)
        self.size_distribution = deque(maxlen=1000)
        self.anomaly_thresholds = {
            'packet_rate': 1000,  # packets per second
            'size_deviation': 3.0,  # standard deviations
            'protocol_ratio': 0.8,  # 80% of traffic
            'mac_frequency': 100,   # packets per minute
            'arp_rate': 5           # ARP packets per 10 seconds (from same source)
        }
        self.arp_traffic = defaultdict(lambda: {'count': 0, 'last_reset': datetime.now()})
        self.local_macs = set()

    def set_local_macs(self, macs: List[str]):
        """Set local MAC addresses to ignore"""
        self.local_macs = set(mac.lower() for mac in macs if mac)
        logger.info(f"Anomaly detector ignoring local MACs: {self.local_macs}")
    
    def analyze_packets(self, packets: List[Any]) -> List[Dict[str, Any]]:
        """Analyze packets for anomalies"""
        try:
            anomalies = []
            current_time = datetime.now()
            
            # Update statistics
            for packet in packets:
                self._update_statistics(packet)
            
            # Detect rate anomalies
            rate_anomalies = self._detect_rate_anomalies()
            anomalies.extend(rate_anomalies)
            
            # Detect size anomalies
            size_anomalies = self._detect_size_anomalies()
            anomalies.extend(size_anomalies)
            
            # Detect protocol anomalies
            protocol_anomalies = self._detect_protocol_anomalies()
            anomalies.extend(protocol_anomalies)
            
            # Detect MAC address anomalies
            mac_anomalies = self._detect_mac_anomalies()
            anomalies.extend(mac_anomalies)
            
            # Detect ARP spoofing anomalies
            arp_anomalies = self._detect_arp_anomalies()
            anomalies.extend(arp_anomalies)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error analyzing packets: {e}")
            return []
    
    def _update_statistics(self, packet):
        """Update internal statistics"""
        try:
            current_time = datetime.now()
            
            # Update packet rates
            if hasattr(packet, 'src'):
                self.packet_rates[packet.src].append(current_time)
            
            # Update protocol counts
            if hasattr(packet, 'type'):
                self.protocol_counts[packet.type] += 1
            
            # Update MAC counts
            if hasattr(packet, 'src'):
                self.mac_counts[packet.src] += 1
            if hasattr(packet, 'dst'):
                self.mac_counts[packet.dst] += 1
            
            # Update size distribution
            packet_size = len(packet) if hasattr(packet, '__len__') else 0
            self.size_distribution.append(packet_size)
            
            # Update ARP traffic
            # Use Scapy's haslayer to check for ARP
            if SCAPY_AVAILABLE and packet.haslayer(ARP) and hasattr(packet, 'src'):
                # Check if we should ignore this MAC (self-detection prevention)
                if packet.src.lower() in self.local_macs:
                    return

                src_mac = packet.src
                arp_data = self.arp_traffic[src_mac]
                
                # Reset every 10 seconds
                if (current_time - arp_data['last_reset']).total_seconds() > 10.0:
                    arp_data['count'] = 1
                    arp_data['last_reset'] = current_time
                else:
                    arp_data['count'] += 1
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def _detect_rate_anomalies(self) -> List[Dict[str, Any]]:
        """Detect packet rate anomalies"""
        anomalies = []
        try:
            current_time = datetime.now()
            
            for mac, times in self.packet_rates.items():
                # Count packets in last minute
                recent_times = [t for t in times if (current_time - t).total_seconds() <= 60]
                
                if len(recent_times) > self.anomaly_thresholds['packet_rate']:
                    anomalies.append({
                        'type': 'HIGH_PACKET_RATE',
                        'severity': 'HIGH',
                        'description': f'High packet rate detected from {mac}: {len(recent_times)} packets/minute',
                        'confidence_score': 0.8,
                        'affected_devices': [mac],
                        'detection_method': 'RATE_ANALYSIS',
                        'mitigation_recommendations': [
                            'Monitor device for suspicious activity',
                            'Check for potential DoS attack',
                            'Consider rate limiting'
                        ]
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting rate anomalies: {e}")
            return []
    
    def _detect_size_anomalies(self) -> List[Dict[str, Any]]:
        """Detect packet size anomalies"""
        anomalies = []
        try:
            if len(self.size_distribution) < 10:
                return anomalies
            
            sizes = list(self.size_distribution)
            mean_size = sum(sizes) / len(sizes)
            variance = sum((x - mean_size) ** 2 for x in sizes) / len(sizes)
            std_dev = variance ** 0.5
            
            # Check for unusually large or small packets
            for size in sizes:
                if abs(size - mean_size) > self.anomaly_thresholds['size_deviation'] * std_dev:
                    anomalies.append({
                        'type': 'SIZE_ANOMALY',
                        'severity': 'MEDIUM',
                        'description': f'Unusual packet size detected: {size} bytes (mean: {mean_size:.1f}, std: {std_dev:.1f})',
                        'confidence_score': 0.7,
                        'detection_method': 'STATISTICAL_ANALYSIS',
                        'mitigation_recommendations': [
                            'Investigate packet source',
                            'Check for potential fragmentation attacks'
                        ]
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting size anomalies: {e}")
            return []
    
    def _detect_protocol_anomalies(self) -> List[Dict[str, Any]]:
        """Detect protocol distribution anomalies"""
        anomalies = []
        try:
            total_packets = sum(self.protocol_counts.values())
            if total_packets == 0:
                return anomalies
            
            for protocol, count in self.protocol_counts.items():
                ratio = count / total_packets
                
                if ratio > self.anomaly_thresholds['protocol_ratio']:
                    anomalies.append({
                        'type': 'PROTOCOL_ANOMALY',
                        'severity': 'MEDIUM',
                        'description': f'Unusual protocol distribution: {protocol} represents {ratio:.1%} of traffic',
                        'confidence_score': 0.6,
                        'detection_method': 'PROTOCOL_ANALYSIS',
                        'mitigation_recommendations': [
                            'Monitor protocol usage patterns',
                            'Check for potential protocol-based attacks'
                        ]
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting protocol anomalies: {e}")
            return []
    
    def _detect_mac_anomalies(self) -> List[Dict[str, Any]]:
        """Detect MAC address anomalies"""
        anomalies = []
        try:
            current_time = datetime.now()
            
            for mac, count in self.mac_counts.items():
                if count > self.anomaly_thresholds['mac_frequency']:
                    anomalies.append({
                        'type': 'MAC_ANOMALY',
                        'severity': 'HIGH',
                        'description': f'Unusual MAC address activity: {mac} has {count} packets',
                        'confidence_score': 0.8,
                        'affected_devices': [mac],
                        'detection_method': 'MAC_FREQUENCY_ANALYSIS',
                        'mitigation_recommendations': [
                            'Verify device identity',
                            'Check for MAC spoofing',
                            'Monitor device behavior'
                        ]
                    })
            
            return anomalies
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting MAC anomalies: {e}")
            return []

    def _detect_arp_anomalies(self) -> List[Dict[str, Any]]:
        """Detect ARP spoofing anomalies"""
        anomalies = []
        try:
            for mac, data in self.arp_traffic.items():
                if data['count'] > self.anomaly_thresholds['arp_rate']:
                    # Create anomaly compatible with Module 4's expectation
                    # Module 4 looks for 'ARP_SPOOF' in alert_type or 'ARP' in protocol
                    # Here we set type to 'ARP_SPOOF' to match
                    
                    anomalies.append({
                        'type': 'ARP_SPOOF', # Matches Module 4 check
                        'severity': 'CRITICAL',
                        'description': f"Suspicious ARP activity ({data['count']} packets) from {mac} - potential ARP poisoning.",
                        'confidence_score': 0.9,
                        'affected_devices': [mac],
                        'detection_method': 'ARP_RATE_ANALYSIS',
                        'mitigation_recommendations': [
                            'Investigate ARP table integrity',
                            'Block suspicious source MAC',
                            'Check for Man-in-the-Middle attacks'
                        ]
                    })
                    
                    # Reset count to avoid flooding alerts for the same window
                    data['count'] = 0
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting ARP anomalies: {e}")
            return []


class NetworkInterfaceMonitor:
    """Monitor network interface statistics"""
    
    def __init__(self):
        self.interface_stats = {}
    
    def get_interface_statistics(self) -> Dict[str, Any]:
        """Get real network interface statistics"""
        try:
            stats = {}
            
            # Get network I/O statistics
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, io_stats in net_io.items():
                stats[interface] = {
                    'bytes_sent': io_stats.bytes_sent,
                    'bytes_recv': io_stats.bytes_recv,
                    'packets_sent': io_stats.packets_sent,
                    'packets_recv': io_stats.packets_recv,
                    'errin': io_stats.errin,
                    'errout': io_stats.errout,
                    'dropin': io_stats.dropin,
                    'dropout': io_stats.dropout
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting interface statistics: {e}")
            return {}


# Global instance for Module 3
real_packet_capture = None

def get_real_packet_capture(config: Dict[str, Any] = None) -> RealPacketCapture:
    """Get global real packet capture instance"""
    global real_packet_capture
    
    if real_packet_capture is None:
        real_packet_capture = RealPacketCapture(config)
    
    return real_packet_capture

if __name__ == "__main__":
    # Test the real packet capture system
    print("Initializing Real Packet Capture System...")
    
    config = {
        'database_path': 'test_real_packet_capture.db',
        'capture_dir': './test_captures'
    }
    
    capture_system = RealPacketCapture(config)
    
    # Get available interfaces
    interfaces = capture_system.get_available_interfaces()
    print(f"Available interfaces: {interfaces}")
    
    # Start capture for 30 seconds
    print("Starting packet capture for 30 seconds...")
    success = capture_system.start_capture(duration=30)
    
    if success:
        print("Capture started successfully")
        time.sleep(35)  # Wait for capture to complete
        capture_system.stop_capture()
        
        # Get results
        status = capture_system.get_capture_status()
        print(f"Capture status: {status}")
        
        packets = capture_system.get_recent_packets(10)
        print(f"Captured {len(packets)} packets")
        
        anomalies = capture_system.get_anomalies(10)
        print(f"Detected {len(anomalies)} anomalies")
    else:
        print("Failed to start capture")
