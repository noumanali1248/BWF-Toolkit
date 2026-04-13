#!/usr/bin/env python3
"""
Real Bluetooth Traffic Monitor
Captures and analyzes REAL Bluetooth HCI/L2CAP traffic to detect attacks like Blueson
Uses btmon to capture actual Bluetooth packets
"""

import subprocess
import threading
import time
import logging
import re
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BluetoothTrafficMonitor:
    """
    Monitors REAL Bluetooth traffic using btmon
    Detects L2CAP ping floods and other Bluetooth attacks
    """
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.detected_attacks = []
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'l2cap_pings': 0,
            'last_seen': None,
            'first_seen': None
        })
        self.attack_threshold = {
            'l2cap_ping_flood': 50,  # 50+ L2CAP pings in window = flood
            'time_window': 10  # 10 second window
        }
        
    def start_monitoring(self):
        """Start monitoring Bluetooth traffic in background"""
        if self.monitoring:
            logger.warning("Bluetooth monitoring already running")
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("🎧 Real Bluetooth traffic monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Bluetooth traffic monitoring stopped")
    
    def _monitor_loop(self):
        """
        Monitor Bluetooth HCI traffic using btmon
        This captures REAL Bluetooth packets including L2CAP ping floods
        """
        try:
            # Start btmon process
            logger.info("Starting btmon to capture real Bluetooth traffic...")
            process = subprocess.Popen(
                ['sudo', 'btmon', '-t'],  # -t for timestamps
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            current_packet = {}
            
            while self.monitoring:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                
                # Parse btmon output for L2CAP packets
                if 'L2CAP' in line:
                    # Detect L2CAP Echo Request (ping)
                    if 'Echo Request' in line or 'Echo Response' in line:
                        self._process_l2cap_ping(line)
                    
                # Detect connection events
                elif 'ACL Data' in line:
                    self._process_acl_data(line)
                
                # Detect HCI events
                elif 'HCI Event' in line:
                    self._process_hci_event(line)
                    
                # Analyze for attacks every second
                time.sleep(0.01)  # Small delay to prevent CPU overload
                
        except FileNotFoundError:
            logger.error("btmon not found! Install with: sudo apt install bluez")
        except subprocess.CalledProcessError as e:
            logger.error(f"btmon error: {e}")
        except Exception as e:
            logger.error(f"Bluetooth monitoring error: {e}")
        finally:
            if 'process' in locals():
                process.terminate()
                
    def _process_l2cap_ping(self, line):
        """Process L2CAP Echo Request/Response (detects ping floods)"""
        try:
            # Extract timestamp and source
            timestamp = datetime.now()
            
            # Extract handle/address from btmon output
            # Example line: "< ACL Data TX: Handle 64 flags 0x00 dlen 12 [hci0]"
            handle_match = re.search(r'Handle\s+(\d+)', line)
            if handle_match:
                handle = handle_match.group(1)
                
                # Track L2CAP pings per handle
                self.traffic_stats[handle]['l2cap_pings'] += 1
                self.traffic_stats[handle]['packet_count'] += 1
                self.traffic_stats[handle]['last_seen'] = timestamp
                
                if not self.traffic_stats[handle]['first_seen']:
                    self.traffic_stats[handle]['first_seen'] = timestamp
                
                # Check for ping flood
                self._check_for_ping_flood(handle)
                
        except Exception as e:
            logger.error(f"Error processing L2CAP ping: {e}")
    
    def _process_acl_data(self, line):
        """Process ACL data packets"""
        try:
            # Track general Bluetooth traffic
            timestamp = datetime.now()
            
            # Extract handle
            handle_match = re.search(r'Handle\s+(\d+)', line)
            if handle_match:
                handle = handle_match.group(1)
                self.traffic_stats[handle]['packet_count'] += 1
                self.traffic_stats[handle]['last_seen'] = timestamp
                
        except Exception as e:
            logger.error(f"Error processing ACL data: {e}")
    
    def _process_hci_event(self, line):
        """Process HCI events"""
        try:
            # Detect connection/disconnection events
            if 'Connection Complete' in line or 'Disconnection Complete' in line:
                logger.info(f"Bluetooth connection event: {line}")
        except Exception as e:
            logger.error(f"Error processing HCI event: {e}")
    
    def _check_for_ping_flood(self, handle):
        """Check if we're seeing a ping flood attack"""
        stats = self.traffic_stats[handle]
        
        if stats['first_seen'] and stats['last_seen']:
            time_diff = (stats['last_seen'] - stats['first_seen']).total_seconds()
            
            if time_diff > 0 and time_diff <= self.attack_threshold['time_window']:
                # Check if ping count exceeds threshold
                if stats['l2cap_pings'] >= self.attack_threshold['l2cap_ping_flood']:
                    # REAL ATTACK DETECTED!
                    attack_event = {
                        'id': f'bluetooth_dos_{handle}_{int(time.time())}',
                        'type': 'bluetooth_l2cap_ping_flood',
                        'severity': 'critical',
                        'title': '🚨 REAL Bluetooth DoS Attack Detected (Blueson-style)',
                        'message': f'L2CAP ping flood detected on Bluetooth handle {handle} - {stats["l2cap_pings"]} pings in {time_diff:.1f} seconds',
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'bluetooth_handle': handle,
                            'l2cap_ping_count': stats['l2cap_pings'],
                            'total_packets': stats['packet_count'],
                            'time_window': time_diff,
                            'attack_rate': stats['l2cap_pings'] / time_diff if time_diff > 0 else 0,
                            'threshold': self.attack_threshold['l2cap_ping_flood'],
                            'attack_method': 'L2CAP Echo Request Flood',
                            'tool_signature': 'Blueson / l2ping',
                            'real_traffic': True
                        },
                        'source': 'Bluetooth Traffic Monitor (btmon)',
                        'recommendation': 'Device under Bluetooth DoS attack - disconnect and investigate source',
                        'attack_vector': 'Bluetooth L2CAP Denial of Service',
                        'cve_references': ['CVE-2017-0781', 'CVE-2018-5383']
                    }
                    
                    # Add to detected attacks (avoid duplicates)
                    attack_id = attack_event['id']
                    if not any(a['id'] == attack_id for a in self.detected_attacks):
                        self.detected_attacks.append(attack_event)
                        logger.warning(f"🚨 REAL BLUETOOTH DOS ATTACK DETECTED: {stats['l2cap_pings']} L2CAP pings in {time_diff:.1f}s")
    
    def get_detected_attacks(self) -> List[Dict[str, Any]]:
        """Get list of detected Bluetooth attacks"""
        return self.detected_attacks
    
    def get_traffic_statistics(self) -> Dict[str, Any]:
        """Get real-time Bluetooth traffic statistics"""
        return {
            'total_handles': len(self.traffic_stats),
            'total_packets': sum(s['packet_count'] for s in self.traffic_stats.values()),
            'total_l2cap_pings': sum(s['l2cap_pings'] for s in self.traffic_stats.values()),
            'attacks_detected': len(self.detected_attacks),
            'monitoring_active': self.monitoring,
            'handles': dict(self.traffic_stats)
        }
    
    def clear_old_stats(self, max_age_seconds=300):
        """Clear old statistics to prevent memory buildup"""
        now = datetime.now()
        to_remove = []
        
        for handle, stats in self.traffic_stats.items():
            if stats['last_seen']:
                age = (now - stats['last_seen']).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(handle)
        
        for handle in to_remove:
            del self.traffic_stats[handle]

# Global instance
_bluetooth_monitor = None

def get_bluetooth_monitor():
    """Get global Bluetooth traffic monitor instance"""
    global _bluetooth_monitor
    if _bluetooth_monitor is None:
        _bluetooth_monitor = BluetoothTrafficMonitor()
    return _bluetooth_monitor

def start_bluetooth_monitoring():
    """Start Bluetooth traffic monitoring"""
    monitor = get_bluetooth_monitor()
    monitor.start_monitoring()
    return monitor

if __name__ == '__main__':
    # Test the monitor
    print("Starting Bluetooth Traffic Monitor...")
    print("This will capture REAL Bluetooth traffic including L2CAP ping floods")
    print("Run a Blueson attack in another terminal to test detection\n")
    
    monitor = BluetoothTrafficMonitor()
    monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(5)
            stats = monitor.get_traffic_statistics()
            print(f"\n📊 Traffic Stats: {stats['total_packets']} packets, {stats['total_l2cap_pings']} L2CAP pings")
            
            attacks = monitor.get_detected_attacks()
            if attacks:
                print(f"\n🚨 ATTACKS DETECTED: {len(attacks)}")
                for attack in attacks[-3:]:  # Show last 3
                    print(f"   - {attack['title']}: {attack['message']}")
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop_monitoring()













"""
Real Bluetooth Traffic Monitor
Captures and analyzes REAL Bluetooth HCI/L2CAP traffic to detect attacks like Blueson
Uses btmon to capture actual Bluetooth packets
"""

import subprocess
import threading
import time
import logging
import re
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BluetoothTrafficMonitor:
    """
    Monitors REAL Bluetooth traffic using btmon
    Detects L2CAP ping floods and other Bluetooth attacks
    """
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.detected_attacks = []
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'l2cap_pings': 0,
            'last_seen': None,
            'first_seen': None
        })
        self.attack_threshold = {
            'l2cap_ping_flood': 50,  # 50+ L2CAP pings in window = flood
            'time_window': 10  # 10 second window
        }
        
    def start_monitoring(self):
        """Start monitoring Bluetooth traffic in background"""
        if self.monitoring:
            logger.warning("Bluetooth monitoring already running")
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("🎧 Real Bluetooth traffic monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Bluetooth traffic monitoring stopped")
    
    def _monitor_loop(self):
        """
        Monitor Bluetooth HCI traffic using btmon
        This captures REAL Bluetooth packets including L2CAP ping floods
        """
        try:
            # Start btmon process
            logger.info("Starting btmon to capture real Bluetooth traffic...")
            process = subprocess.Popen(
                ['sudo', 'btmon', '-t'],  # -t for timestamps
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            current_packet = {}
            
            while self.monitoring:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                
                # Parse btmon output for L2CAP packets
                if 'L2CAP' in line:
                    # Detect L2CAP Echo Request (ping)
                    if 'Echo Request' in line or 'Echo Response' in line:
                        self._process_l2cap_ping(line)
                    
                # Detect connection events
                elif 'ACL Data' in line:
                    self._process_acl_data(line)
                
                # Detect HCI events
                elif 'HCI Event' in line:
                    self._process_hci_event(line)
                    
                # Analyze for attacks every second
                time.sleep(0.01)  # Small delay to prevent CPU overload
                
        except FileNotFoundError:
            logger.error("btmon not found! Install with: sudo apt install bluez")
        except subprocess.CalledProcessError as e:
            logger.error(f"btmon error: {e}")
        except Exception as e:
            logger.error(f"Bluetooth monitoring error: {e}")
        finally:
            if 'process' in locals():
                process.terminate()
                
    def _process_l2cap_ping(self, line):
        """Process L2CAP Echo Request/Response (detects ping floods)"""
        try:
            # Extract timestamp and source
            timestamp = datetime.now()
            
            # Extract handle/address from btmon output
            # Example line: "< ACL Data TX: Handle 64 flags 0x00 dlen 12 [hci0]"
            handle_match = re.search(r'Handle\s+(\d+)', line)
            if handle_match:
                handle = handle_match.group(1)
                
                # Track L2CAP pings per handle
                self.traffic_stats[handle]['l2cap_pings'] += 1
                self.traffic_stats[handle]['packet_count'] += 1
                self.traffic_stats[handle]['last_seen'] = timestamp
                
                if not self.traffic_stats[handle]['first_seen']:
                    self.traffic_stats[handle]['first_seen'] = timestamp
                
                # Check for ping flood
                self._check_for_ping_flood(handle)
                
        except Exception as e:
            logger.error(f"Error processing L2CAP ping: {e}")
    
    def _process_acl_data(self, line):
        """Process ACL data packets"""
        try:
            # Track general Bluetooth traffic
            timestamp = datetime.now()
            
            # Extract handle
            handle_match = re.search(r'Handle\s+(\d+)', line)
            if handle_match:
                handle = handle_match.group(1)
                self.traffic_stats[handle]['packet_count'] += 1
                self.traffic_stats[handle]['last_seen'] = timestamp
                
        except Exception as e:
            logger.error(f"Error processing ACL data: {e}")
    
    def _process_hci_event(self, line):
        """Process HCI events"""
        try:
            # Detect connection/disconnection events
            if 'Connection Complete' in line or 'Disconnection Complete' in line:
                logger.info(f"Bluetooth connection event: {line}")
        except Exception as e:
            logger.error(f"Error processing HCI event: {e}")
    
    def _check_for_ping_flood(self, handle):
        """Check if we're seeing a ping flood attack"""
        stats = self.traffic_stats[handle]
        
        if stats['first_seen'] and stats['last_seen']:
            time_diff = (stats['last_seen'] - stats['first_seen']).total_seconds()
            
            if time_diff > 0 and time_diff <= self.attack_threshold['time_window']:
                # Check if ping count exceeds threshold
                if stats['l2cap_pings'] >= self.attack_threshold['l2cap_ping_flood']:
                    # REAL ATTACK DETECTED!
                    attack_event = {
                        'id': f'bluetooth_dos_{handle}_{int(time.time())}',
                        'type': 'bluetooth_l2cap_ping_flood',
                        'severity': 'critical',
                        'title': '🚨 REAL Bluetooth DoS Attack Detected (Blueson-style)',
                        'message': f'L2CAP ping flood detected on Bluetooth handle {handle} - {stats["l2cap_pings"]} pings in {time_diff:.1f} seconds',
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'bluetooth_handle': handle,
                            'l2cap_ping_count': stats['l2cap_pings'],
                            'total_packets': stats['packet_count'],
                            'time_window': time_diff,
                            'attack_rate': stats['l2cap_pings'] / time_diff if time_diff > 0 else 0,
                            'threshold': self.attack_threshold['l2cap_ping_flood'],
                            'attack_method': 'L2CAP Echo Request Flood',
                            'tool_signature': 'Blueson / l2ping',
                            'real_traffic': True
                        },
                        'source': 'Bluetooth Traffic Monitor (btmon)',
                        'recommendation': 'Device under Bluetooth DoS attack - disconnect and investigate source',
                        'attack_vector': 'Bluetooth L2CAP Denial of Service',
                        'cve_references': ['CVE-2017-0781', 'CVE-2018-5383']
                    }
                    
                    # Add to detected attacks (avoid duplicates)
                    attack_id = attack_event['id']
                    if not any(a['id'] == attack_id for a in self.detected_attacks):
                        self.detected_attacks.append(attack_event)
                        logger.warning(f"🚨 REAL BLUETOOTH DOS ATTACK DETECTED: {stats['l2cap_pings']} L2CAP pings in {time_diff:.1f}s")
    
    def get_detected_attacks(self) -> List[Dict[str, Any]]:
        """Get list of detected Bluetooth attacks"""
        return self.detected_attacks
    
    def get_traffic_statistics(self) -> Dict[str, Any]:
        """Get real-time Bluetooth traffic statistics"""
        return {
            'total_handles': len(self.traffic_stats),
            'total_packets': sum(s['packet_count'] for s in self.traffic_stats.values()),
            'total_l2cap_pings': sum(s['l2cap_pings'] for s in self.traffic_stats.values()),
            'attacks_detected': len(self.detected_attacks),
            'monitoring_active': self.monitoring,
            'handles': dict(self.traffic_stats)
        }
    
    def clear_old_stats(self, max_age_seconds=300):
        """Clear old statistics to prevent memory buildup"""
        now = datetime.now()
        to_remove = []
        
        for handle, stats in self.traffic_stats.items():
            if stats['last_seen']:
                age = (now - stats['last_seen']).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(handle)
        
        for handle in to_remove:
            del self.traffic_stats[handle]

# Global instance
_bluetooth_monitor = None

def get_bluetooth_monitor():
    """Get global Bluetooth traffic monitor instance"""
    global _bluetooth_monitor
    if _bluetooth_monitor is None:
        _bluetooth_monitor = BluetoothTrafficMonitor()
    return _bluetooth_monitor

def start_bluetooth_monitoring():
    """Start Bluetooth traffic monitoring"""
    monitor = get_bluetooth_monitor()
    monitor.start_monitoring()
    return monitor

if __name__ == '__main__':
    # Test the monitor
    print("Starting Bluetooth Traffic Monitor...")
    print("This will capture REAL Bluetooth traffic including L2CAP ping floods")
    print("Run a Blueson attack in another terminal to test detection\n")
    
    monitor = BluetoothTrafficMonitor()
    monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(5)
            stats = monitor.get_traffic_statistics()
            print(f"\n📊 Traffic Stats: {stats['total_packets']} packets, {stats['total_l2cap_pings']} L2CAP pings")
            
            attacks = monitor.get_detected_attacks()
            if attacks:
                print(f"\n🚨 ATTACKS DETECTED: {len(attacks)}")
                for attack in attacks[-3:]:  # Show last 3
                    print(f"   - {attack['title']}: {attack['message']}")
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop_monitoring()















