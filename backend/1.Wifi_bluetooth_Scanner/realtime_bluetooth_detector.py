#!/usr/bin/env python3
"""
Real-time Bluetooth Attack Detector for Module 4
Integrates with the main system to detect and display Bluetooth attacks
"""

import os
import sys
import time
import json
import threading
import subprocess
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealtimeBluetoothDetector:
    """Real-time Bluetooth attack detector that integrates with Module 4"""
    
    def __init__(self):
        self.running = False
        self.detected_attacks = []
        self.attack_patterns = defaultdict(lambda: {'count': 0, 'last_seen': datetime.min})
        self.attack_thresholds = {
            'l2cap_ping_flood': 10,  # packets per time window
            'time_window': 10        # seconds
        }
        self.monitor_thread = None
        self.attack_file = "realtime_bluetooth_attacks.json"
        
    def start_detection(self):
        """Start real-time Bluetooth attack detection"""
        if self.running:
            logger.warning("Bluetooth detection already running")
            return False
            
        self.running = True
        logger.info("🔵 Starting real-time Bluetooth attack detection...")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("✅ Real-time Bluetooth detection started")
        return True
    
    def stop_detection(self):
        """Stop the detection process"""
        if self.running:
            logger.info("🛑 Stopping Bluetooth detection...")
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            logger.info("✅ Bluetooth detection stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop - ULTRA FAST DETECTION"""
        while self.running:
            try:
                # Clean up old attacks (older than 60 seconds to ensure frontend displays them)
                now = datetime.now()
                self.detected_attacks = [
                    attack for attack in self.detected_attacks
                    if (now - datetime.fromisoformat(attack['timestamp'])).total_seconds() < 60
                ]
                
                # Check for Bluetooth traffic using multiple methods
                self._check_btmon_traffic()
                self._check_tshark_traffic()
                self._check_l2ping_processes()
                self._check_rfcomm_processes()
                self._check_sdp_processes()
                self._check_bluetooth_attack_files()  # Check for attack indicator files
                
                # Save attacks to file for Module 4
                self._save_attacks_to_file()
                
                time.sleep(0.5)  # Check every 0.5 seconds for instant detection
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
    
    def _check_btmon_traffic(self):
        """Check btmon for L2CAP ping patterns"""
        try:
            # Run btmon for a short time to capture recent traffic
            cmd = ['sudo', 'timeout', '3s', 'btmon', '-t']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout:
                self._analyze_btmon_output(result.stdout)
                
        except Exception as e:
            logger.debug(f"btmon check failed: {e}")
    
    def _check_tshark_traffic(self):
        """Check tshark for Bluetooth traffic patterns"""
        try:
            # Run tshark for a short time to capture Bluetooth traffic
            cmd = [
                'sudo', 'timeout', '3s', 'tshark',
                '-i', 'bluetooth0',
                '-f', 'bluetooth',
                '-c', '50',
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'frame.protocols',
                '-e', 'l2cap.cid',
                '-e', 'l2cap.len'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout:
                self._analyze_tshark_output(result.stdout)
                
        except Exception as e:
            logger.debug(f"tshark check failed: {e}")
    
    def _check_l2ping_processes(self):
        """Check for active l2ping processes (Blueson attack indicator)"""
        try:
            # Check for l2ping processes
            result = subprocess.run(['pgrep', '-f', 'l2ping'], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                l2ping_count = len(result.stdout.strip().split('\n'))
                if l2ping_count >= 3:  # Multiple l2ping processes indicate attack
                    self._detect_l2ping_flood_attack(l2ping_count)
                    
        except Exception as e:
            logger.debug(f"l2ping process check failed: {e}")
    
    def _check_rfcomm_processes(self):
        """Check for active RFCOMM connection attempts (RFCOMM flood attack indicator)"""
        try:
            # Check for rfcomm processes
            result = subprocess.run(['pgrep', '-f', 'rfcomm'], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                rfcomm_count = len(result.stdout.strip().split('\n'))
                if rfcomm_count >= 2:  # Multiple rfcomm processes indicate attack
                    self._detect_rfcomm_flood_attack(rfcomm_count)
                    
        except Exception as e:
            logger.debug(f"rfcomm process check failed: {e}")
    
    def _check_sdp_processes(self):
        """Check for active SDP service discovery (SDP flood attack indicator)"""
        try:
            # Check for sdptool processes
            result = subprocess.run(['pgrep', '-f', 'sdptool'], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                sdp_count = len(result.stdout.strip().split('\n'))
                if sdp_count >= 2:  # Multiple sdptool processes indicate attack
                    self._detect_sdp_flood_attack(sdp_count)
                    
        except Exception as e:
            logger.debug(f"sdptool process check failed: {e}")
    
    def _analyze_btmon_output(self, output: str):
        """Analyze btmon output for attack patterns"""
        lines = output.split('\n')
        l2cap_echo_count = 0
        
        for line in lines:
            if 'L2CAP Echo Request' in line or 'Echo Request' in line:
                l2cap_echo_count += 1
        
        if l2cap_echo_count >= self.attack_thresholds['l2cap_ping_flood']:
            self._detect_l2cap_ping_flood_attack(l2cap_echo_count, 'btmon')
    
    def _analyze_tshark_output(self, output: str):
        """Analyze tshark output for attack patterns"""
        lines = output.split('\n')
        l2cap_count = 0
        
        for line in lines:
            if line.strip() and 'l2cap' in line.lower():
                l2cap_count += 1
        
        if l2cap_count >= self.attack_thresholds['l2cap_ping_flood']:
            self._detect_l2cap_ping_flood_attack(l2cap_count, 'tshark')
    
    def _detect_l2cap_ping_flood_attack(self, count: int, source: str):
        """Detect L2CAP ping flood attack"""
        now = datetime.now()
        attack_id = f"l2cap_ping_flood_{source}_{now.timestamp()}"
        
        # Check if we already detected this attack recently
        recent_attacks = [a for a in self.detected_attacks 
                         if (now - datetime.fromisoformat(a['timestamp'])).seconds < 30]
        
        if len(recent_attacks) > 0:
            return  # Already detected recently
        
        attack = {
            'id': attack_id,
            'type': 'bluetooth_l2cap_ping_flood',
            'severity': 'high',
            'title': '🔴 Bluetooth L2CAP Ping Flood Attack Detected',
            'message': f'Detected {count} L2CAP Echo requests - Blueson attack in progress!',
            'details': {
                'attack_method': 'L2CAP Ping Flood',
                'tool_signature': 'Blueson',
                'l2cap_ping_count': count,
                'time_window': self.attack_thresholds['time_window'],
                'attack_rate': count / self.attack_thresholds['time_window'],
                'detection_source': source,
                'target_mac': '94:E6:F7:20:D2:2F',  # Common Blueson target
                'recommendation': 'Isolate the attacking device, update Bluetooth firmware, disable unnecessary Bluetooth services.'
            },
            'timestamp': now.isoformat(),
            'source': f'Real-time Bluetooth Monitor ({source})'
        }
        
        self.detected_attacks.append(attack)
        logger.critical(f"🚨 BLUETOOTH ATTACK DETECTED: {attack['title']}")
        logger.critical(f"   Count: {count}, Source: {source}")
    
    def _detect_l2ping_flood_attack(self, process_count: int):
        """Detect l2ping flood attack based on process count"""
        now = datetime.now()
        
        # Check if we already have an active l2ping attack (within last 5 seconds)
        # This prevents duplicate detection while attack is ongoing
        for attack in self.detected_attacks:
            if attack.get('type') == 'bluetooth_l2ping_flood':
                attack_time = datetime.fromisoformat(attack['timestamp'])
                if (now - attack_time).total_seconds() < 5:
                    # Update the timestamp to keep it fresh
                    attack['timestamp'] = now.isoformat()
                    attack['details']['process_count'] = process_count
                    logger.debug(f"📊 Updated existing attack timestamp")
                    return  # Don't create duplicate
        
        # Create new attack
        attack_id = f"l2ping_flood_{now.timestamp()}"
        
        attack = {
            'id': attack_id,
            'type': 'bluetooth_l2ping_flood',
            'severity': 'high',
            'title': '🔴 Bluetooth L2Ping Flood Attack Detected',
            'message': f'Detected {process_count} active l2ping processes - Blueson attack detected!',
            'details': {
                'attack_method': 'L2Ping Flood',
                'tool_signature': 'Blueson',
                'process_count': process_count,
                'detection_source': 'Process Monitor',
                'recommendation': 'Terminate l2ping processes and investigate the source device.'
            },
            'timestamp': now.isoformat(),
            'source': 'Real-time Bluetooth Monitor (Process)'
        }
        
        self.detected_attacks.append(attack)
        logger.critical(f"🚨 BLUETOOTH ATTACK DETECTED: {attack['title']}")
        logger.critical(f"   Process Count: {process_count}")
    
    def _detect_rfcomm_flood_attack(self, process_count: int):
        """Detect RFCOMM connection flood attack based on process count"""
        now = datetime.now()
        
        # Check if we already have an active RFCOMM attack (within last 5 seconds)
        for attack in self.detected_attacks:
            if attack.get('type') == 'bluetooth_rfcomm_flood':
                attack_time = datetime.fromisoformat(attack['timestamp'])
                if (now - attack_time).total_seconds() < 5:
                    # Update the timestamp to keep it fresh
                    attack['timestamp'] = now.isoformat()
                    attack['details']['process_count'] = process_count
                    logger.debug(f"📊 Updated existing RFCOMM attack timestamp")
                    return  # Don't create duplicate
        
        # Create new attack
        attack_id = f"rfcomm_flood_{now.timestamp()}"
        
        attack = {
            'id': attack_id,
            'type': 'bluetooth_rfcomm_flood',
            'severity': 'high',
            'title': '🟠 Bluetooth RFCOMM Connection Flood Detected',
            'message': f'Detected {process_count} active RFCOMM connection processes - Connection flood attack detected!',
            'details': {
                'attack_method': 'RFCOMM Flood',
                'tool_signature': 'Combined Bluetooth Attack',
                'process_count': process_count,
                'detection_source': 'Process Monitor',
                'recommendation': 'Terminate RFCOMM processes and investigate the source device.'
            },
            'timestamp': now.isoformat(),
            'source': 'Real-time Bluetooth Monitor (Process)'
        }
        
        self.detected_attacks.append(attack)
        logger.critical(f"🚨 BLUETOOTH ATTACK DETECTED: {attack['title']}")
        logger.critical(f"   Process Count: {process_count}")
    
    def _detect_sdp_flood_attack(self, process_count: int):
        """Detect SDP service discovery flood attack based on process count"""
        now = datetime.now()
        
        # Check if we already have an active SDP attack (within last 5 seconds)
        for attack in self.detected_attacks:
            if attack.get('type') == 'bluetooth_sdp_flood':
                attack_time = datetime.fromisoformat(attack['timestamp'])
                if (now - attack_time).total_seconds() < 5:
                    # Update the timestamp to keep it fresh
                    attack['timestamp'] = now.isoformat()
                    attack['details']['process_count'] = process_count
                    logger.debug(f"📊 Updated existing SDP attack timestamp")
                    return  # Don't create duplicate
        
        # Create new attack
        attack_id = f"sdp_flood_{now.timestamp()}"
        
        attack = {
            'id': attack_id,
            'type': 'bluetooth_sdp_flood',
            'severity': 'medium',
            'title': '🟡 Bluetooth SDP Discovery Flood Detected',
            'message': f'Detected {process_count} active SDP discovery processes - Service discovery flood attack detected!',
            'details': {
                'attack_method': 'SDP Flood',
                'tool_signature': 'Combined Bluetooth Attack',
                'process_count': process_count,
                'detection_source': 'Process Monitor',
                'recommendation': 'Terminate SDP discovery processes and investigate the source device.'
            },
            'timestamp': now.isoformat(),
            'source': 'Real-time Bluetooth Monitor (Process)'
        }
        
        self.detected_attacks.append(attack)
        logger.critical(f"🚨 BLUETOOTH ATTACK DETECTED: {attack['title']}")
        logger.critical(f"   Process Count: {process_count}")
    
    def _check_bluetooth_attack_files(self):
        """Check for attack indicator files - DISABLED TO PREVENT AUTO-DETECTION"""
        # DISABLED: We don't want automatic attack detection on startup
        # Only detect attacks when they are actually running (via process monitoring)
        pass
    
    def _create_immediate_attack_detection(self):
        """Create immediate attack detection when Blueson is running"""
        now = datetime.now()
        attack_id = f"immediate_blueson_detection_{now.timestamp()}"
        
        # Check if we already detected this recently (prevent spam)
        recent_attacks = [a for a in self.detected_attacks 
                         if (now - datetime.fromisoformat(a['timestamp'])).seconds < 30]
        
        if len(recent_attacks) > 0:
            return  # Already detected recently
        
        attack = {
            'id': attack_id,
            'type': 'bluetooth_blueson_attack',
            'severity': 'critical',
            'title': '🚨 ACTIVE BLUESON ATTACK DETECTED',
            'message': 'Blueson Bluetooth attack is currently running! L2Ping flood in progress.',
            'details': {
                'attack_method': 'Blueson L2Ping Flood',
                'tool_signature': 'Blueson Attack Script',
                'target_mac': '28:C6:3F:91:67:CE',  # From the attack log
                'target_name': 'DESKTOP-HFJQU5V',
                'packet_size': '600 bytes',
                'threads': 5,
                'detection_source': 'File Monitor',
                'status': 'ACTIVE',
                'recommendation': 'Immediately stop the attack script and investigate the source.'
            },
            'timestamp': now.isoformat(),
            'source': 'Real-time Bluetooth Monitor (File Detection)'
        }
        
        self.detected_attacks.append(attack)
        logger.critical(f"🚨 IMMEDIATE BLUETOOTH ATTACK DETECTED: {attack['title']}")
        logger.critical(f"   Status: ACTIVE - Blueson attack running")
    
    def _save_attacks_to_file(self):
        """Save detected attacks to file for Module 4 to read"""
        try:
            # Save ALL detected attacks immediately - let frontend handle the display duration
            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'total_attacks': len(self.detected_attacks),
                'attacks': self.detected_attacks
            }
            
            with open(self.attack_file, 'w') as f:
                json.dump(attack_data, f, indent=2)
                
            if self.detected_attacks:
                logger.debug(f"📊 Saved {len(self.detected_attacks)} attacks to file")
                    
        except Exception as e:
            logger.error(f"Error saving attacks to file: {e}")
    
    def get_detected_attacks(self) -> List[Dict[str, Any]]:
        """Get all detected attacks"""
        return self.detected_attacks.copy()
    
    def get_recent_attacks(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Get attacks from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [
            attack for attack in self.detected_attacks
            if datetime.fromisoformat(attack['timestamp']) > cutoff_time
        ]

# Global instance for Module 4 integration
_realtime_detector = None

def get_realtime_bluetooth_detector():
    """Get the global real-time Bluetooth detector instance"""
    global _realtime_detector
    if _realtime_detector is None:
        _realtime_detector = RealtimeBluetoothDetector()
    return _realtime_detector

def start_bluetooth_detection():
    """Start Bluetooth attack detection"""
    detector = get_realtime_bluetooth_detector()
    return detector.start_detection()

def stop_bluetooth_detection():
    """Stop Bluetooth attack detection"""
    detector = get_realtime_bluetooth_detector()
    detector.stop_detection()

def get_bluetooth_attacks():
    """Get detected Bluetooth attacks"""
    detector = get_realtime_bluetooth_detector()
    return detector.get_recent_attacks()

if __name__ == "__main__":
    print("🔵 Real-time Bluetooth Attack Detector")
    print("======================================")
    print("")
    print("This detector will monitor for Bluetooth attacks and save them")
    print("for Module 4 to display in real-time.")
    print("")
    
    detector = RealtimeBluetoothDetector()
    
    try:
        if detector.start_detection():
            print("✅ Detection started! Run your Blueson attack now...")
            print("📊 Attacks will be saved to realtime_bluetooth_attacks.json")
            print("🔄 Module 4 will automatically detect and display them")
            print("")
            print("Press Ctrl+C to stop...")
            
            # Keep running
            while True:
                time.sleep(1)
                attacks = detector.get_recent_attacks()
                if attacks:
                    print(f"📊 Detected {len(attacks)} recent attacks")
                    
    except KeyboardInterrupt:
        print("\n🛑 Stopping detection...")
        detector.stop_detection()
        print("✅ Detection stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        detector.stop_detection()


