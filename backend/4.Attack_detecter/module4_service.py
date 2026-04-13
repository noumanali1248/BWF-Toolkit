#!/usr/bin/env python3
"""
Module 4: Real-time Attack Detection & Threat Intelligence Engine

A production-grade real-time threat detection system that:
- Ingests ONLY real-time Module 3 telemetry (no simulations)
- Evaluates explainable rules (Wi-Fi & Bluetooth)
- Correlates with Module 2 device profiles
- Emits immutable alert JSONs with forensic evidence
- Provides terminal-first verification

NO SIMULATED ATTACKS - REAL-TIME DETECTION ONLY
"""

import os
import sys
import json
import time
import yaml
import sqlite3
import hashlib
import argparse
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import uuid

# Import comprehensive attack detector
from .comprehensive_attack_detector import get_comprehensive_attack_detector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'module4_service.log')),
    ]
)
logger = logging.getLogger(__name__)

class Module4Service:
    """Real-time Attack Detection & Threat Intelligence Service"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules = self.load_rules()
        self.db_path = config['database']
        self.alerts_dir = Path(config['alerts_dir'])
        self.alerts_dir.mkdir(exist_ok=True)
        
        # Initialize sliding windows for rule evaluation
        self.windows = {}
        self.device_profiles = {}
        self.alert_count = 0
        
        # Initialize comprehensive attack detector
        self.comprehensive_attack_detector = get_comprehensive_attack_detector()
        
        # Load existing device profiles from Module 2
        self.load_device_profiles()
        
        logger.info(f"Module 4 Service initialized with {len(self.rules)} rules")
        logger.info(f"Database: {self.db_path}")
        logger.info(f"Alerts directory: {self.alerts_dir}")
    
    def _init_external_apis(self):
        """Initialize external APIs (Disabled)"""
        self.kismet_client = None
        self.bettercap_client = None
        logger.info("External APIs (Kismet/Bettercap) disabled")
    
    def load_rules(self) -> Dict[str, Any]:
        """Load detection rules from YAML configuration"""
        try:
            with open(self.config['rules_file'], 'r') as f:
                rules = yaml.safe_load(f)
            logger.info(f"Loaded {len(rules)} detection rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return {}
    
    def load_device_profiles(self):
        """Load device profiles from Module 2 database"""
        try:
            # Try to load from Module 2 database if available
            module2_db = "threat_detection.db"
            if os.path.exists(module2_db):
                conn = sqlite3.connect(module2_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT mac_address, device_type, risk_score FROM known_devices")
                for row in cursor.fetchall():
                    mac, device_type, risk_score = row
                    self.device_profiles[mac] = {
                        'device_type': device_type,
                        'risk_score': risk_score or 0.5
                    }
                
                conn.close()
                logger.info(f"Loaded {len(self.device_profiles)} device profiles")
        except Exception as e:
            logger.warning(f"Could not load device profiles: {e}")
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a single event and return generated alerts"""
        alerts = []
        
        # Extract event metadata
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
        protocol = event.get('protocol', '')
        src_mac = event.get('src_mac', '')
        dst_mac = event.get('dst_mac', '')
        length = event.get('length', 0)
        flags = event.get('flags', '')
        pcap_file = event.get('pcap_file', '')
        
        # Enrich event with Kismet data (if available)
        event = self.enrich_event_with_kismet(event)
        
        # Enrich event with Bettercap data (if available)
        event = self.enrich_event_with_bettercap(event)
        
        # Update sliding windows
        self.update_windows(event, timestamp)
        
        # Evaluate each rule (only if enabled)
        for rule_id, rule_config in self.rules.items():
            if not rule_config.get('enabled', False):
                continue
                
            if self.evaluate_rule(rule_id, rule_config, event, timestamp):
                alert = self.generate_alert(rule_id, rule_config, event, timestamp)
                if alert:
                    alerts.append(alert)
                    self.write_alert(alert)
        
        return alerts
    
    def update_windows(self, event: Dict[str, Any], timestamp: datetime):
        """Update sliding time windows for rule evaluation"""
        window_size = timedelta(seconds=60)  # 60-second windows
        
        # Create time-based windows
        for rule_id in self.rules:
            if rule_id not in self.windows:
                self.windows[rule_id] = []
            
            # Add current event
            self.windows[rule_id].append({
                'event': event,
                'timestamp': timestamp
            })
            
            # Remove old events outside window
            cutoff_time = timestamp - window_size
            self.windows[rule_id] = [
                w for w in self.windows[rule_id] 
                if w['timestamp'] > cutoff_time
            ]
    
    def evaluate_rule(self, rule_id: str, rule_config: Dict[str, Any], 
                     event: Dict[str, Any], timestamp: datetime) -> bool:
        """Evaluate a specific rule against the current event and window"""
        try:
            rule_type = rule_config.get('type', '')
            threshold = rule_config.get('threshold', 10)
            window_seconds = rule_config.get('window_seconds', 60)
            
            if rule_id not in self.windows:
                return False
            
            window = self.windows[rule_id]
            
            # Count events in window
            window_events = [w['event'] for w in window]
            count = len(window_events)
            
            if rule_type == 'deauth_flood':
                # Detect deauthentication flood attacks
                deauth_count = sum(1 for e in window_events if 'deauth' in e.get('flags', '').lower())
                return deauth_count >= threshold
            
            elif rule_type == 'evil_twin':
                # Detect evil twin attacks (multiple APs with same SSID)
                ssids = {}
                for e in window_events:
                    ssid = e.get('ssid', '')
                    bssid = e.get('bssid', '')
                    if ssid and bssid:
                        if ssid not in ssids:
                            ssids[ssid] = set()
                        ssids[ssid].add(bssid)
                
                for ssid, bssids in ssids.items():
                    if len(bssids) > 1:
                        return True
                return False
            
            elif rule_type == 'high_pps':
                # Detect high packets per second
                return count >= threshold
            
            elif rule_type == 'mac_churn':
                # Detect MAC address churn (rapid MAC changes)
                unique_macs = set()
                for e in window_events:
                    if e.get('src_mac'):
                        unique_macs.add(e['src_mac'])
                return len(unique_macs) >= threshold
            
            elif rule_type == 'bt_pairing_flood':
                # Detect Bluetooth pairing flood
                bt_events = [e for e in window_events if 'bluetooth' in e.get('protocol', '').lower()]
                return len(bt_events) >= threshold
            
            elif rule_type == 'size_anomaly':
                # Detect packet size anomalies
                large_packets = sum(1 for e in window_events if e.get('length', 0) > 1500)
                small_packets = sum(1 for e in window_events if e.get('length', 0) < 20)
                return large_packets >= threshold or small_packets >= threshold
            
            elif rule_type == 'network_scanning':
                # Detect network scanning behavior
                if 'NETWORK_SCANNING_DETECTED' in event.get('flags', ''):
                    scan_events = sum(1 for e in window_events 
                                    if 'NETWORK_SCANNING_DETECTED' in e.get('flags', ''))
                    return scan_events >= threshold
            
            # ===== 12 NEW ADVANCED WIFI ATTACK DETECTION RULES =====
            
            elif rule_type == 'deauth_disassoc_flood':
                # Rule 1: Enhanced Deauth/Disassoc Flood Detection
                per_source_threshold = rule_config.get('per_source_threshold', 5)
                
                # Count deauth/disassoc per source MAC
                source_counts = {}
                for e in window_events:
                    flags = e.get('flags', '').lower()
                    frame_type = e.get('frame_type', '').lower()
                    
                    if 'deauth' in flags or 'disassoc' in flags or \
                       'deauth' in frame_type or 'disassoc' in frame_type:
                        src_mac = e.get('src_mac', 'unknown')
                        source_counts[src_mac] = source_counts.get(src_mac, 0) + 1
                
                # Check if any source exceeds threshold
                for src_mac, count in source_counts.items():
                    if count >= per_source_threshold:
                        return True
                
                # Also check total deauth count
                total_deauths = sum(source_counts.values())
                return total_deauths >= threshold
            
            elif rule_type == 'beacon_flood_advanced':
                # Rule 2: Beacon Flood (Fake APs)
                unique_pairs_threshold = rule_config.get('unique_pairs_threshold', 20)
                
                unique_pairs = set()
                beacon_count = 0
                
                for e in window_events:
                    frame_type = e.get('frame_type', '').lower()
                    if 'beacon' in frame_type:
                        beacon_count += 1
                        bssid = e.get('bssid', '')
                        ssid = e.get('ssid', '')
                        if bssid and ssid:
                            unique_pairs.add((bssid, ssid))
                
                # Alert if too many unique BSSID/SSID pairs or total beacons
                return len(unique_pairs) >= unique_pairs_threshold or beacon_count >= threshold
            
            elif rule_type == 'probe_request_flood':
                # Rule 3: Probe Request Flood / SSID Scanning
                per_client_threshold = rule_config.get('per_client_threshold', 30)
                
                # Count probe requests per client
                client_probes = {}
                for e in window_events:
                    frame_type = e.get('frame_type', '').lower()
                    if 'probe' in frame_type and 'request' in frame_type:
                        src_mac = e.get('src_mac', 'unknown')
                        client_probes[src_mac] = client_probes.get(src_mac, 0) + 1
                
                # Check if any client exceeds per-client threshold
                for client_mac, count in client_probes.items():
                    if count >= per_client_threshold:
                        return True
                
                # Also check total probe requests
                total_probes = sum(client_probes.values())
                return total_probes >= threshold
            
            elif rule_type == 'evil_twin_rssi':
                # Rule 4: Evil Twin with RSSI Analysis
                rssi_diff_threshold = rule_config.get('rssi_difference_threshold', 20)
                
                # Group by SSID
                ssid_aps = {}
                for e in window_events:
                    ssid = e.get('ssid', '')
                    bssid = e.get('bssid', '')
                    rssi = e.get('rssi', -100)
                    channel = e.get('channel', 0)
                    
                    if ssid and bssid:
                        if ssid not in ssid_aps:
                            ssid_aps[ssid] = []
                        
                        ssid_aps[ssid].append({
                            'bssid': bssid,
                            'rssi': rssi,
                            'channel': channel
                        })
                
                # Check for evil twins with RSSI anomalies
                for ssid, aps_list in ssid_aps.items():
                    if len(aps_list) > 1:
                        # Check RSSI differences
                        rssis = [ap['rssi'] for ap in aps_list if ap['rssi'] != -100]
                        if len(rssis) >= 2:
                            max_rssi = max(rssis)
                            min_rssi = min(rssis)
                            if abs(max_rssi - min_rssi) > rssi_diff_threshold:
                                return True
                
                return False
            
            elif rule_type == 'mac_spoofing_advanced':
                # Rule 5: MAC Spoofing / Rapid MAC Churn (IP-based tracking)
                mapping_changes_threshold = rule_config.get('mapping_changes_threshold', 3)
                
                # Track IP to MAC mappings
                ip_mac_history = {}
                for e in window_events:
                    src_ip = e.get('src_ip', '')
                    src_mac = e.get('src_mac', '')
                    hostname = e.get('hostname', '')
                    
                    if src_ip and src_mac:
                        key = src_ip if src_ip != '0.0.0.0' else hostname
                        if key:
                            if key not in ip_mac_history:
                                ip_mac_history[key] = set()
                            ip_mac_history[key].add(src_mac)
                
                # Check for multiple MAC changes for same IP/hostname
                for key, macs in ip_mac_history.items():
                    if len(macs) >= mapping_changes_threshold:
                        return True
                
                return False
            
            elif rule_type == 'rts_cts_flood':
                # Rule 6: RTS/CTS Control Frame Flood
                per_source_threshold = rule_config.get('per_source_threshold', 50)
                
                # Count RTS/CTS frames per source
                source_counts = {}
                for e in window_events:
                    frame_type = e.get('frame_type', '').lower()
                    flags = e.get('flags', '').lower()
                    
                    if 'rts' in frame_type or 'cts' in frame_type or \
                       'rts' in flags or 'cts' in flags:
                        src_mac = e.get('src_mac', 'unknown')
                        source_counts[src_mac] = source_counts.get(src_mac, 0) + 1
                
                # Check per-source threshold
                for src_mac, count in source_counts.items():
                    if count >= per_source_threshold:
                        return True
                
                # Check total threshold
                total_rts_cts = sum(source_counts.values())
                return total_rts_cts >= threshold
            
            elif rule_type == 'dhcp_starvation':
                # Rule 7: DHCP Starvation Attack
                unique_clients_threshold = rule_config.get('unique_clients_threshold', 15)
                
                # Count unique DHCP clients
                dhcp_clients = set()
                dhcp_requests = 0
                
                for e in window_events:
                    protocol = e.get('protocol', '').lower()
                    flags = e.get('flags', '').lower()
                    
                    if 'dhcp' in protocol or 'dhcp' in flags:
                        if 'discover' in flags or 'request' in flags:
                            dhcp_requests += 1
                            src_mac = e.get('src_mac', '')
                            if src_mac:
                                dhcp_clients.add(src_mac)
                
                # Alert if too many unique clients or total requests
                return len(dhcp_clients) >= unique_clients_threshold or dhcp_requests >= threshold
            
            elif rule_type == 'arp_poisoning':
                # Rule 8: ARP Spoofing / ARP Poisoning
                gratuitous_arp_threshold = rule_config.get('gratuitous_arp_threshold', 3)
                
                # Track IP to MAC mappings and detect conflicts
                ip_mac_map = {}
                gratuitous_arps = 0
                conflicts = 0
                
                for e in window_events:
                    protocol = e.get('protocol', '').lower()
                    if 'arp' in protocol:
                        src_ip = e.get('src_ip', '')
                        src_mac = e.get('src_mac', '')
                        flags = e.get('flags', '').lower()
                        
                        # Count gratuitous ARPs
                        if 'gratuitous' in flags or (src_ip and src_ip == e.get('dst_ip', '')):
                            gratuitous_arps += 1
                        
                        # Track IP-MAC mappings
                        if src_ip and src_mac:
                            if src_ip in ip_mac_map and ip_mac_map[src_ip] != src_mac:
                                conflicts += 1
                            ip_mac_map[src_ip] = src_mac
                
                # Alert on gratuitous ARPs or conflicts
                return gratuitous_arps >= gratuitous_arp_threshold or conflicts >= threshold
            
            elif rule_type == 'karma_attack':
                # Rule 9: Karma / SSID Spoofing Attack
                unique_ssids_per_bssid_threshold = rule_config.get('unique_ssids_per_bssid_threshold', 5)
                
                # Track probe responses per BSSID
                bssid_ssids = {}
                for e in window_events:
                    frame_type = e.get('frame_type', '').lower()
                    if 'probe' in frame_type and 'response' in frame_type:
                        bssid = e.get('bssid', '')
                        ssid = e.get('ssid', '')
                        
                        if bssid and ssid:
                            if bssid not in bssid_ssids:
                                bssid_ssids[bssid] = set()
                            bssid_ssids[bssid].add(ssid)
                
                # Check if any BSSID responds with too many different SSIDs
                for bssid, ssids in bssid_ssids.items():
                    if len(ssids) >= unique_ssids_per_bssid_threshold:
                        return True
                
                return False
            
            elif rule_type == 'handshake_harvesting':
                # Rule 10: WPA/WPA2 Handshake Harvesting
                deauth_eapol_window = rule_config.get('deauth_eapol_correlation_window', 30)
                
                # Look for deauth followed by EAPOL within short window
                deauth_events = []
                eapol_events = []
                
                for w in window:
                    e = w['event']
                    t = w['timestamp']
                    flags = e.get('flags', '').lower()
                    protocol = e.get('protocol', '').lower()
                    frame_type = e.get('frame_type', '').lower()
                    
                    if 'deauth' in flags or 'deauth' in frame_type:
                        deauth_events.append({
                            'timestamp': t,
                            'target_mac': e.get('dst_mac', '')
                        })
                    
                    if 'eapol' in protocol or 'eapol' in flags:
                        eapol_events.append({
                            'timestamp': t,
                            'client_mac': e.get('src_mac', '')
                        })
                
                # Check for correlation (deauth followed by EAPOL for same target)
                correlations = 0
                for deauth in deauth_events:
                    deauth_time = deauth['timestamp']
                    target = deauth['target_mac']
                    
                    for eapol in eapol_events:
                        eapol_time = eapol['timestamp']
                        client = eapol['client_mac']
                        
                        # Check if EAPOL within window after deauth for same client
                        time_diff = (eapol_time - deauth_time).total_seconds()
                        if 0 < time_diff <= deauth_eapol_window and target == client:
                            correlations += 1
                
                return correlations >= threshold
            
            elif rule_type == 'assoc_request_flood':
                # Rule 11: Association Request Flood
                per_client_threshold = rule_config.get('per_client_threshold', 20)
                per_ap_threshold = rule_config.get('per_ap_threshold', 40)
                
                # Count association requests per client and per AP
                client_assocs = {}
                ap_assocs = {}
                
                for e in window_events:
                    frame_type = e.get('frame_type', '').lower()
                    if 'assoc' in frame_type and 'request' in frame_type:
                        src_mac = e.get('src_mac', '')
                        dst_mac = e.get('dst_mac', '')
                        
                        if src_mac:
                            client_assocs[src_mac] = client_assocs.get(src_mac, 0) + 1
                        if dst_mac:
                            ap_assocs[dst_mac] = ap_assocs.get(dst_mac, 0) + 1
                
                # Check per-client threshold
                for client_mac, count in client_assocs.items():
                    if count >= per_client_threshold:
                        return True
                
                # Check per-AP threshold
                for ap_mac, count in ap_assocs.items():
                    if count >= per_ap_threshold:
                        return True
                
                # Check total threshold
                total_assocs = sum(client_assocs.values())
                return total_assocs >= threshold
            
            elif rule_type == 'channel_jamming':
                # Rule 12: Channel/Noise Jamming (PHY Layer Attack)
                malformed_threshold = rule_config.get('malformed_frame_threshold', 50)
                
                # Count malformed frames and PHY errors
                malformed_count = 0
                phy_errors = 0
                total_frames = len(window_events)
                
                for e in window_events:
                    flags = e.get('flags', '').lower()
                    frame_type = e.get('frame_type', '').lower()
                    
                    # Detect malformed frames
                    if 'malformed' in flags or 'invalid' in flags or 'error' in flags:
                        malformed_count += 1
                    
                    # Detect PHY errors
                    if 'phy_error' in flags or 'fcs_error' in flags or 'crc_error' in flags:
                        phy_errors += 1
                    
                    # Detect abnormal frame sizes (potential jamming)
                    length = e.get('length', 0)
                    if length > 2500 or length < 10:  # Abnormal sizes
                        malformed_count += 1
                
                # Alert if malformed frames exceed threshold
                if malformed_count >= malformed_threshold:
                    return True
                
                # Alert if PHY error rate is too high
                if total_frames > 10:  # Need enough frames for statistics
                    error_rate = (phy_errors + malformed_count) / total_frames
                    baseline_error_rate = 0.05  # 5% baseline
                    multiplier = rule_config.get('phy_error_rate_multiplier', 3.0)
                    
                    if error_rate > baseline_error_rate * multiplier:
                        return True
                
                return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule_id}: {e}")
            return False
    
    def generate_alert(self, rule_id: str, rule_config: Dict[str, Any], 
                      event: Dict[str, Any], timestamp: datetime) -> Optional[Dict[str, Any]]:
        """Generate an immutable alert with forensic evidence"""
        try:
            # Generate unique alert ID
            alert_id = str(uuid.uuid4())
            
            # Calculate PCAP SHA256 if file exists
            pcap_file = event.get('pcap_file', '')
            pcap_sha256 = ''
            if pcap_file and os.path.exists(pcap_file):
                with open(pcap_file, 'rb') as f:
                    pcap_sha256 = hashlib.sha256(f.read()).hexdigest()
            
            # Get device risk score
            src_mac = event.get('src_mac', '')
            device_risk = self.device_profiles.get(src_mac, {}).get('risk_score', 0.5)
            
            # Calculate alert severity
            base_severity = rule_config.get('severity', 'medium')
            if device_risk > 0.8:
                severity = 'high'
            elif device_risk > 0.6:
                severity = 'medium'
            else:
                severity = 'low'
            
            alert = {
                'alert_id': alert_id,
                'rule_id': rule_id,
                'severity': severity,
                'rules_file': os.path.join(os.path.dirname(__file__), 'rules.yml'),
                'alerts_dir': os.path.join(os.path.dirname(__file__), 'alerts'),
                'timestamp': timestamp.isoformat() + 'Z',
                'evidence': {
                    'pcap_file': pcap_file,
                    'pcap_sha256': pcap_sha256,
                    'event_timestamp': event.get('timestamp', timestamp.isoformat()),
                    'packet_index_or_window': len(self.windows.get(rule_id, [])),
                    'protocol': event.get('protocol', ''),
                    'src_mac': src_mac,
                    'dst_mac': event.get('dst_mac', ''),
                    'length': event.get('length', 0),
                    'flags': event.get('flags', '')
                },
                'metrics': {
                    'device_risk_score': device_risk,
                    'window_size': len(self.windows.get(rule_id, [])),
                    'rule_threshold': rule_config.get('threshold', 10),
                    'confidence': min(0.95, 0.5 + (device_risk * 0.45))
                },
                'status': 'active',
                'rule_description': rule_config.get('description', f'Rule {rule_id} triggered')
            }
            
            return alert
            
        except Exception as e:
            logger.error(f"Error generating alert for rule {rule_id}: {e}")
            return None
    
    def enrich_event_with_kismet(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with Kismet API data"""
        if not self.kismet_client:
            return event
        
        try:
            # Add Kismet device information
            src_mac = event.get('src_mac', '')
            if src_mac:
                # Get device info from Kismet
                devices = self.kismet_client.get_devices()
                for device in devices:
                    if device.get('kismet.device.base.macaddr', '') == src_mac:
                        event['kismet_device_type'] = device.get('kismet.device.base.type', 'Unknown')
                        event['kismet_signal'] = device.get('kismet.device.base.signal/kismet.common.signal.last_signal', -100)
                        event['kismet_channel'] = device.get('kismet.device.base.channel', 0)
                        break
            
            # Add Kismet deauth statistics
            deauth_stats = self.kismet_client.get_deauth_events(window_seconds=60)
            if deauth_stats:
                event['kismet_deauth_stats'] = deauth_stats
            
            # Add Evil Twin detections
            evil_twins = self.kismet_client.detect_evil_twin()
            if evil_twins:
                event['kismet_evil_twins'] = evil_twins
                
        except Exception as e:
            logger.debug(f"Error enriching with Kismet data: {e}")
        
        return event
    
    def enrich_event_with_bettercap(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with Bettercap API data"""
        if not self.bettercap_client:
            return event
        
        try:
            # Add Bettercap deauth detection
            deauth_stats = self.bettercap_client.detect_deauth_flood(window_seconds=60)
            if deauth_stats:
                event['bettercap_deauth_stats'] = deauth_stats
            
            # Add probe flood detection
            probe_stats = self.bettercap_client.detect_probe_flood(window_seconds=60)
            if probe_stats:
                event['bettercap_probe_stats'] = probe_stats
            
            # Add ARP poisoning detection
            arp_conflicts = self.bettercap_client.detect_arp_poisoning(window_seconds=180)
            if arp_conflicts:
                event['bettercap_arp_conflicts'] = arp_conflicts
            
            # Add Karma attack detection
            karma_detections = self.bettercap_client.detect_karma_attack(window_seconds=120)
            if karma_detections:
                event['bettercap_karma_attacks'] = karma_detections
            
            # Add handshake captures
            handshakes = self.bettercap_client.get_handshake_captures()
            if handshakes:
                event['bettercap_handshakes'] = handshakes
                
        except Exception as e:
            logger.debug(f"Error enriching with Bettercap data: {e}")
        
        return event
    
    def write_alert(self, alert: Dict[str, Any]):
        """Write alert to immutable JSON file"""
        try:
            if self.config.get('dry_run', False):
                logger.info(f"[DRY RUN] Would write alert: {alert['alert_id']}")
                return
            
            alert_file = self.alerts_dir / f"{alert['alert_id']}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            self.alert_count += 1
            logger.info(f"Alert written: {alert['alert_id']} ({self.alert_count} total)")
            
        except Exception as e:
            logger.error(f"Error writing alert: {e}")
    
    def get_real_attack_events(self) -> List[Dict[str, Any]]:
        """Get real attack events from comprehensive attack detector"""
        try:
            # Get real attacks from the comprehensive attack detector
            logger.info("🔍 Module4Service: Calling detect_all_attacks()...")
            attacks = self.comprehensive_attack_detector.detect_all_attacks()
            logger.info(f"🔍 Module4Service: Got {len(attacks)} attacks from detector")
            
            # Convert to Module 4 event format
            events = []
            for attack in attacks:
                event = {
                    'event_id': attack.get('id', f"real_attack_{int(time.time())}"),
                    'timestamp': attack.get('timestamp', datetime.now().isoformat()),
                    'type': attack.get('type', 'unknown'),
                    'severity': attack.get('severity', 'medium'),
                    'title': attack.get('title', 'Real Attack Detected'),
                    'message': attack.get('message', 'Attack detected from real network data'),
                    'details': attack.get('details', {}),
                    'source': attack.get('source', 'Comprehensive Attack Detector'),
                    'recommendation': attack.get('recommendation', 'Investigate this attack'),
                    'module': 'Module 4',
                    'real_data': True,
                    'attack_vector': attack.get('attack_vector', 'Unknown'),
                    'cve_references': attack.get('cve_references', [])
                }
                events.append(event)
            
            logger.info(f"Generated {len(events)} real attack events from comprehensive detector")
            return events
            
        except Exception as e:
            logger.error(f"Error getting real attack events: {e}")
            return []
    
    def get_real_attack_statistics(self) -> Dict[str, Any]:
        """Get statistics about real attacks"""
        try:
            return self.comprehensive_attack_detector.get_attack_statistics()
        except Exception as e:
            logger.error(f"Error getting real attack statistics: {e}")
            return {
                'total_attacks': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'by_type': {},
                'by_source': {},
                'by_attack_vector': {},
                'cve_references': []
            }

class EventHandler(FileSystemEventHandler):
    """File system event handler for monitoring Module 3 events"""
    
    def __init__(self, service: Module4Service):
        self.service = service
        self.processed_files = set()
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.json'):
            self.process_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.json'):
            self.process_file(event.src_path)
    
    def process_file(self, file_path: str):
        """Process a Module 3 event file"""
        try:
            if file_path in self.processed_files:
                return
            
            # Small delay to ensure file is fully written
            time.sleep(0.1)
            
            with open(file_path, 'r') as f:
                events = json.load(f)
            
            # Handle both single events and arrays
            if not isinstance(events, list):
                events = [events]
            
            for event in events:
                alerts = self.service.process_event(event)
                for alert in alerts:
                    self.service.write_alert(alert)
            
            self.processed_files.add(file_path)
            logger.debug(f"Processed {len(events)} events from {file_path}")
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Module 4: Attack Detection & Threat Intelligence')
    parser.add_argument('--watch-dir', required=True, help='Directory to watch for Module 3 events')
    parser.add_argument('--rules', default='rules.yml', help='Rules configuration file')
    parser.add_argument('--alerts-dir', default='./alerts', help='Directory for alert JSONs')
    parser.add_argument('--db', default='capture_metadata.db', help='Module 3 database path')
    parser.add_argument('--dry-run', action='store_true', help='Validate rules without writing alerts')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    
    args = parser.parse_args()
    
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Validate paths
    if not os.path.exists(args.watch_dir):
        logger.error(f"Watch directory does not exist: {args.watch_dir}")
        sys.exit(1)
    
    if not os.path.exists(args.rules):
        logger.error(f"Rules file does not exist: {args.rules}")
        sys.exit(1)
    
    if not os.path.exists(args.db):
        logger.error(f"Database does not exist: {args.db}")
        sys.exit(1)
    
    # Initialize service
    config = {
        'watch_dir': args.watch_dir,
        'rules_file': args.rules,
        'alerts_dir': args.alerts_dir,
        'database': args.db,
        'dry_run': args.dry_run
    }
    
    service = Module4Service(config)
    
    # Setup file monitoring
    event_handler = EventHandler(service)
    observer = Observer()
    observer.schedule(event_handler, args.watch_dir, recursive=False)
    
    logger.info(f"Starting Module 4 service...")
    logger.info(f"Watching: {args.watch_dir}")
    logger.info(f"Rules: {args.rules}")
    logger.info(f"Alerts: {args.alerts_dir}")
    logger.info(f"Database: {args.db}")
    if args.dry_run:
        logger.info("DRY RUN MODE - No alerts will be written")
    
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Module 4 service...")
        observer.stop()
    
    observer.join()
    logger.info("Module 4 service stopped")

if __name__ == '__main__':
    main()

