#!/usr/bin/env python3
"""
Live Packet Capture System
- No sudo password prompts needed (uses dumpcap with capabilities)
- Start/stop capture via API
- WebSocket broadcasting every 5 seconds
- Clean CSV-like parsing from tshark
"""

import subprocess
import threading
import time
import json
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional
import asyncio

class LivePacketCapture:
    """Live packet capture without sudo prompts"""
    
    def __init__(self):
        self.running = False
        self.process: Optional[subprocess.Popen] = None
        self.capture_thread: Optional[threading.Thread] = None
        
        # Store packets in memory (last 1000)
        self.packets = deque(maxlen=1000)
        self.suspicious_packets = deque(maxlen=500)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'protocols': defaultdict(int),
            'suspicious_count': 0,
            'start_time': None
        }
        
        # Traffic monitoring for DoS detection - using time windows
        self.ip_traffic = defaultdict(lambda: {'count': 0, 'first_packet_time': None, 'last_reset': time.time()})
        
        # ARP monitoring for Spoofing detection
        self.arp_traffic = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
        
        # Port scan detection: track unique ports accessed by each IP
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'first_port_time': None, 'last_reset': time.time()})
        
        # WebSocket clients
        self.ws_clients = []
        
        # Get local MACs to prevent self-detection
        self.local_macs = self._get_local_macs()
        print(f"🔒 Local MAC Addresses: {self.local_macs}")
        
    def _get_local_macs(self) -> set:
        """Get all local MAC addresses to ignore own traffic"""
        macs = set()
        try:
            # Method 1: ip link (Linux)
            try:
                result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'link/ether' in line:
                            # Extract MAC: "    link/ether 00:11:22:33:44:55 brd ..."
                            parts = line.split('link/ether ')
                            if len(parts) > 1:
                                mac = parts[1].split()[0].strip()
                                macs.add(mac.lower())
                                macs.add(mac.upper())
                        
                        # Also check for loopback (often used by virtual gateways)
                        if 'link/loopback' in line:
                            parts = line.split('link/loopback ')
                            if len(parts) > 1:
                                mac = parts[1].split()[0].strip()
                                macs.add(mac.lower())
                                macs.add(mac.upper())
            except Exception as e:
                print(f"Error getting MACs from ip link: {e}")

            # Method 2: UUID fallback
            import uuid
            mac_num = uuid.getnode()
            mac = ':'.join(['{:02x}'.format((mac_num >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
            macs.add(mac.lower())
            
            # Add Null MAC (common for virtual interfaces/any capture)
            macs.add('00:00:00:00:00:00')
            
            return macs
        except Exception as e:
            print(f"Error getting local MACs: {e}")
            return macs
        
    def start_capture(self):
        """Start packet capture"""
        if self.running:
            return {'status': 'already_running', 'message': 'Capture is already running'}
        
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        return {'status': 'started', 'message': 'Packet capture started'}
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.running:
            return {'status': 'not_running', 'message': 'Capture is not running'}
        
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
        
        return {'status': 'stopped', 'message': 'Packet capture stopped'}
    
    def _capture_loop(self):
        """Main capture loop using tshark"""
        try:
            # TShark command - CSV-like output
            cmd = [
                'tshark',
                '-i', 'any',           # All interfaces
                '-Y', 'not tcp.srcport == 8000', # Exclude backend API responses
                '-T', 'fields',        # Field output
                '-e', 'frame.number',
                '-e', 'frame.time_epoch',
                '-e', 'frame.len',
                '-e', 'frame.protocols',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'tcp.flags',
                '-e', 'icmp.type',
                '-e', 'arp.opcode',
                '-e', 'arp.src.proto_ipv4', # Add ARP source IP
                '-e', 'arp.dst.proto_ipv4', # Add ARP dest IP
                '-e', 'eth.src',            # Add Source MAC
                '-E', 'separator=,',   # CSV separator
                '-E', 'occurrence=f'   # First occurrence only
            ]
            
            print(f"🚀 Starting tshark capture: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                bufsize=1
            )
            
            packet_count = 0
            start_time = time.time()
            last_pps_update = start_time
            
            print("✅ Capture started! Processing packets...")
            
            for line in self.process.stdout:
                if not self.running:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Parse CSV line
                packet = self._parse_csv_packet(line)
                if packet:
                    packet_count += 1
                    self.stats['total_packets'] += 1
                    
                    # Add to packets list
                    self.packets.append(packet)
                    
                    # Update statistics
                    self._update_statistics(packet)
                    
                    # Check if suspicious
                    if self._is_suspicious(packet):
                        packet['suspicious'] = True
                        packet['alert_type'] = self._get_alert_type(packet)
                        self.suspicious_packets.append(packet)
                        self.stats['suspicious_count'] += 1
                    
                    # Update packets per second every second
                    current_time = time.time()
                    if current_time - last_pps_update >= 1.0:
                        # Calculate instantaneous PPS (packets in the last second)
                        # We need to track packets since last update
                        if not hasattr(self, 'last_packet_count'):
                            self.last_packet_count = 0
                        
                        packets_since_last = packet_count - self.last_packet_count
                        self.stats['packets_per_second'] = packets_since_last
                        
                        self.last_packet_count = packet_count
                        last_pps_update = current_time
                    
                    # Print progress every 100 packets
                    if packet_count % 100 == 0:
                        print(f"📦 Captured {packet_count} packets ({self.stats['packets_per_second']} pps, "
                              f"{self.stats['suspicious_count']} suspicious)")
            
        except Exception as e:
            print(f"❌ Error in capture loop: {e}")
        finally:
            self.running = False
            print("🛑 Capture stopped")
    
    def _parse_csv_packet(self, csv_line: str) -> Optional[Dict[str, Any]]:
        """Parse CSV line into packet dictionary"""
        try:
            fields = csv_line.split(',')
            
            # Ensure we have enough fields (now 16 with eth.src)
            while len(fields) < 16:
                fields.append('')
            
            # Determine protocol
            protocols = fields[3].lower() if fields[3] else ''
            if 'tcp' in protocols:
                protocol = 'TCP'
                src_port = fields[6]
                dst_port = fields[7]
            elif 'udp' in protocols:
                protocol = 'UDP'
                src_port = fields[8]
                dst_port = fields[9]
            elif 'icmp' in protocols:
                protocol = 'ICMP'
                src_port = ''
                dst_port = ''
            elif 'arp' in protocols:
                protocol = 'ARP'
                src_port = ''
                dst_port = ''
            else:
                protocol = protocols.split(':')[0].upper() if ':' in protocols else 'OTHER'
                src_port = ''
                dst_port = ''
            
            # Handle IP addresses (use ARP IPs if protocol is ARP)
            src_ip = fields[4]
            dst_ip = fields[5]
            
            if protocol == 'ARP':
                src_ip = fields[13] # arp.src.proto_ipv4
                dst_ip = fields[14] # arp.dst.proto_ipv4
                
            src_mac = fields[15] # eth.src
            
            packet = {
                'id': fields[0],
                'timestamp': float(fields[1]) if fields[1] else time.time(),
                'time_str': datetime.fromtimestamp(float(fields[1])).strftime('%H:%M:%S.%f')[:-3] if fields[1] else '',
                'length': int(fields[2]) if fields[2] else 0,
                'protocol': protocol,
                'protocols': fields[3],
                'src_ip': src_ip or '',
                'dst_ip': dst_ip or '',
                'src_port': src_port or '',
                'dst_port': dst_port or '',
                'tcp_flags': fields[10] if protocol == 'TCP' else '',
                'src_mac': src_mac or '',
                'suspicious': False,
                'alert_type': None
            }
            
            return packet
            
        except Exception as e:
            return None
    
    def _update_statistics(self, packet: Dict[str, Any]):
        """Update statistics"""
        # Protocol count
        self.stats['protocols'][packet['protocol']] += 1
        
        # IP traffic monitoring with time windows
        if packet['src_ip']:
            ip_data = self.ip_traffic[packet['src_ip']]
            current_time = time.time()
            
            # If this is first packet or window expired, reset
            if ip_data['first_packet_time'] is None or (current_time - ip_data['last_reset']) > 5.0:
                ip_data['count'] = 1
                ip_data['first_packet_time'] = current_time
                ip_data['last_reset'] = current_time
            else:
                ip_data['count'] += 1
                
        # ARP traffic monitoring
        if packet['protocol'] == 'ARP' and packet['src_ip']:
            arp_data = self.arp_traffic[packet['src_ip']]
            current_time = time.time()
            
            # Reset every 10 seconds
            if (current_time - arp_data['last_reset']) > 10.0:
                arp_data['count'] = 1
                arp_data['last_reset'] = current_time
            else:
                arp_data['count'] += 1
    
    def _is_suspicious(self, packet: Dict[str, Any]) -> bool:
        """Check if packet is suspicious - ONLY mark as suspicious during ACTUAL ATTACKS"""
        
        # Ignore our own traffic (prevent self-detection of mitigation)
        if packet.get('src_mac') and (packet.get('src_mac').lower() in self.local_macs or packet.get('src_mac').upper() in self.local_macs):
            return False
        
        # PRIORITY 1: Check for DoS Attack (>300 packets in 5 seconds from same IP)
        # Normal browsing generates ~50-100 packets/5sec, attacks generate 1000+
        # Lowered to 300 to catch slower attacks (~60 req/s)
        # This is checked FIRST because it's more critical
        # PRIORITY 1: Check for DoS Attack (>1000 packets in 5 seconds from same IP)
        # Normal browsing generates ~50-100 packets/5sec, attacks generate 1000+
        # Raised to 1000 to filter high background noise (~170 pps)
        # This is checked FIRST because it's more critical
        if packet['src_ip']:
            ip_data = self.ip_traffic.get(packet['src_ip'])
            if ip_data and ip_data['count'] > 1000:
                return True
        
        # PRIORITY 2: Check for Port Scan (>10 DIFFERENT destination ports in 10 seconds)
        # Normal usage accesses 1-5 ports, port scans probe 10-1000+ DIFFERENT ports
        # Note: High volume to SAME port = DoS, not port scan
        if packet['src_ip'] and packet['dst_port']:
            try:
                port = int(packet['dst_port'])
                
                # Ignore port 8000 for port scan detection (it's the API)
                if port == 8000:
                    return False
                
                # Ignore packets with ACK flag (return traffic/responses)
                # This prevents false positives from normal web browsing where servers reply to multiple ephemeral ports
                if packet.get('protocol') == 'TCP' and packet.get('tcp_flags'):
                    try:
                        # TShark returns flags as hex string (e.g., 0x0010)
                        flags_str = packet['tcp_flags']
                        if flags_str.startswith('0x'):
                            flags = int(flags_str, 16)
                        else:
                            flags = int(flags_str) if flags_str.strip() else 0
                            
                        # ACK flag is 0x10 (16)
                        if flags & 0x10:
                            return False
                    except Exception:
                        pass
                
                # Ignore DNS traffic (UDP src port 53)
                # DNS servers reply to multiple ephemeral ports, which looks like a scan
                if packet.get('protocol') == 'UDP':
                    src_port = packet.get('src_port', '')
                    if str(src_port) == '53':
                        return False
                    
                scan_data = self.port_scan_tracker[packet['src_ip']]
                current_time = time.time()
                
                # Reset if more than 10 seconds passed
                if scan_data['first_port_time'] is None or (current_time - scan_data['last_reset']) > 10.0:
                    scan_data['ports'].clear()
                    scan_data['first_port_time'] = current_time
                    scan_data['last_reset'] = current_time
                
                # Add port to set (sets automatically handle duplicates)
                scan_data['ports'].add(port)
                
                # Port scan detected: >20 DIFFERENT ports in 10 seconds
                # If accessing same port repeatedly, it won't increase the set size
                if len(scan_data['ports']) > 20:
                    # Check if this IP is doing a DoS attack (suppress port scan if so)
                    ip_data = self.ip_traffic.get(packet['src_ip'])
                    if ip_data and ip_data['count'] > 1000:
                        return False
                    return True
            except:
                pass
        
        # PRIORITY 3: Check for ARP Spoofing (> 5 ARP packets in 10 seconds from same IP)
        # Normal ARP traffic is very low (1-2 packets per minute per device)
        if packet['protocol'] == 'ARP' and packet['src_ip']:
            arp_data = self.arp_traffic.get(packet['src_ip'])
            if arp_data and arp_data['count'] > 15:  # Lowered to 15 to catch slower attacks (default tools ~2pps)
                return True
        
        # DO NOT flag normal traffic as suspicious
        # Normal web browsing, DNS queries, ARP, HTTPS are all legitimate
        
        return False
    
    def _get_alert_type(self, packet: Dict[str, Any]) -> str:
        """Determine alert type - DoS takes absolute priority over port scan"""
        
        # PRIORITY 1: Check for DoS Attack (>1000 packets in 5 seconds)
        # This is checked FIRST and EXCLUSIVELY - if DoS is detected, return immediately
        if packet['src_ip']:
            ip_data = self.ip_traffic.get(packet['src_ip'])
            if ip_data and ip_data['count'] > 1000:
                # Determine DoS type based on protocol
                if packet['protocol'] == 'ICMP':
                    return 'ICMP_FLOOD'
                elif packet['protocol'] == 'TCP' and packet['tcp_flags'] and 'S' in packet['tcp_flags']:
                    return 'SYN_FLOOD'
                else:
                    return 'DOS_ATTACK'
        
        # PRIORITY 2: Check for Port Scan (>20 different ports in 10 seconds)
        # ONLY classify as port scan if it's NOT a DoS attack
        if packet['src_ip'] and packet['dst_port']:
            # First check if this IP is doing a DoS attack
            ip_data = self.ip_traffic.get(packet['src_ip'])
            if ip_data and ip_data['count'] > 1000: # Raised DoS threshold for alert type
                # This IP is doing DoS, don't flag for port scan
                return None
            
            # Not a DoS attack, check for port scan
            scan_data = self.port_scan_tracker.get(packet['src_ip'])
            if scan_data and len(scan_data['ports']) > 20: # Raised port scan threshold for alert type
                return 'PORT_SCAN'
        
        # PRIORITY 3: Check for ARP Spoofing
        if packet['protocol'] == 'ARP' and packet['src_ip']:
            arp_data = self.arp_traffic.get(packet['src_ip'])
            if arp_data and arp_data['count'] > 5:
                return 'ARP_SPOOF'
        
        return None
    
    def get_packets(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent packets"""
        return list(self.packets)[-count:]
    
    def get_suspicious_packets(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get suspicious packets"""
        return list(self.suspicious_packets)[-count:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics"""
        # Top IPs
        sorted_ips = sorted(
            self.ip_traffic.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]
        
        top_ips = [
            {'ip': ip, 'count': data['count']}
            for ip, data in sorted_ips
        ]
        
        # Alert distribution
        alert_types = defaultdict(int)
        for packet in self.suspicious_packets:
            if packet.get('alert_type'):
                alert_types[packet['alert_type']] += 1
        
        return {
            'total_packets': self.stats['total_packets'],
            'packets_per_second': self.stats['packets_per_second'],
            'protocols': dict(self.stats['protocols']),
            'suspicious_count': self.stats['suspicious_count'],
            'top_ips': top_ips,
            'alert_types': dict(alert_types),
            'start_time': self.stats['start_time']
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get capture status"""
        return {
            'running': self.running,
            'total_packets': self.stats['total_packets'],
            'packets_per_second': self.stats['packets_per_second'],
            'suspicious_count': self.stats['suspicious_count'],
            'start_time': self.stats['start_time']
        }

# Global instance
_capture_instance = None

def get_live_capture() -> LivePacketCapture:
    """Get global capture instance"""
    global _capture_instance
    if _capture_instance is None:
        _capture_instance = LivePacketCapture()
    return _capture_instance

