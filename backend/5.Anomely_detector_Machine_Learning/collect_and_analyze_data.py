#!/usr/bin/env python3
"""
Data Collection and Analysis Script
Collects and analyzes real data from Module 1 and Module 3 APIs
"""

import json
import sqlite3
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataCollector:
    """Collects and analyzes data from Module 1 and Module 3"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.module3_db = "capture_metadata.db"
        
    def collect_module1_data(self) -> Dict[str, Any]:
        """Collect data from Module 1 APIs"""
        print("=" * 60)
        print("COLLECTING MODULE 1 DATA (WiFi & Bluetooth)")
        print("=" * 60)
        
        module1_data = {}
        
        try:
            # Get system status
            print("1. Getting system status...")
            response = requests.get(f"{self.base_url}/api/status", timeout=10)
            if response.status_code == 200:
                module1_data["status"] = response.json()
                print(f"   [OK] Status: {module1_data['status']}")
            else:
                print(f"   [FAIL] Status API failed: {response.status_code}")
            
            # Get scan results
            print("2. Getting scan results...")
            response = requests.get(f"{self.base_url}/api/scan/results", timeout=10)
            if response.status_code == 200:
                module1_data["scan_results"] = response.json()
                print(f"   [OK] Scan results: {len(module1_data['scan_results'].get('wifi_networks', []))} WiFi, {len(module1_data['scan_results'].get('bluetooth_devices', []))} Bluetooth")
            else:
                print(f"   [FAIL] Scan results API failed: {response.status_code}")
            
            # Get WiFi networks
            print("3. Getting WiFi networks...")
            response = requests.get(f"{self.base_url}/api/networks", timeout=10)
            if response.status_code == 200:
                module1_data["wifi_networks"] = response.json()
                print(f"   [OK] WiFi networks: {len(module1_data['wifi_networks'].get('networks', []))} networks")
            else:
                print(f"   [FAIL] WiFi networks API failed: {response.status_code}")
            
            # Get Bluetooth devices
            print("4. Getting Bluetooth devices...")
            response = requests.get(f"{self.base_url}/api/bluetooth", timeout=10)
            if response.status_code == 200:
                module1_data["bluetooth_devices"] = response.json()
                print(f"   [OK] Bluetooth devices: {len(module1_data['bluetooth_devices'].get('devices', []))} devices")
            else:
                print(f"   [FAIL] Bluetooth devices API failed: {response.status_code}")
            
            # Get network activity
            print("5. Getting network activity...")
            response = requests.get(f"{self.base_url}/api/network-activity", timeout=10)
            if response.status_code == 200:
                module1_data["network_activity"] = response.json()
                print(f"   [OK] Network activity: {len(module1_data['network_activity'].get('activity', []))} data points")
            else:
                print(f"   [FAIL] Network activity API failed: {response.status_code}")
            
            # Get threat timeline
            print("6. Getting threat timeline...")
            response = requests.get(f"{self.base_url}/api/threat-timeline", timeout=10)
            if response.status_code == 200:
                module1_data["threat_timeline"] = response.json()
                print(f"   [OK] Threat timeline: {len(module1_data['threat_timeline'].get('timeline', []))} events")
            else:
                print(f"   [FAIL] Threat timeline API failed: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("   [FAIL] Cannot connect to Module 1 server. Is it running?")
        except Exception as e:
            print(f"   [FAIL] Error collecting Module 1 data: {e}")
        
        return module1_data
    
    def collect_module3_data(self) -> Dict[str, Any]:
        """Collect data from Module 3 database"""
        print("\n" + "=" * 60)
        print("COLLECTING MODULE 3 DATA (Packet Capture)")
        print("=" * 60)
        
        module3_data = {}
        
        try:
            if not Path(self.module3_db).exists():
                print(f"   [FAIL] Module 3 database not found: {self.module3_db}")
                return module3_data
            
            conn = sqlite3.connect(self.module3_db)
            cursor = conn.cursor()
            
            # Get table schema
            print("1. Getting database schema...")
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"   [OK] Database tables: {len(tables)} tables")
            for table in tables:
                print(f"     - {table[0][:100]}...")
            
            # Get packet count
            print("2. Getting packet statistics...")
            cursor.execute("SELECT COUNT(*) FROM packet_metadata")
            total_packets = cursor.fetchone()[0]
            print(f"   [OK] Total packets: {total_packets}")
            
            # Get recent packets
            print("3. Getting recent packets...")
            cursor.execute("""
                SELECT timestamp, src_mac, dst_mac, length, protocol, rssi, frame_type, flags
                FROM packet_metadata 
                ORDER BY timestamp DESC 
                LIMIT 10
            """)
            recent_packets = cursor.fetchall()
            print(f"   [OK] Recent packets: {len(recent_packets)} packets")
            
            # Get unique devices
            print("4. Getting unique devices...")
            cursor.execute("SELECT COUNT(DISTINCT src_mac) FROM packet_metadata")
            unique_devices = cursor.fetchone()[0]
            print(f"   [OK] Unique devices: {unique_devices}")
            
            # Get protocol distribution
            print("5. Getting protocol distribution...")
            cursor.execute("""
                SELECT protocol, COUNT(*) as count 
                FROM packet_metadata 
                GROUP BY protocol 
                ORDER BY count DESC
            """)
            protocols = cursor.fetchall()
            print(f"   [OK] Protocol distribution: {len(protocols)} protocols")
            for protocol, count in protocols[:5]:
                print(f"     - {protocol}: {count} packets")
            
            # Get frame type distribution
            print("6. Getting frame type distribution...")
            cursor.execute("""
                SELECT frame_type, COUNT(*) as count 
                FROM packet_metadata 
                GROUP BY frame_type 
                ORDER BY count DESC
            """)
            frame_types = cursor.fetchall()
            print(f"   [OK] Frame type distribution: {len(frame_types)} types")
            for frame_type, count in frame_types[:5]:
                print(f"     - {frame_type}: {count} packets")
            
            # Get RSSI statistics
            print("7. Getting RSSI statistics...")
            cursor.execute("""
                SELECT MIN(rssi), MAX(rssi), AVG(rssi), COUNT(rssi)
                FROM packet_metadata 
                WHERE rssi IS NOT NULL
            """)
            rssi_stats = cursor.fetchone()
            if rssi_stats and rssi_stats[3] > 0:
                print(f"   [OK] RSSI stats: Min={rssi_stats[0]}, Max={rssi_stats[1]}, Avg={rssi_stats[2]:.1f}, Count={rssi_stats[3]}")
            else:
                print("   [FAIL] No RSSI data available")
            
            # Get packet size statistics
            print("8. Getting packet size statistics...")
            cursor.execute("""
                SELECT MIN(length), MAX(length), AVG(length), COUNT(length)
                FROM packet_metadata 
                WHERE length IS NOT NULL AND length > 0
            """)
            size_stats = cursor.fetchone()
            if size_stats and size_stats[3] > 0:
                print(f"   [OK] Packet size stats: Min={size_stats[0]}, Max={size_stats[1]}, Avg={size_stats[2]:.1f}, Count={size_stats[3]}")
            else:
                print("   [FAIL] No packet size data available")
            
            # Get time range
            print("9. Getting time range...")
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM packet_metadata")
            time_range = cursor.fetchone()
            if time_range and time_range[0]:
                print(f"   [OK] Time range: {time_range[0]} to {time_range[1]}")
            else:
                print("   [FAIL] No timestamp data available")
            
            # Store data
            module3_data = {
                "total_packets": total_packets,
                "unique_devices": unique_devices,
                "recent_packets": recent_packets,
                "protocols": protocols,
                "frame_types": frame_types,
                "rssi_stats": rssi_stats,
                "size_stats": size_stats,
                "time_range": time_range
            }
            
            conn.close()
            
        except Exception as e:
            print(f"   [FAIL] Error collecting Module 3 data: {e}")
        
        return module3_data
    
    def analyze_data(self, module1_data: Dict[str, Any], module3_data: Dict[str, Any]):
        """Analyze the collected data"""
        print("\n" + "=" * 60)
        print("DATA ANALYSIS")
        print("=" * 60)
        
        # Module 1 Analysis
        print("MODULE 1 ANALYSIS:")
        if "scan_results" in module1_data:
            wifi_networks = module1_data["scan_results"].get("wifi_networks", [])
            bluetooth_devices = module1_data["scan_results"].get("bluetooth_devices", [])
            
            print(f"  WiFi Networks: {len(wifi_networks)}")
            if wifi_networks:
                # Analyze WiFi networks
                security_types = {}
                channels = {}
                rssi_values = []
                
                for network in wifi_networks:
                    # Security analysis
                    security = network.get("security", "Unknown")
                    security_types[security] = security_types.get(security, 0) + 1
                    
                    # Channel analysis
                    channel = network.get("channel", 0)
                    if channel > 0:
                        channels[channel] = channels.get(channel, 0) + 1
                    
                    # RSSI analysis
                    rssi = network.get("rssi")
                    if rssi is not None:
                        rssi_values.append(rssi)
                
                print(f"    Security types: {security_types}")
                print(f"    Channels used: {channels}")
                if rssi_values:
                    print(f"    RSSI range: {min(rssi_values)} to {max(rssi_values)} dBm")
            
            print(f"  Bluetooth Devices: {len(bluetooth_devices)}")
            if bluetooth_devices:
                # Analyze Bluetooth devices
                device_types = {}
                rssi_values = []
                
                for device in bluetooth_devices:
                    # Device type analysis
                    device_type = device.get("device_type", "Unknown")
                    device_types[device_type] = device_types.get(device_type, 0) + 1
                    
                    # RSSI analysis
                    rssi = device.get("rssi")
                    if rssi is not None:
                        rssi_values.append(rssi)
                
                print(f"    Device types: {device_types}")
                if rssi_values:
                    print(f"    RSSI range: {min(rssi_values)} to {max(rssi_values)} dBm")
        
        # Module 3 Analysis
        print("\nMODULE 3 ANALYSIS:")
        if module3_data:
            print(f"  Total Packets: {module3_data.get('total_packets', 0)}")
            print(f"  Unique Devices: {module3_data.get('unique_devices', 0)}")
            
            if module3_data.get("protocols"):
                print("  Top Protocols:")
                for protocol, count in module3_data["protocols"][:5]:
                    print(f"    - {protocol}: {count} packets")
            
            if module3_data.get("frame_types"):
                print("  Top Frame Types:")
                for frame_type, count in module3_data["frame_types"][:5]:
                    print(f"    - {frame_type}: {count} packets")
            
            if module3_data.get("rssi_stats") and module3_data["rssi_stats"][3] > 0:
                rssi_stats = module3_data["rssi_stats"]
                print(f"  RSSI Statistics: Min={rssi_stats[0]}, Max={rssi_stats[1]}, Avg={rssi_stats[2]:.1f}")
            
            if module3_data.get("size_stats") and module3_data["size_stats"][3] > 0:
                size_stats = module3_data["size_stats"]
                print(f"  Packet Size Statistics: Min={size_stats[0]}, Max={size_stats[1]}, Avg={size_stats[2]:.1f}")
        
        # Cross-module Analysis
        print("\nCROSS-MODULE ANALYSIS:")
        module1_devices = 0
        module3_devices = 0
        
        if "scan_results" in module1_data:
            module1_devices = len(module1_data["scan_results"].get("wifi_networks", [])) + len(module1_data["scan_results"].get("bluetooth_devices", []))
        
        if module3_data:
            module3_devices = module3_data.get("unique_devices", 0)
        
        print(f"  Module 1 devices: {module1_devices}")
        print(f"  Module 3 devices: {module3_devices}")
        if module3_devices > 0:
            coverage = (module1_devices / module3_devices) * 100
            print(f"  Device coverage: {coverage:.1f}%")
    
    def save_analysis(self, module1_data: Dict[str, Any], module3_data: Dict[str, Any]):
        """Save analysis to file"""
        analysis_data = {
            "timestamp": datetime.now().isoformat(),
            "module1_data": module1_data,
            "module3_data": module3_data
        }
        
        filename = f"data_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(analysis_data, f, indent=2, default=str)
        
        print(f"\nAnalysis saved to: {filename}")

def main():
    """Main function"""
    print("DATA COLLECTION AND ANALYSIS")
    print("Collecting real data from Module 1 and Module 3")
    print("=" * 60)
    
    collector = DataCollector()
    
    # Collect data
    module1_data = collector.collect_module1_data()
    module3_data = collector.collect_module3_data()
    
    # Analyze data
    collector.analyze_data(module1_data, module3_data)
    
    # Save analysis
    collector.save_analysis(module1_data, module3_data)
    
    print("\n" + "=" * 60)
    print("DATA COLLECTION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
