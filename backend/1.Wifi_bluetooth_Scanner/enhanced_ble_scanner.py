#!/usr/bin/env python3
"""
Enhanced BLE Scanner for Module 1
Replaces the old Bluetooth scanner with a more efficient BLE-only scanner
"""

import asyncio
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

# Ensure bleak is installed
try:
    from bleak import BleakScanner
except ImportError:
    os.system('pip install bleak')
    from bleak import BleakScanner


class EnhancedBLEScanner:
    """Enhanced BLE Scanner that integrates with Module 1"""
    
    def __init__(self):
        self.scanning = False
        self.bluetooth_devices = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_thread = None
        self._lock = threading.Lock()
        
    def start_comprehensive_scan(self, duration: int = 10):
        """Start a comprehensive BLE scan"""
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_start_time = datetime.now()
        self.bluetooth_devices = []
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(duration,),
            daemon=True
        )
        self.scan_thread.start()
        
    def _run_scan_thread(self, duration: int):
        """Run the BLE scan in a separate thread"""
        try:
            # Run the async scan
            asyncio.run(self._scan_devices(duration))
        except Exception as e:
            print(f"BLE scan error: {e}")
        finally:
            with self._lock:
                self.scanning = False
                self.scan_end_time = datetime.now()
    
    async def _scan_devices(self, duration: int):
        """Perform BLE scan with advertisement data"""
        try:
            print(f"Starting BLE scan for {duration} seconds...")
            devices = await BleakScanner.discover(return_adv=True, timeout=duration)
            
            with self._lock:
                self.bluetooth_devices = []
                
                if not devices:
                    print("No BLE devices found.")
                    return
                
                device_count = 0
                for device_id, (device, adv_data) in devices.items():
                    device_count += 1
                    
                    # Get device information
                    address = device.address
                    
                    # Try to get the actual name
                    name = adv_data.local_name or device.name or ""
                    
                    # Get RSSI if available
                    rssi = adv_data.rssi if adv_data.rssi is not None else -100
                    
                    # Get manufacturer data
                    manufacturer_data = adv_data.manufacturer_data
                    manufacturer_name = "Unknown"
                    
                    if manufacturer_data:
                        # Common manufacturer IDs
                        manufacturer_names = {
                            6: "Microsoft",
                            76: "Apple", 
                            117: "Samsung",
                            48: "Google",
                            89: "Intel",
                            207: "Qualcomm",
                        }
                        
                        for mfg_id, mfg_name in manufacturer_names.items():
                            if mfg_id in manufacturer_data:
                                manufacturer_name = mfg_name
                                break
                    
                    # Get services
                    services = list(adv_data.service_uuids) if adv_data.service_uuids else []
                    
                    # Create device info
                    if not name.strip():
                        # Skip unnamed/unknown devices per request
                        continue

                    device_info = {
                        'id': device_count,
                        'name': name,
                        'address': address,
                        'rssi': rssi,
                        'manufacturer': manufacturer_name,
                        'manufacturer_data': dict(manufacturer_data) if manufacturer_data else {},
                        'services': services,
                        'connectable': True,  # BLE devices are generally connectable
                        'discovery_method': 'BLE Advertisement',
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'signal_strength': f"{rssi} dBm" if rssi != -100 else "Unknown",
                        'device_type': 'BLE Device',
                        'device_class': 0,  # BLE devices
                        'paired': False,
                        'status': 'Discovered'
                    }
                    
                    self.bluetooth_devices.append(device_info)
                    print(f"Found BLE device: {name} - {address} (RSSI: {rssi} dBm)")
                
                print(f"BLE scan completed. Found {len(self.bluetooth_devices)} devices.")
                
        except Exception as e:
            print(f"BLE scan failed: {e}")
            with self._lock:
                self.bluetooth_devices = []
    
    def get_scan_results(self) -> Dict[str, Any]:
        """Get scan results in the format expected by Module 1"""
        with self._lock:
            scan_duration = 0
            if self.scan_start_time and self.scan_end_time:
                scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            elif self.scan_start_time:
                scan_duration = (datetime.now() - self.scan_start_time).total_seconds()
            
            # Calculate statistics
            total_devices = len(self.bluetooth_devices)
            manufacturers = {}
            signal_strengths = []
            
            for device in self.bluetooth_devices:
                # Count manufacturers
                manufacturer = device.get('manufacturer', 'Unknown')
                manufacturers[manufacturer] = manufacturers.get(manufacturer, 0) + 1
                
                # Collect signal strengths
                rssi = device.get('rssi', -100)
                if rssi != -100:
                    signal_strengths.append(rssi)
            
            avg_signal = sum(signal_strengths) / len(signal_strengths) if signal_strengths else -100
            
            return {
                'bluetooth_devices': self.bluetooth_devices,
                'statistics': {
                    'total_devices': total_devices,
                    'manufacturers': manufacturers,
                    'average_signal_strength': round(avg_signal, 2),
                    'strongest_signal': max(signal_strengths) if signal_strengths else -100,
                    'weakest_signal': min(signal_strengths) if signal_strengths else -100,
                    'scan_duration': round(scan_duration, 2)
                },
                'scan_info': {
                    'scan_type': 'BLE Advertisement Scan',
                    'start_time': self.scan_start_time.isoformat() if self.scan_start_time else None,
                    'end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
                    'duration': round(scan_duration, 2),
                    'scanner_version': 'Enhanced BLE Scanner v1.0'
                }
            }
    
    def stop_scan(self):
        """Stop the current scan"""
        with self._lock:
            self.scanning = False
    
    def is_scanning(self) -> bool:
        """Check if scan is currently running"""
        with self._lock:
            return self.scanning
    
    def get_device_count(self) -> int:
        """Get the number of discovered devices"""
        with self._lock:
            return len(self.bluetooth_devices)
    
    def get_devices_by_manufacturer(self, manufacturer: str) -> List[Dict]:
        """Get devices filtered by manufacturer"""
        with self._lock:
            return [device for device in self.bluetooth_devices 
                   if device.get('manufacturer', '').lower() == manufacturer.lower()]
    
    def get_strongest_signals(self, count: int = 5) -> List[Dict]:
        """Get devices with strongest signal strength"""
        with self._lock:
            sorted_devices = sorted(
                [device for device in self.bluetooth_devices if device.get('rssi', -100) != -100],
                key=lambda x: x.get('rssi', -100),
                reverse=True
            )
            return sorted_devices[:count]


# For backward compatibility, create an alias
EnhancedBluetoothScanner = EnhancedBLEScanner
