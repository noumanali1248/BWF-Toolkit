#!/usr/bin/env python3
"""
Unified Bluetooth Scanner - Detects both Classic Bluetooth and BLE devices
Uses hcitool, bluetoothctl, and Bleak
Detects smartphones, laptops, speakers, smartwatches, etc.
"""

import subprocess
import re
import time
import threading
import asyncio
from datetime import datetime
from typing import List, Dict, Any
import logging

# Import Bleak for BLE scanning
try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    print("Warning: Bleak not available for BLE scanning")

# Import Scapy for OUI lookup
try:
    from scapy.all import conf
    # Ensure manufdb is loaded
    if not conf.manufdb:
        conf.load_manuf()
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available for OUI lookup")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UnifiedBluetoothScanner:
    """Unified scanner for both Classic Bluetooth and BLE devices"""
    
    def __init__(self):
        self.classic_devices = {}
        self.ble_devices = {}
    
    def scan_all_bluetooth_devices(self, classic_duration: int = 20, ble_duration: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan for BOTH Classic Bluetooth and BLE devices
        Returns separate lists for each type
        """
        print("🔍 Starting Unified Bluetooth Scan")
        print("=" * 80)
        print("📡 Scanning for:")
        print("   ✓ Classic Bluetooth: Smartphones, laptops, speakers")
        print("   ✓ BLE Devices: Smartwatches, fitness trackers, beacons")
        print()
        
        results = {
            'classic_devices': [],
            'ble_devices': []
        }
        
        # STEP 1: Scan Classic Bluetooth devices
        print("📱 STEP 1: Classic Bluetooth Scan")
        print("-" * 80)
        classic_devices = self._scan_classic_bluetooth(duration=classic_duration)
        results['classic_devices'] = classic_devices
        print(f"✅ Found {len(classic_devices)} Classic Bluetooth device(s)")
        print()
        
        # STEP 2: Scan BLE devices
        print("📡 STEP 2: BLE Device Scan")
        print("-" * 80)
        ble_devices = self._scan_ble_devices(duration=ble_duration)
        results['ble_devices'] = ble_devices
        print(f"✅ Found {len(ble_devices)} BLE device(s)")
        print()
        
        # --- MERGE LOGIC START ---
        # Enrich Classic devices with BLE data (Manufacturer specifically)
        # because BLE Advertising Data often contains Manufacturer Name while Classic scan doesn't.
        print("🔄 Merging scan results...")
        ble_map = {d['address']: d for d in ble_devices}
        
        merged_count = 0
        for classic_dev in classic_devices:
            mac = classic_dev['address']
            if mac in ble_map:
                ble_dev = ble_map[mac]
                
                # Check if Classic thinks it's "Unknown" but BLE knows it
                if classic_dev.get('manufacturer') == 'Unknown' and ble_dev.get('manufacturer') != 'Unknown':
                    classic_dev['manufacturer'] = ble_dev['manufacturer']
                    classic_dev['vendor'] = ble_dev['vendor']
                    
                    # If Classic type is generic, update it
                    if classic_dev.get('device_type') == 'Classic Bluetooth Device':
                        if 'Apple' in classic_dev['manufacturer']:
                             classic_dev['device_type'] = 'Apple Device (Dual-Mode)'
                        elif 'Samsung' in classic_dev['manufacturer']:
                             classic_dev['device_type'] = 'Samsung Device (Dual-Mode)'
                        else:
                             classic_dev['device_type'] = f"{classic_dev['manufacturer']} Device (Dual-Mode)"
                    
                    merged_count += 1
        
        print(f"✅ Enriched {merged_count} Classic devices with BLE metadata")
        print()
        # --- MERGE LOGIC END ---
        
        print("=" * 80)
        print(f"✅ Total Scan Complete")
        print(f"   - Classic Bluetooth: {len(classic_devices)}")
        print(f"   - BLE Devices: {len(ble_devices)}")
        print(f"   - TOTAL: {len(classic_devices) + len(ble_devices)}")
        print("=" * 80)
        
        return results
    
    def _scan_classic_bluetooth(self, duration: int = 20) -> List[Dict[str, Any]]:
        """Scan for Classic Bluetooth devices only"""
        all_devices = []
        
        # Method 1: hcitool scan
        print("   Method 1: hcitool (Classic Bluetooth)")
        hcitool_devices = self._scan_with_hcitool()
        all_devices.extend(hcitool_devices)
        
        # Method 2: bluetoothctl scan
        print("   Method 2: bluetoothctl (Comprehensive)")
        bluetoothctl_devices = self._scan_with_bluetoothctl(duration=duration)
        
        # Merge devices (avoid duplicates)
        existing_macs = {d['address'] for d in all_devices}
        for device in bluetoothctl_devices:
            if device['address'] not in existing_macs:
                all_devices.append(device)
        
        return all_devices
    
    def _scan_ble_devices(self, duration: int = 10) -> List[Dict[str, Any]]:
        """Scan for BLE devices only"""
        if not BLEAK_AVAILABLE:
            logger.warning("Bleak not available, skipping BLE scan")
            return []
        
        try:
            print(f"   Scanning BLE devices for {duration} seconds...")
            
            # Run BLE scan
            discovered_devices = []
            
            async def scan_ble():
                devices = await BleakScanner.discover(return_adv=True, timeout=duration)
                
                for device_id, (device, adv_data) in devices.items():
                    # Get device name
                    name = adv_data.local_name or device.name or "Unknown BLE Device"
                    
                    # Get manufacturer
                    manufacturer = "Unknown"
                    manufacturer_id = None
                    if adv_data.manufacturer_data:
                        for mfg_id in adv_data.manufacturer_data.keys():
                            manufacturer_id = mfg_id
                            manufacturer_names = {
                                6: "Microsoft", 76: "Apple", 117: "Samsung", 48: "Google",
                                89: "Intel", 207: "Qualcomm", 224: "Google"
                            }
                            manufacturer = manufacturer_names.get(mfg_id, f"Unknown ({mfg_id})")
                            break
                    
                    # Get services
                    services = []
                    if adv_data.service_uuids:
                        for svc_uuid in adv_data.service_uuids:
                            services.append({
                                'uuid': svc_uuid,
                                'name': svc_uuid
                            })
                    
                    # Get RSSI
                    rssi = adv_data.rssi if hasattr(adv_data, 'rssi') else -100
                    signal_quality = "Excellent" if rssi > -50 else "Good" if rssi > -60 else "Fair" if rssi > -70 else "Weak" if rssi > -80 else "Very Weak"
                    
                    # Determine device type
                    device_type = "BLE Device"
                    if manufacturer == "Apple":
                        device_type = "Apple BLE Device"
                    elif manufacturer == "Microsoft":
                        device_type = "Microsoft BLE Device"
                    elif manufacturer == "Samsung":
                        device_type = "Samsung BLE Device"
                    
                    device_info = {
                        'name': name,
                        'address': device.address,
                        'mac_address': device.address,
                        'manufacturer': manufacturer,
                        'vendor': manufacturer,
                        'manufacturer_id': manufacturer_id,
                        'device_type': device_type,
                        'rssi': rssi,
                        'signal_strength': rssi,
                        'signal_quality': signal_quality,
                        'services': services,
                        'service_count': len(services),
                        'bluetooth_type': 'BLE (Bluetooth Low Energy)',
                        'nearby': True,
                        'discoverable': True,
                        'discovery_method': 'Bleak (BLE)',
                        'scan_timestamp': datetime.now().isoformat(),
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    discovered_devices.append(device_info)
                
                return discovered_devices
            
            # Run async scan (handle event loop properly)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If loop is already running, create task
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, scan_ble())
                        devices = future.result(timeout=duration + 5)
                else:
                    devices = asyncio.run(scan_ble())
            except RuntimeError:
                # Fallback: run in new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, scan_ble())
                    devices = future.result(timeout=duration + 5)
            
            # Get unique devices only
            unique_devices = {}
            for device in devices:
                mac = device['address']
                if mac not in unique_devices:
                    unique_devices[mac] = device
            
            logger.info(f"BLE scan found {len(unique_devices)} unique devices")
            return list(unique_devices.values())
            
        except Exception as e:
            logger.error(f"BLE scan failed: {e}")
            return []
    
    def _scan_with_hcitool(self) -> List[Dict[str, Any]]:
        """Scan using hcitool - detects Classic Bluetooth devices"""
        devices = []
        
        try:
            print("   Executing: hcitool scan --flush...")
            
            # Run hcitool scan
            result = subprocess.run(
                ['hcitool', 'scan', '--flush'],
                capture_output=True,
                text=True,
                timeout=25
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Look for MAC address pattern
                    mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
                    
                    if mac_match:
                        mac = mac_match.group(1).upper()
                        
                        # Get device name (everything after MAC)
                        name = line.split(mac, 1)[1].strip() if mac in line.upper() else "Unknown Device"
                        
                        if not name or name == '':
                            name = "Unknown Device"
                        
                        # Get additional device information
                        device_info = self._get_device_details(mac, name)
                        devices.append(device_info)
                        
                        logger.info(f"hcitool: {name} ({mac})")
            
            else:
                logger.warning(f"hcitool failed with code {result.returncode}")
                if result.stderr:
                    logger.warning(f"Error: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            logger.warning("hcitool scan timed out")
        except Exception as e:
            logger.error(f"hcitool scan failed: {e}")
        
        return devices
    
    def _scan_with_bluetoothctl(self, duration: int = 15) -> List[Dict[str, Any]]:
        """Scan using bluetoothctl - Interactive Bluetooth scanning"""
        devices = {}
        
        try:
            print(f"   Starting bluetoothctl scan for {duration} seconds...")
            
            # Start bluetoothctl in interactive mode
            process = subprocess.Popen(
                ['bluetoothctl'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Send scan on command
            process.stdin.write('scan on\n')
            process.stdin.flush()
            
            # Collect discovered devices
            def read_output():
                try:
                    for line in process.stdout:
                        # Look for device discoveries
                        # Format: [NEW] Device AA:BB:CC:DD:EE:FF Name
                        # Or: [CHG] Device AA:BB:CC:DD:EE:FF Name
                        if 'Device' in line:
                            mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
                            
                            if mac_match:
                                mac = mac_match.group(1).upper()
                                
                                # Robust Name Extraction: Split line by MAC
                                # This ensures we get exactly what follows the MAC
                                parts = line.split(mac, 1)
                                if len(parts) > 1:
                                    raw_name = parts[1].strip()
                                else:
                                    raw_name = "Unknown Device"
                                
                                # --- FIX START ---
                                # 1. Strip ANSI color codes
                                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                                name = ansi_escape.sub('', raw_name)
                                
                                # 2. Remove explicit [0m if leftover and cleanup whitespace
                                name = name.replace('[0m', '').replace(' [0m', '').strip()
                                
                                # 3. Check for duplicated MAC in name (e.g. "Device <MAC> <MAC>")
                                # Or "Device <MAC> <Dashed-MAC>"
                                # Compare normalized versions
                                name_norm = name.replace('-', ':').upper()
                                if name_norm == mac:
                                    name = "Unknown Device"
                                
                                # 4. Filter out technical noise often mistaken for names
                                if name.startswith('RSSI:') or name.startswith('Class:') or name.startswith('Icon:') or name.startswith('[NEW]'):
                                    name = "Unknown Device"
                                
                                # 5. Check if name actually CONTAINS the MAC and nothing else useful
                                if name == mac:
                                    name = "Unknown Device"
                                
                                # 6. Handle cases where name is "MAC Name" -> "Name" (e.g. "AA:BB:.. My Device")
                                # This checks if the remainder starts with the MAC again
                                if name.startswith(mac):
                                    name = name[len(mac):].strip()
                                
                                # If name became empty after stripping
                                if not name:
                                    name = "Unknown Device"
                                # --- FIX END ---
                                
                                # Store or update device
                                if mac not in devices or (name and name != "Unknown Device"):
                                    devices[mac] = name
                                    # Only log if new or interesting
                                    if name != "Unknown Device":
                                        logger.info(f"bluetoothctl: {name} ({mac})")
                except:
                    pass
            
            # Start output reader
            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            
            # Wait for scan
            time.sleep(duration)
            
            # Stop scan
            process.stdin.write('scan off\n')
            process.stdin.write('quit\n')
            process.stdin.flush()
            
            time.sleep(1)
            process.terminate()
            
            # Convert to device list
            device_list = []
            for mac, name in devices.items():
                device_info = self._get_device_details(mac, name)
                device_list.append(device_info)
            
            return device_list
            
        except Exception as e:
            logger.error(f"bluetoothctl scan failed: {e}")
            return []
    
    def _get_device_details(self, mac: str, name: str) -> Dict[str, Any]:
        """Get detailed information about a Classic Bluetooth device"""
        
        # Classify manufacturer
        manufacturer = 'Unknown'
        vendor = 'Unknown'
        device_type = 'Classic Bluetooth Device'
        
        name_lower = name.lower()
        
        # Detect manufacturer from name
        if 'realme' in name_lower:
            manufacturer = 'Realme'
            vendor = 'Realme'
            device_type = 'Realme Smartphone'
        elif 'samsung' in name_lower or 'galaxy' in name_lower or 's21' in name_lower:
            manufacturer = 'Samsung'
            vendor = 'Samsung'
            device_type = 'Samsung Smartphone'
        elif 'soundcore' in name_lower or 'anker' in name_lower:
            manufacturer = 'Anker'
            vendor = 'Anker'
            device_type = 'Audio Device'
        elif 'iphone' in name_lower or 'ipad' in name_lower or 'macbook' in name_lower:
            manufacturer = 'Apple'
            vendor = 'Apple'
            device_type = 'Apple Device'
        elif 'xiaomi' in name_lower or 'redmi' in name_lower or 'poco' in name_lower or 'mi ' in name_lower:
            manufacturer = 'Xiaomi'
            vendor = 'Xiaomi'
            device_type = 'Xiaomi Smartphone'
        elif 'oppo' in name_lower:
            manufacturer = 'OPPO'
            vendor = 'OPPO'
            device_type = 'OPPO Smartphone'
        elif 'vivo' in name_lower:
            manufacturer = 'Vivo'
            vendor = 'Vivo'
            device_type = 'Vivo Smartphone'
        elif 'oneplus' in name_lower:
            manufacturer = 'OnePlus'
            vendor = 'OnePlus'
            device_type = 'OnePlus Smartphone'
        elif 'motorola' in name_lower or 'moto' in name_lower:
            manufacturer = 'Motorola'
            vendor = 'Motorola'
            device_type = 'Motorola Smartphone'
        elif 'nokia' in name_lower:
            manufacturer = 'Nokia'
            vendor = 'Nokia'
            device_type = 'Nokia Device'
        elif 'lg' in name_lower:
            manufacturer = 'LG'
            vendor = 'LG'
            device_type = 'LG Device'
        elif 'desktop' in name_lower or 'laptop' in name_lower or 'pc' in name_lower:
            device_type = 'Computer/Laptop'
        elif 'headset' in name_lower or 'headphone' in name_lower:
            device_type = 'Headset/Headphones'
        elif 'speaker' in name_lower:
            device_type = 'Bluetooth Speaker'
        elif 'earbuds' in name_lower or 'buds' in name_lower or 'tws' in name_lower:
            device_type = 'Wireless Earbuds'
        elif 'watch' in name_lower:
            device_type = 'Smartwatch'
        
        # --- FIX START ---
        # If manufacturer is still Unknown, try OUI lookup via Scapy
        if manufacturer == 'Unknown' and SCAPY_AVAILABLE:
            try:
                # Scapy's manufdb lookup
                # mac is XX:XX:XX...
                prefix = mac[:8].upper()
                
                # Try full MAC lookup first (rarely works for just OUI but good to try)
                oui_manuf = conf.manufdb.get(mac)
                
                # If not found, try OUI (first 3 bytes)
                if not oui_manuf:
                    oui_manuf = conf.manufdb.get(prefix)
                
                if oui_manuf:
                    manufacturer = str(oui_manuf)
                    vendor = str(oui_manuf)
                    
                    # Refine device type based on OUI result if still generic
                    if device_type == 'Classic Bluetooth Device':
                        if 'Apple' in manufacturer:
                             device_type = 'Apple Device'
                        elif 'Samsung' in manufacturer:
                             device_type = 'Samsung Device'
                        elif 'Intel' in manufacturer:
                             device_type = 'Computer/Laptop'
            except Exception as e:
                pass
        # --- FIX END ---
        
        # Try to get additional info from bluetoothctl
        rssi = None
        signal_quality = 'Unknown'
        device_class = 'Unknown'
        icon = 'Unknown'
        services = []
        uuids = []
        
        try:
            info_result = subprocess.run(
                ['bluetoothctl', 'info', mac],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if info_result.returncode == 0:
                for line in info_result.stdout.split('\n'):
                    line = line.strip()
                    
                    if 'RSSI:' in line:
                        rssi_match = re.search(r'RSSI:\s*(-?\d+)', line)
                        if rssi_match:
                            rssi = int(rssi_match.group(1))
                            if rssi > -50:
                                signal_quality = 'Excellent'
                            elif rssi > -60:
                                signal_quality = 'Good'
                            elif rssi > -70:
                                signal_quality = 'Fair'
                            elif rssi > -80:
                                signal_quality = 'Weak'
                            else:
                                signal_quality = 'Very Weak'
                    
                    elif 'Class:' in line:
                        class_match = re.search(r'Class:\s*(0x[0-9a-fA-F]+)', line)
                        if class_match:
                            device_class = class_match.group(1)
                    
                    elif 'Icon:' in line:
                        icon = line.split(':', 1)[1].strip()
                        # Update device type based on icon
                        if 'phone' in icon.lower() and device_type == 'Classic Bluetooth Device':
                            device_type = 'Smartphone'
                        elif 'audio' in icon.lower():
                            device_type = 'Audio Device'
                        elif 'computer' in icon.lower():
                            device_type = 'Computer'
                    
                    elif 'UUID:' in line:
                        uuid_match = re.search(r'UUID:\s+([^\s\(]+)', line)
                        if uuid_match:
                            uuid = uuid_match.group(1)
                            service_name = line.split('(')[1].split(')')[0] if '(' in line else uuid
                            uuids.append(uuid)
                            services.append({
                                'uuid': uuid,
                                'name': service_name
                            })
        except:
            pass
        
        # Create device info
        device_info = {
            'name': name,
            'address': mac,
            'mac_address': mac,
            'manufacturer': manufacturer,
            'vendor': vendor,
            'device_type': device_type,
            'device_class': device_class,
            'icon': icon,
            'rssi': rssi,
            'signal_strength': rssi,
            'signal_quality': signal_quality,
            'services': services,
            'service_count': len(services),
            'uuids': uuids,
            'bluetooth_type': 'Classic Bluetooth',
            'nearby': True,
            'discoverable': True,
            'discovery_method': 'hcitool/bluetoothctl',
            'scan_timestamp': datetime.now().isoformat(),
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
        
        return device_info

def main():
    """Test the Unified Bluetooth scanner"""
    scanner = UnifiedBluetoothScanner()
    results = scanner.scan_all_bluetooth_devices(classic_duration=20, ble_duration=10)
    
    classic_devices = results['classic_devices']
    ble_devices = results['ble_devices']
    
    print()
    print("=" * 80)
    print("📊 DETAILED SCAN RESULTS")
    print("=" * 80)
    print()
    
    # Display Classic Bluetooth devices
    print("🔷 CLASSIC BLUETOOTH DEVICES")
    print("=" * 80)
    print(f"Total: {len(classic_devices)} device(s)")
    print()
    
    if classic_devices:
        for i, device in enumerate(classic_devices, 1):
            print(f"📱 DEVICE #{i}")
            print("=" * 80)
            print(f"  📌 Name: {device.get('name', 'Unknown')}")
            print(f"  🔢 MAC Address: {device.get('address', 'Unknown')}")
            print(f"  🏭 Manufacturer: {device.get('manufacturer', 'Unknown')}")
            print(f"  📦 Device Type: {device.get('device_type', 'Unknown')}")
            print(f"  🔧 Bluetooth Type: {device.get('bluetooth_type', 'Unknown')}")
            print()
            
            if device.get('rssi'):
                print(f"  📶 Signal Strength:")
                print(f"     RSSI: {device['rssi']} dBm")
                print(f"     Quality: {device.get('signal_quality', 'Unknown')}")
                print()
            
            if device.get('device_class') and device['device_class'] != 'Unknown':
                print(f"  🎨 Device Class: {device['device_class']}")
            
            if device.get('icon') and device['icon'] != 'Unknown':
                print(f"  🖼️  Icon: {device['icon']}")
            
            if device.get('services') and len(device['services']) > 0:
                print(f"  🔧 Services: {len(device['services'])}")
                for svc in device['services'][:5]:
                    print(f"     - {svc.get('name', svc.get('uuid', 'Unknown'))}")
                if len(device['services']) > 5:
                    print(f"     ... and {len(device['services']) - 5} more")
            
            print(f"  ⏰ Discovered: {device.get('scan_timestamp', 'Unknown')}")
            print("=" * 80)
            print()
    else:
        print("⚠️  No Classic Bluetooth devices found")
        print()
    
    # Display BLE devices
    print()
    print("🔶 BLE (BLUETOOTH LOW ENERGY) DEVICES")
    print("=" * 80)
    print(f"Total: {len(ble_devices)} device(s)")
    print()
    
    if ble_devices:
        # Show devices with names first
        named_ble = [d for d in ble_devices if d.get('name') and 'Unknown' not in d.get('name')]
        unnamed_ble = [d for d in ble_devices if not d.get('name') or 'Unknown' in d.get('name')]
        
        if named_ble:
            print(f"📝 BLE Devices with Names ({len(named_ble)}):")
            print("-" * 80)
            for i, device in enumerate(named_ble, 1):
                print(f"📱 BLE DEVICE #{i}")
                print(f"  📌 Name: {device.get('name', 'Unknown')}")
                print(f"  🔢 MAC: {device.get('address', 'Unknown')}")
                print(f"  🏭 Manufacturer: {device.get('manufacturer', 'Unknown')}")
                print(f"  📶 RSSI: {device.get('rssi')} dBm ({device.get('signal_quality', 'Unknown')})")
                print(f"  🔧 Services: {device.get('service_count', 0)}")
                print()
        
        if unnamed_ble:
            print(f"⚠️  BLE Devices (Privacy-Protected) ({len(unnamed_ble)}):")
            print("-" * 80)
            
            # Group by manufacturer
            by_manufacturer = {}
            for device in unnamed_ble:
                mfg = device.get('manufacturer', 'Unknown')
                if mfg not in by_manufacturer:
                    by_manufacturer[mfg] = []
                by_manufacturer[mfg].append(device)
            
            for mfg, devices in sorted(by_manufacturer.items(), key=lambda x: len(x[1]), reverse=True):
                print(f"  🏭 {mfg}: {len(devices)} device(s)")
            print()
    else:
        print("⚠️  No BLE devices found")
        print()
    
    # Final Summary
    print()
    print("=" * 80)
    print("📊 FINAL SUMMARY")
    print("=" * 80)
    print(f"  🔷 Classic Bluetooth Devices: {len(classic_devices)}")
    print(f"  🔶 BLE Devices: {len(ble_devices)}")
    print(f"  🎯 TOTAL DEVICES: {len(classic_devices) + len(ble_devices)}")
    print("=" * 80)
    print()
    print("✅ Unified Scan Complete!")

if __name__ == "__main__":
    main()

