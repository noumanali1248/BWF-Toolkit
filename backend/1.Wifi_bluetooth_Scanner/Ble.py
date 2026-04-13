
import asyncio
import os
from datetime import datetime

# Ensure bleak is installed
try:
    from bleak import BleakScanner
except ImportError:
    os.system('pip install bleak')
    from bleak import BleakScanner


class BLEScannerTerminal:
    def __init__(self, mask_mac=False):
        self.mask_mac = mask_mac
        self.devices_found = []

    def log(self, message: str):
        """Print message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def mask_address(self, address: str) -> str:
        """Mask MAC address if masking is enabled."""
        if not self.mask_mac:
            return address
        
        parts = address.split(":")
        if len(parts) == 6:
            return "XX:XX:XX:" + ":".join(parts[-3:])
        return address

    async def scan_devices(self):
        """Perform BLE scan with advertisement data to get actual names."""
        self.log("Starting BLE device scan...")
        print("=" * 60)
        print("BLE SCANNER - TERMINAL VERSION")
        print(f"MAC Masking: {'ENABLED' if self.mask_mac else 'DISABLED'}")
        print("=" * 60)
        
        try:
            devices = await BleakScanner.discover(return_adv=True, timeout=10.0)
        except Exception as e:
            self.log(f"ERROR: Scan failed - {e}")
            return

        if not devices:
            self.log("No BLE devices found.")
            return

        self.log(f"Found {len(devices)} BLE device(s):")
        print("-" * 60)
        
        device_count = 0
        for device_id, (device, adv_data) in devices.items():
            device_count += 1
            
            # Get device information
            address = self.mask_address(device.address)
            
            # Try to get the actual name (advertised local name > device.name > Unknown)
            name = adv_data.local_name or device.name or "Unknown Device"
            
            # Get RSSI if available
            rssi = adv_data.rssi if adv_data.rssi is not None else "N/A"
            
            print(f"Device #{device_count}:")
            print(f"  Name: {name}")
            print(f"  Address: {address}")
            print(f"  RSSI: {rssi} dBm")
            
            # Show manufacturer data if available
            if adv_data.manufacturer_data:
                print(f"  Manufacturer Data: {adv_data.manufacturer_data}")
            
            # Show services if available
            if adv_data.service_uuids:
                print(f"  Services: {len(adv_data.service_uuids)} service(s)")
                for service in list(adv_data.service_uuids)[:3]:  # Show first 3
                    print(f"    - {service}")
                if len(adv_data.service_uuids) > 3:
                    print(f"    ... and {len(adv_data.service_uuids) - 3} more")
            
            print("-" * 40)
            
            # Store device info
            device_info = {
                'name': name,
                'address': address,
                'rssi': rssi,
                'timestamp': datetime.now().isoformat()
            }
            self.devices_found.append(device_info)

        print(f"\nScan completed. Found {len(self.devices_found)} BLE devices.")
        return self.devices_found

    def print_summary(self):
        """Print summary of found devices."""
        if not self.devices_found:
            return
            
        print("\n" + "=" * 60)
        print("BLE DEVICE SUMMARY")
        print("=" * 60)
        
        # Group by device type/name
        device_types = {}
        for device in self.devices_found:
            name = device['name']
            if name not in device_types:
                device_types[name] = []
            device_types[name].append(device)
        
        for device_type, devices in device_types.items():
            print(f"\n{device_type}: {len(devices)} device(s)")
            for device in devices:
                print(f"  - {device['address']} (RSSI: {device['rssi']} dBm)")

    def run_scan(self):
        """Run a single scan."""
        return asyncio.run(self.scan_devices())


def main():
    """Main function."""
    print("Starting BLE Scanner...")
    
    # Create scanner with MAC masking DISABLED
    scanner = BLEScannerTerminal(mask_mac=False)
    
    try:
        devices = scanner.run_scan()
        scanner.print_summary()
        
        if devices:
            print(f"\nTotal devices found: {len(devices)}")
        else:
            print("\nNo devices found.")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nERROR: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())



