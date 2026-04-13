#!/usr/bin/env python3
"""
WiFi Attack Simulator for Testing Rogue Device Detection
Run this on a second laptop to simulate WiFi attacks
"""

import subprocess
import time
import random
import sys
import os
from datetime import datetime

class WiFiAttackSimulator:
    def __init__(self):
        self.attack_scenarios = [
            {
                "name": "Evil Twin Attack",
                "ssid": "Free_WiFi_Here",
                "password": "",  # Open network
                "description": "Creates fake free WiFi hotspot"
            },
            {
                "name": "Airport WiFi Spoof",
                "ssid": "Airport_WiFi_Free",
                "password": "",
                "description": "Simulates fake airport WiFi"
            },
            {
                "name": "Coffee Shop Spoof",
                "ssid": "CoffeeShop_Guest",
                "password": "",
                "description": "Simulates fake coffee shop WiFi"
            },
            {
                "name": "Hotel WiFi Spoof",
                "ssid": "Hotel_Lobby_WiFi",
                "password": "",
                "description": "Simulates fake hotel WiFi"
            },
            {
                "name": "Setup Required Attack",
                "ssid": "WiFi_Setup_Required",
                "password": "",
                "description": "Suspicious setup-related SSID"
            },
            {
                "name": "Security Alert Attack",
                "ssid": "Security_Update_Required",
                "password": "",
                "description": "Suspicious security-related SSID"
            },
            {
                "name": "Router Admin Spoof",
                "ssid": "Router_Admin_Panel",
                "password": "",
                "description": "Suspicious admin panel SSID"
            },
            {
                "name": "Network Config Attack",
                "ssid": "Network_Configuration",
                "password": "",
                "description": "Suspicious network config SSID"
            }
        ]
        
        self.current_attack = None
        self.attack_start_time = None

    def print_banner(self):
        """Print attack simulator banner"""
        print("=" * 60)
        print("🔴 WiFi ATTACK SIMULATOR - ROGUE DEVICE TESTING")
        print("=" * 60)
        print("This script simulates WiFi attacks to test Module 2 detection")
        print("Make sure Module 2 dashboard is running on the main laptop")
        print("=" * 60)

    def check_system(self):
        """Check if system supports WiFi hotspot creation"""
        try:
            # Check if we're on Windows
            if os.name == 'nt':
                result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print("✅ Windows WiFi system detected")
                    return True
                else:
                    print("❌ WiFi system not available")
                    return False
            else:
                print("❌ This script is designed for Windows systems")
                return False
        except Exception as e:
            print(f"❌ Error checking system: {e}")
            return False

    def create_hotspot_profile(self, ssid, password=""):
        """Create a WiFi hotspot profile"""
        try:
            profile_name = f"AttackProfile_{ssid.replace(' ', '_')}"
            
            # Create XML profile for the hotspot
            if password:
                security_key = f'<keyMaterial>{password}</keyMaterial>'
                auth_encryption = '''
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>'''
            else:
                security_key = ''
                auth_encryption = '''
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>'''

            xml_content = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{profile_name}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                {auth_encryption}
            </authEncryption>
            {security_key}
        </security>
    </MSM>
</WLANProfile>'''

            # Write profile to temp file
            profile_file = f"{profile_name}.xml"
            with open(profile_file, 'w') as f:
                f.write(xml_content)

            # Add profile to Windows
            result = subprocess.run(['netsh', 'wlan', 'add', 'profile', 
                                   f'filename={profile_file}'], 
                                  capture_output=True, text=True, timeout=10)
            
            # Clean up temp file
            if os.path.exists(profile_file):
                os.remove(profile_file)

            if result.returncode == 0:
                print(f"✅ Created hotspot profile: {ssid}")
                return profile_name
            else:
                print(f"❌ Failed to create profile: {result.stderr}")
                return None

        except Exception as e:
            print(f"❌ Error creating hotspot profile: {e}")
            return None

    def start_hotspot(self, profile_name):
        """Start the WiFi hotspot"""
        try:
            # Start hosted network
            result = subprocess.run(['netsh', 'wlan', 'start', 'hostednetwork'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"✅ Started hotspot with profile: {profile_name}")
                return True
            else:
                print(f"❌ Failed to start hotspot: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error starting hotspot: {e}")
            return False

    def stop_hotspot(self):
        """Stop the WiFi hotspot"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'stop', 'hostednetwork'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("✅ Stopped hotspot")
                return True
            else:
                print(f"❌ Failed to stop hotspot: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error stopping hotspot: {e}")
            return False

    def show_attack_menu(self):
        """Show attack scenario menu"""
        print("\n🎯 AVAILABLE ATTACK SCENARIOS:")
        print("-" * 50)
        for i, scenario in enumerate(self.attack_scenarios, 1):
            print(f"{i}. {scenario['name']}")
            print(f"   SSID: '{scenario['ssid']}'")
            print(f"   Password: {'None (Open)' if not scenario['password'] else 'Protected'}")
            print(f"   Description: {scenario['description']}")
            print()

    def run_attack(self, scenario_index):
        """Run a specific attack scenario"""
        if scenario_index < 1 or scenario_index > len(self.attack_scenarios):
            print("❌ Invalid scenario number")
            return False

        scenario = self.attack_scenarios[scenario_index - 1]
        self.current_attack = scenario
        self.attack_start_time = datetime.now()

        print(f"\n🔴 STARTING ATTACK: {scenario['name']}")
        print(f"SSID: '{scenario['ssid']}'")
        print(f"Password: {'None (Open Network)' if not scenario['password'] else 'Protected'}")
        print(f"Description: {scenario['description']}")
        print("-" * 50)

        # Create and start hotspot
        profile_name = self.create_hotspot_profile(scenario['ssid'], scenario['password'])
        if profile_name:
            if self.start_hotspot(profile_name):
                print(f"\n✅ ATTACK ACTIVE!")
                print(f"📡 Hotspot '{scenario['ssid']}' is now broadcasting")
                print(f"🕐 Started at: {self.attack_start_time.strftime('%H:%M:%S')}")
                print(f"\n📊 Check Module 2 dashboard to see if it detects this as a rogue device!")
                print(f"🌐 Dashboard URL: http://localhost:8001/module2")
                return True

        return False

    def show_attack_status(self):
        """Show current attack status"""
        if self.current_attack:
            duration = datetime.now() - self.attack_start_time
            print(f"\n📊 CURRENT ATTACK STATUS:")
            print(f"Attack: {self.current_attack['name']}")
            print(f"SSID: '{self.current_attack['ssid']}'")
            print(f"Duration: {duration}")
            print(f"Status: ACTIVE")
        else:
            print("\n📊 No active attack")

    def run_interactive_mode(self):
        """Run interactive attack mode"""
        while True:
            print("\n" + "=" * 60)
            print("🔴 WiFi ATTACK SIMULATOR - MAIN MENU")
            print("=" * 60)
            print("1. Show available attack scenarios")
            print("2. Run attack scenario")
            print("3. Show current attack status")
            print("4. Stop current attack")
            print("5. Run random attack")
            print("6. Exit")
            print("-" * 60)

            try:
                choice = input("Enter your choice (1-6): ").strip()

                if choice == '1':
                    self.show_attack_menu()

                elif choice == '2':
                    self.show_attack_menu()
                    try:
                        scenario_num = int(input("Enter scenario number: "))
                        self.run_attack(scenario_num)
                    except ValueError:
                        print("❌ Invalid number")

                elif choice == '3':
                    self.show_attack_status()

                elif choice == '4':
                    if self.current_attack:
                        self.stop_hotspot()
                        self.current_attack = None
                        self.attack_start_time = None
                    else:
                        print("❌ No active attack to stop")

                elif choice == '5':
                    random_scenario = random.randint(1, len(self.attack_scenarios))
                    print(f"🎲 Running random attack scenario #{random_scenario}")
                    self.run_attack(random_scenario)

                elif choice == '6':
                    if self.current_attack:
                        print("🛑 Stopping current attack...")
                        self.stop_hotspot()
                    print("👋 Exiting attack simulator")
                    break

                else:
                    print("❌ Invalid choice")

            except KeyboardInterrupt:
                print("\n🛑 Interrupted by user")
                if self.current_attack:
                    self.stop_hotspot()
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def run_quick_test(self):
        """Run a quick test with the first attack scenario"""
        print("\n🚀 RUNNING QUICK TEST...")
        print("This will run the 'Evil Twin Attack' scenario for 60 seconds")
        
        if self.run_attack(1):  # Run first scenario
            print("\n⏰ Attack will run for 60 seconds...")
            print("📊 Check Module 2 dashboard now!")
            
            for i in range(60, 0, -10):
                print(f"⏳ Time remaining: {i} seconds")
                time.sleep(10)
            
            print("\n🛑 Stopping attack...")
            self.stop_hotspot()
            print("✅ Quick test completed!")

def main():
    """Main function"""
    simulator = WiFiAttackSimulator()
    simulator.print_banner()

    # Check system compatibility
    if not simulator.check_system():
        print("❌ System not compatible. Exiting.")
        return

    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--quick":
            simulator.run_quick_test()
        elif sys.argv[1] == "--help":
            print("\nUsage:")
            print("  python wifi_attack_simulator.py          # Interactive mode")
            print("  python wifi_attack_simulator.py --quick  # Quick test")
            print("  python wifi_attack_simulator.py --help   # Show this help")
        else:
            print("❌ Unknown argument. Use --help for usage information.")
    else:
        # Run interactive mode
        simulator.run_interactive_mode()

if __name__ == "__main__":
    main()
