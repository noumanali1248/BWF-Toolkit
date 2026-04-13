
import sys
import os

# Add parent directory to path to allow importing module3
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from module3.live_packet_capture import LivePacketCapture
    
    print("Instantiating LivePacketCapture...")
    capture = LivePacketCapture()
    
    print(f"Detected Local MACs: {capture.local_macs}")
    
    target_mac = "5c:fb:3a:ac:c5:e5"
    if target_mac in capture.local_macs or target_mac.upper() in capture.local_macs:
        print("✅ SUCCESS: wlan0 MAC found in local_macs exclusion list.")
    else:
        print(f"❌ FAILURE: wlan0 MAC {target_mac} NOT found in local_macs.")
        sys.exit(1)
        
except Exception as e:
    print(f"Error during verification: {e}")
    sys.exit(1)
