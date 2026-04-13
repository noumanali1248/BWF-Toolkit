
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from module3.live_packet_capture import LivePacketCapture
    
    print("Instantiating LivePacketCapture...")
    capture = LivePacketCapture()
    
    # Test Case 1: UDP DNS Traffic (Should be IGNORED)
    dns_packet = {
        'src_ip': '192.168.18.1',
        'src_port': '53', # DNS
        'dst_port': '50000',
        'protocol': 'UDP',
        'src_mac': '00:11:22:33:44:55'
    }
    
    print("\nTesting UDP DNS Packet (Legitimate Return Traffic):")
    is_suspicious_dns = capture._is_suspicious(dns_packet)
    if not is_suspicious_dns:
        print("✅ SUCCESS: UDP DNS packet ignored.")
    else:
        print("❌ FAILURE: UDP DNS packet flagged as suspicious.")
        sys.exit(1)

    # Test Case 2: UDP Port Scan (Should be DETECTED)
    print("\nTesting UDP Port Scan:")
    scan_source = '9.9.9.9'
    
    # Reset tracker
    if scan_source in capture.port_scan_tracker:
        del capture.port_scan_tracker[scan_source]
        
    detected = False
    for port in range(200, 230): # 30 different ports
        scan_packet = {
            'src_ip': scan_source,
            'src_port': '4444', # Random source
            'dst_port': str(port),
            'protocol': 'UDP',
            'src_mac': '00:11:22:33:44:55'
        }
        if capture._is_suspicious(scan_packet):
            detected = True
            print(f"✅ SUCCESS: UDP Port Scan detected at port {port}")
            break
            
    if not detected:
        print("❌ FAILURE: UDP Port Scan NOT detected.")
        sys.exit(1)

except Exception as e:
    print(f"Error during verification: {e}")
    sys.exit(1)
