
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from module3.live_packet_capture import LivePacketCapture
    
    print("Instantiating LivePacketCapture...")
    capture = LivePacketCapture()
    
    # Test Case 1: ACK Traffic (Should be IGNORED)
    ack_packet = {
        'src_ip': '1.2.3.4',
        'dst_port': '80',
        'protocol': 'TCP',
        'tcp_flags': '0x0010', # ACK
        'src_mac': '00:11:22:33:44:55'
    }
    
    print("\nTesting ACK Packet (Legitimate Return Traffic):")
    is_suspicious_ack = capture._is_suspicious(ack_packet)
    if not is_suspicious_ack:
        print("✅ SUCCESS: ACK packet ignored.")
    else:
        print("❌ FAILURE: ACK packet flagged as suspicious.")
        sys.exit(1)

    # Test Case 2: SYN Traffic (Should be DETECTED if volume is high)
    # We need to simulate multiple ports to trigger the threshold
    print("\nTesting SYN Packets (Port Scan):")
    syn_source = '5.6.7.8'
    
    # Reset tracker for this IP
    if syn_source in capture.port_scan_tracker:
        del capture.port_scan_tracker[syn_source]
        
    detected = False
    for port in range(100, 130): # 30 different ports (Threshold is > 20)
        syn_packet = {
            'src_ip': syn_source,
            'dst_port': str(port),
            'protocol': 'TCP',
            'tcp_flags': '0x0002', # SYN
            'src_mac': '00:11:22:33:44:55'
        }
        if capture._is_suspicious(syn_packet):
            detected = True
            print(f"✅ SUCCESS: Port Scan detected at port {port}")
            break
            
    if not detected:
        print("❌ FAILURE: SYN Port Scan NOT detected.")
        sys.exit(1)

except Exception as e:
    print(f"Error during verification: {e}")
    sys.exit(1)
