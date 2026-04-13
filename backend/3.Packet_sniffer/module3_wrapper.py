#!/usr/bin/env python3
"""
Module 3 Wrapper for BWF Toolkit Integration
Now uses REAL packet capture system
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Import the real packet capture system
try:
    from .module3_real_packet_capture import get_real_packet_capture, RealPacketCapture
    REAL_CAPTURE_AVAILABLE = True
except ImportError as e:
    print(f"Real packet capture not available: {e}")
    REAL_CAPTURE_AVAILABLE = False

# Import Live Packet Capture as fallback
try:
    from .live_packet_capture import LivePacketCapture
    LIVE_CAPTURE_AVAILABLE = True
except ImportError:
    LIVE_CAPTURE_AVAILABLE = False

class Module3Wrapper:
    """Wrapper class for Module 3 REAL packet capture functionality"""
    
    def __init__(self):
        self.running = False
        self.use_fallback = False
        self.live_capture = None
        
        if REAL_CAPTURE_AVAILABLE:
            # Initialize real packet capture system
            config = {
                'database_path': 'real_packet_capture.db',
                'capture_dir': './real_captures'
            }
            self.real_capture = get_real_packet_capture(config)
            print("Real packet capture system initialized")
        else:
            self.real_capture = None
            print("Real packet capture not available - attempting fallback")
            
            if LIVE_CAPTURE_AVAILABLE:
                self.live_capture = LivePacketCapture()
                self.use_fallback = True
                print("Using LivePacketCapture (TShark) as fallback")
            else:
                print("No packet capture systems available")
    
    # Database initialization is now handled by the real capture system
        
    def get_real_capture_status(self):
        """Get REAL capture status"""
        if self.use_fallback and self.live_capture:
            return self.live_capture.get_status()
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return {
                "running": False,
                "available": False,
                "message": "Real packet capture not available",
                "real_data_only": True
            }
        
        try:
            status = self.real_capture.get_capture_status()
            status["available"] = True
            status["real_data_only"] = True
            return status
        except Exception as e:
            return {
                "running": False,
                "available": True,
                "error": str(e),
                "real_data_only": True
            }
    
    def start_real_capture(self, duration=60):
        """Start REAL packet capture"""
        if self.use_fallback and self.live_capture:
            return self.live_capture.start_capture()
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return False
        
        try:
            success = self.real_capture.start_capture(duration=duration)
            if success:
                self.running = True
                print(f"Real packet capture started for {duration} seconds")
            return success
        except Exception as e:
            print(f"Error starting real capture: {e}")
            return False
    
    def stop_real_capture(self):
        """Stop REAL packet capture"""
        if self.use_fallback and self.live_capture:
            return self.live_capture.stop_capture()
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return False
        
        try:
            success = self.real_capture.stop_capture()
            if success:
                self.running = False
                print("Real packet capture stopped")
            return success
        except Exception as e:
            print(f"Error stopping real capture: {e}")
            return False
    
    def get_real_recent_packets(self, limit=100):
        """Get REAL recent packets from database"""
        if self.use_fallback and self.live_capture:
            # Convert deque to list and return recent packets
            return list(self.live_capture.packets)[-limit:]
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return []
        
        try:
            packets = self.real_capture.get_recent_packets(limit)
            print(f"Retrieved {len(packets)} real packets")
            return packets
        except Exception as e:
            print(f"Error getting real packets: {e}")
            return []
    
    def get_real_anomalies(self, limit=50):
        """Get REAL anomalies from database"""
        if self.use_fallback:
            return [] # Live capture doesn't store anomalies in DB same way
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return []
        
        try:
            anomalies = self.real_capture.get_anomalies(limit)
            print(f"Retrieved {len(anomalies)} real anomalies")
            return anomalies
        except Exception as e:
            print(f"Error getting real anomalies: {e}")
            return []
    
    def export_real_metadata(self, format_type="csv", hours=24):
        """Export REAL metadata"""
        if self.use_fallback:
            return None
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return None
        
        try:
            filename = self.real_capture.export_data(format_type, hours)
            if filename:
                print(f"Exported real data to {filename}")
            return filename
        except Exception as e:
            print(f"Error exporting real metadata: {e}")
            return None
    
    def get_real_network_interfaces(self):
        """Get REAL available network interfaces"""
        if self.use_fallback:
            return []
            
        if not REAL_CAPTURE_AVAILABLE or not self.real_capture:
            return []
        
        try:
            interfaces = self.real_capture.get_available_interfaces()
            print(f"Retrieved {len(interfaces)} real network interfaces")
            return interfaces
        except Exception as e:
            print(f"Error getting real interfaces: {e}")
            return []
