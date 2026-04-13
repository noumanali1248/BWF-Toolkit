
import sys
import os
import json
import logging

# Configure logging to see output
logging.basicConfig(level=logging.INFO)

# Add module path
sys.path.append('/home/kali/Videos/Complete Project.100%/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/module8')

from module8_controller import EndpointSecurityController

def test_controller_config():
    try:
        # Initialize controller
        # This should trigger _load_config
        controller = EndpointSecurityController()
        
        allowed = controller.config.get('allowed_actions', [])
        print(f"Allowed actions in controller config: {allowed}")
        
        if 'block_mac' in allowed and 'unblock_mac' in allowed:
            print("SUCCESS: block_mac and unblock_mac are in allowed_actions")
            return True
        else:
            print("FAILURE: block_mac or unblock_mac missing from allowed_actions")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_controller_config()
