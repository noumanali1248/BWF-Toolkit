
import sys
import os
import json

# Add module path
sys.path.append('/home/kali/Videos/Complete Project.100%/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/module8')

from module8_agent import EndpointSecurityAgent

def test_allowed_actions():
    try:
        # Initialize agent (might fail to connect but we just want to check config)
        # We mock the config loading or just check the default config logic if possible, 
        # but since we modified the file, let's see if we can instantiate it or just inspect the class/config file.
        
        # Actually, let's just load the config file directly as the agent does
        config_path = '/home/kali/Videos/Complete Project.100%/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend/module8/agent_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        allowed = config.get('allowed_actions', [])
        print(f"Allowed actions in config: {allowed}")
        
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
    test_allowed_actions()
