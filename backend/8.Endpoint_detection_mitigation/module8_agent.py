#!/usr/bin/env python3
"""
Module 8: Lightweight Endpoint Security Agent
Cross-platform agent for authorized corporate device management
"""

import os
import sys
import json
import ssl
import time
import hmac
import hashlib
import logging
import subprocess
import threading
import platform
import psutil
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional
import websocket
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EndpointSecurityAgent:
    """Lightweight endpoint security agent for corporate device management"""
    
    def __init__(self, config_file: str = 'agent_config.json'):
        self.config = self._load_config(config_file)
        self.running = False
        self.ws = None
        self.command_handlers = self._init_command_handlers()
        self.system_info = self._get_system_info()
        
        # Security
        self.auth_token = self.config.get('auth_token', '')
        self.controller_url = self.config.get('controller_url', 'wss://localhost:8001/ws')
        self.encryption_key = self._derive_encryption_key()
        
        logger.info(f"Agent initialized for {self.system_info['hostname']} ({self.system_info['platform']})")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load agent configuration"""
        default_config = {
            'controller_url': 'wss://localhost:8001/ws',
            'auth_token': 'default_token_change_me',
            'reconnect_interval': 30,
            'command_timeout': 60,
            'log_level': 'INFO',
            'allowed_actions': [
                'network_scan',
                'process_list',
                'service_control',
                'firewall_rule',
                'bluetooth_control',
                'wifi_control',
                'system_info',
                'file_scan',
                'registry_check',
                'log_collect',
                'block_mac',
                'unblock_mac'
            ]
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Error loading config file: {e}")
        
        return default_config
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from auth token"""
        password = self.auth_token.encode()
        salt = b'endpoint_security_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        try:
            return {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent,
                'network_interfaces': self._get_network_interfaces(),
                'running_processes': len(psutil.pids()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'agent_version': '1.0.0',
                'agent_id': self._generate_agent_id()
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {'error': str(e)}
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                interfaces.append(interface_info)
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
        return interfaces
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        hostname = socket.gethostname()
        mac_address = self._get_mac_address()
        return f"{hostname}_{mac_address}_{int(time.time())}"
    
    def _get_mac_address(self) -> str:
        """Get MAC address of primary network interface"""
        try:
            import uuid
            return ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
        except:
            return "unknown"
    
    def _init_command_handlers(self) -> Dict[str, callable]:
        """Initialize command handlers for different actions"""
        return {
            'network_scan': self._handle_network_scan,
            'process_list': self._handle_process_list,
            'service_control': self._handle_service_control,
            'firewall_rule': self._handle_firewall_rule,
            'bluetooth_control': self._handle_bluetooth_control,
            'wifi_control': self._handle_wifi_control,
            'system_info': self._handle_system_info,
            'file_scan': self._handle_file_scan,
            'registry_check': self._handle_registry_check,
            'log_collect': self._handle_log_collect,
            'emergency_shutdown': self._handle_emergency_shutdown,
            'network_isolation': self._handle_network_isolation,
            'process_terminate': self._handle_process_terminate,
            'file_quarantine': self._handle_file_quarantine
        }
    
    def _handle_network_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle network scanning command"""
        try:
            target = params.get('target', 'localhost')
            scan_type = params.get('scan_type', 'ping')
            
            if scan_type == 'ping':
                result = subprocess.run(['ping', '-c', '4', target] if platform.system() != 'Windows' 
                                      else ['ping', '-n', '4', target], 
                                      capture_output=True, text=True, timeout=30)
                return {
                    'success': result.returncode == 0,
                    'output': result.stdout,
                    'error': result.stderr
                }
            elif scan_type == 'port_scan':
                # Simple port scan
                open_ports = []
                for port in range(1, 1001):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return {
                    'success': True,
                    'open_ports': open_ports
                }
            else:
                return {'success': False, 'error': f'Unknown scan type: {scan_type}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_process_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle process listing command"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return {
                'success': True,
                'processes': processes,
                'total_count': len(processes)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_service_control(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle service control commands"""
        try:
            service_name = params.get('service_name')
            action = params.get('action', 'status')
            
            if platform.system() == 'Windows':
                if action == 'start':
                    result = subprocess.run(['sc', 'start', service_name], capture_output=True, text=True)
                elif action == 'stop':
                    result = subprocess.run(['sc', 'stop', service_name], capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['sc', 'query', service_name], capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            else:
                if action == 'start':
                    result = subprocess.run(['systemctl', 'start', service_name], capture_output=True, text=True)
                elif action == 'stop':
                    result = subprocess.run(['systemctl', 'stop', service_name], capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['systemctl', 'status', service_name], capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_firewall_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle firewall rule management"""
        try:
            action = params.get('action', 'list')
            rule_name = params.get('rule_name', '')
            port = params.get('port', '')
            protocol = params.get('protocol', 'tcp')
            
            if platform.system() == 'Windows':
                if action == 'add':
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol={protocol} localport={port}'
                elif action == 'delete':
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                elif action == 'list':
                    cmd = 'netsh advfirewall firewall show rule name=all'
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            else:
                if action == 'add':
                    cmd = f'iptables -A INPUT -p {protocol} --dport {port} -j DROP'
                elif action == 'delete':
                    cmd = f'iptables -D INPUT -p {protocol} --dport {port} -j DROP'
                elif action == 'list':
                    cmd = 'iptables -L'
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_bluetooth_control(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Bluetooth control commands"""
        try:
            action = params.get('action', 'status')
            
            if platform.system() == 'Windows':
                if action == 'disable':
                    result = subprocess.run(['powershell', '-Command', 'Disable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "*Bluetooth*").InstanceId -Confirm:$false'], 
                                          capture_output=True, text=True)
                elif action == 'enable':
                    result = subprocess.run(['powershell', '-Command', 'Enable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "*Bluetooth*").InstanceId -Confirm:$false'], 
                                          capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['powershell', '-Command', 'Get-PnpDevice -FriendlyName "*Bluetooth*"'], 
                                          capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            else:
                if action == 'disable':
                    result = subprocess.run(['rfkill', 'block', 'bluetooth'], capture_output=True, text=True)
                elif action == 'enable':
                    result = subprocess.run(['rfkill', 'unblock', 'bluetooth'], capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['rfkill', 'list', 'bluetooth'], capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_wifi_control(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle WiFi control commands"""
        try:
            action = params.get('action', 'status')
            
            if platform.system() == 'Windows':
                if action == 'disable':
                    result = subprocess.run(['netsh', 'interface', 'set', 'interface', 'Wi-Fi', 'disable'], 
                                          capture_output=True, text=True)
                elif action == 'enable':
                    result = subprocess.run(['netsh', 'interface', 'set', 'interface', 'Wi-Fi', 'enable'], 
                                          capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                          capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            else:
                if action == 'disable':
                    result = subprocess.run(['nmcli', 'radio', 'wifi', 'off'], capture_output=True, text=True)
                elif action == 'enable':
                    result = subprocess.run(['nmcli', 'radio', 'wifi', 'on'], capture_output=True, text=True)
                elif action == 'status':
                    result = subprocess.run(['nmcli', 'radio', 'wifi'], capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown action: {action}'}
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_system_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system information request"""
        try:
            return {
                'success': True,
                'system_info': self.system_info,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_file_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file scanning command"""
        try:
            scan_path = params.get('path', '/')
            if platform.system() == 'Windows':
                scan_path = params.get('path', 'C:\\')
            
            suspicious_files = []
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Simple heuristic: check for suspicious extensions
                    if file.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.pif')):
                        try:
                            stat = os.stat(file_path)
                            suspicious_files.append({
                                'path': file_path,
                                'size': stat.st_size,
                                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                            })
                        except:
                            pass
                    # Limit results
                    if len(suspicious_files) > 100:
                        break
                if len(suspicious_files) > 100:
                    break
            
            return {
                'success': True,
                'suspicious_files': suspicious_files,
                'scan_path': scan_path
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_registry_check(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Windows registry check"""
        try:
            if platform.system() != 'Windows':
                return {'success': False, 'error': 'Registry check only available on Windows'}
            
            registry_keys = [
                r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            ]
            
            startup_programs = []
            for key in registry_keys:
                try:
                    result = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
                    if result.returncode == 0:
                        startup_programs.append({
                            'key': key,
                            'entries': result.stdout
                        })
                except:
                    pass
            
            return {
                'success': True,
                'startup_programs': startup_programs
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_log_collect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle log collection command"""
        try:
            log_type = params.get('log_type', 'system')
            lines = params.get('lines', 100)
            
            if platform.system() == 'Windows':
                if log_type == 'system':
                    result = subprocess.run(['wevtutil', 'qe', 'System', '/c', str(lines)], 
                                          capture_output=True, text=True)
                elif log_type == 'application':
                    result = subprocess.run(['wevtutil', 'qe', 'Application', '/c', str(lines)], 
                                          capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown log type: {log_type}'}
            else:
                if log_type == 'system':
                    result = subprocess.run(['journalctl', '-n', str(lines)], 
                                          capture_output=True, text=True)
                elif log_type == 'auth':
                    result = subprocess.run(['journalctl', '-u', 'ssh', '-n', str(lines)], 
                                          capture_output=True, text=True)
                else:
                    return {'success': False, 'error': f'Unknown log type: {log_type}'}
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_emergency_shutdown(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle emergency shutdown command"""
        try:
            delay = params.get('delay', 10)
            logger.warning(f"Emergency shutdown initiated with {delay} second delay")
            
            # Log the action
            self._log_action('emergency_shutdown', params)
            
            # Schedule shutdown
            if platform.system() == 'Windows':
                subprocess.run(['shutdown', '/s', '/t', str(delay)], capture_output=True)
            else:
                subprocess.run(['shutdown', '-h', '+{}'.format(delay//60)], capture_output=True)
            
            return {
                'success': True,
                'message': f'System will shutdown in {delay} seconds'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_network_isolation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle network isolation command"""
        try:
            action = params.get('action', 'isolate')
            
            if action == 'isolate':
                # Disable all network interfaces except loopback
                interfaces = psutil.net_if_addrs()
                for interface in interfaces:
                    if interface != 'lo' and interface != 'Loopback Pseudo-Interface 1':
                        if platform.system() == 'Windows':
                            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'disable'], 
                                         capture_output=True)
                        else:
                            subprocess.run(['ifconfig', interface, 'down'], capture_output=True)
                
                return {'success': True, 'message': 'Network interfaces disabled'}
            elif action == 'restore':
                # Re-enable network interfaces
                interfaces = psutil.net_if_addrs()
                for interface in interfaces:
                    if interface != 'lo' and interface != 'Loopback Pseudo-Interface 1':
                        if platform.system() == 'Windows':
                            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'enable'], 
                                         capture_output=True)
                        else:
                            subprocess.run(['ifconfig', interface, 'up'], capture_output=True)
                
                return {'success': True, 'message': 'Network interfaces restored'}
            else:
                return {'success': False, 'error': f'Unknown action: {action}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_process_terminate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle process termination command"""
        try:
            process_name = params.get('process_name')
            process_id = params.get('process_id')
            
            if process_id:
                try:
                    proc = psutil.Process(process_id)
                    proc.terminate()
                    return {'success': True, 'message': f'Process {process_id} terminated'}
                except psutil.NoSuchProcess:
                    return {'success': False, 'error': f'Process {process_id} not found'}
            elif process_name:
                terminated_count = 0
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == process_name.lower():
                            proc.terminate()
                            terminated_count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                return {'success': True, 'message': f'Terminated {terminated_count} processes named {process_name}'}
            else:
                return {'success': False, 'error': 'Either process_name or process_id must be specified'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_file_quarantine(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file quarantine command"""
        try:
            file_path = params.get('file_path')
            quarantine_dir = params.get('quarantine_dir', '/tmp/quarantine')
            
            if platform.system() == 'Windows':
                quarantine_dir = params.get('quarantine_dir', 'C:\\quarantine')
            
            # Create quarantine directory if it doesn't exist
            os.makedirs(quarantine_dir, exist_ok=True)
            
            if os.path.exists(file_path):
                # Move file to quarantine
                filename = os.path.basename(file_path)
                quarantine_path = os.path.join(quarantine_dir, f"{int(time.time())}_{filename}")
                
                if platform.system() == 'Windows':
                    subprocess.run(['move', file_path, quarantine_path], shell=True, capture_output=True)
                else:
                    subprocess.run(['mv', file_path, quarantine_path], capture_output=True)
                
                return {'success': True, 'message': f'File quarantined to {quarantine_path}'}
            else:
                return {'success': False, 'error': f'File not found: {file_path}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _log_action(self, action: str, params: Dict[str, Any]) -> None:
        """Log agent actions for audit"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'params': params,
            'agent_id': self.system_info.get('agent_id'),
            'hostname': self.system_info.get('hostname')
        }
        
        try:
            with open('agent_actions.log', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Error logging action: {e}")
    
    def _encrypt_message(self, message: str) -> str:
        """Encrypt message using Fernet"""
        try:
            f = Fernet(self.encryption_key)
            encrypted = f.encrypt(message.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            return message
    
    def _decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt message using Fernet"""
        try:
            f = Fernet(self.encryption_key)
            decoded = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = f.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            return encrypted_message
    
    def _generate_command_signature(self, command: Dict[str, Any]) -> str:
        """Generate HMAC signature for command"""
        try:
            command_copy = command.copy()
            command_copy.pop('signature', None)
            
            signature = hmac.new(
                self.auth_token.encode(),
                json.dumps(command_copy, sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()
            
            return signature
        except Exception as e:
            logger.error(f"Error generating signature: {e}")
            return ""
    
    def _verify_command_signature(self, command: Dict[str, Any]) -> bool:
        """Verify command signature for security"""
        try:
            # Simple HMAC verification (in production, use proper certificate-based signing)
            signature = command.get('signature', '')
            command_copy = command.copy()
            command_copy.pop('signature', None)
            
            expected_signature = hmac.new(
                self.auth_token.encode(),
                json.dumps(command_copy, sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def _on_message(self, ws, message):
        """Handle incoming WebSocket messages"""
        try:
            # Decrypt message
            decrypted_message = self._decrypt_message(message)
            command = json.loads(decrypted_message)
            
            logger.info(f"Received command: {command.get('action', 'unknown')}")
            
            # Verify signature
            if not self._verify_command_signature(command):
                logger.error("Invalid command signature")
                return
            
            # Check if action is allowed
            action = command.get('action')
            if action not in self.config.get('allowed_actions', []):
                logger.error(f"Action not allowed: {action}")
                return
            
            # Execute command
            handler = self.command_handlers.get(action)
            if handler:
                result = handler(command.get('params', {}))
                result['command_id'] = command.get('command_id')
                result['timestamp'] = datetime.now().isoformat()
                
                # Send response
                response = json.dumps(result)
                encrypted_response = self._encrypt_message(response)
                ws.send(encrypted_response)
                
                # Log action
                self._log_action(action, command.get('params', {}))
            else:
                logger.error(f"No handler for action: {action}")
                
        except Exception as e:
            logger.error(f"Error handling message: {e}")
    
    def _on_error(self, ws, error):
        """Handle WebSocket errors"""
        logger.error(f"WebSocket error: {error}")
    
    def _on_close(self, ws, close_status_code, close_msg):
        """Handle WebSocket close"""
        logger.info("WebSocket connection closed")
        self.running = False
    
    def _on_open(self, ws):
        """Handle WebSocket open"""
        logger.info("WebSocket connection established")
        
        # Send agent registration
        registration = {
            'type': 'agent_registration',
            'agent_id': self.system_info.get('agent_id'),
            'system_info': self.system_info,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            message = json.dumps(registration)
            encrypted_message = self._encrypt_message(message)
            ws.send(encrypted_message)
        except Exception as e:
            logger.error(f"Error sending registration: {e}")
    
    def start(self):
        """Start the agent"""
        logger.info("Starting endpoint security agent...")
        self.running = True
        
        while self.running:
            try:
                # Create WebSocket connection
                ws_url = self.controller_url
                logger.info(f"Connecting to controller: {ws_url}")
                
                # Create WebSocket with SSL context
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE  # For development only
                
                self.ws = websocket.WebSocketApp(
                    ws_url,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open,
                    header=[f"Authorization: Bearer {self.auth_token}"]
                )
                
                # Run WebSocket
                self.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
                
            except Exception as e:
                logger.error(f"Connection error: {e}")
            
            if self.running:
                logger.info(f"Reconnecting in {self.config.get('reconnect_interval', 30)} seconds...")
                time.sleep(self.config.get('reconnect_interval', 30))
    
    def stop(self):
        """Stop the agent"""
        logger.info("Stopping endpoint security agent...")
        self.running = False
        if self.ws:
            self.ws.close()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Endpoint Security Agent')
    parser.add_argument('--config', default='agent_config.json', help='Configuration file')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    agent = EndpointSecurityAgent(args.config)
    
    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        agent.stop()
    except Exception as e:
        logger.error(f"Agent error: {e}")
        agent.stop()

if __name__ == "__main__":
    main()
