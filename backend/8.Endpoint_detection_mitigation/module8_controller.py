#!/usr/bin/env python3
"""
Module 8: Endpoint Security Controller
Central controller for managing endpoint security agents
NOW WITH AUTO-DEPLOYED VIRTUAL AGENTS FOR DEMO!
"""

import os
import json
import ssl
import time
import hmac
import hashlib
import logging
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import asyncio
import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Import virtual agent manager for auto-deployment
try:
    from .auto_deploy_agents import get_virtual_agent_manager, stop_virtual_agents, VirtualAgentManager
    VIRTUAL_AGENTS_AVAILABLE = True
    logger_temp = logging.getLogger(__name__)
    logger_temp.info("✅ Virtual agent manager loaded successfully")
except ImportError as e:
    VIRTUAL_AGENTS_AVAILABLE = False
    logger_temp = logging.getLogger(__name__)
    logger_temp.warning(f"⚠️ Virtual agent manager not available: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'controller.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Pydantic models
class CommandRequest(BaseModel):
    agent_id: str
    action: str
    params: Dict[str, Any] = {}
    priority: str = "normal"  # low, normal, high, critical

class AgentStatus(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    last_seen: str
    status: str
    system_info: Dict[str, Any]

class CommandResponse(BaseModel):
    command_id: str
    agent_id: str
    action: str
    status: str
    result: Dict[str, Any]
    timestamp: str

class EndpointSecurityController:
    """Central controller for endpoint security agents"""
    
    def __init__(self, config_file: str = 'controller_config.json', auto_deploy_agents: bool = False):
        self.config = self._load_config(config_file)
        self.connected_agents = {}
        # Check if encryption is enabled in config
        self.use_encryption = self.config.get('security', {}).get('enable_encryption', True)
        
        # Derive encryption key
        self.encryption_key = self._derive_encryption_key()
        
        if self.use_encryption:
            logger.info("🔒 Message encryption ENABLED")
        else:
            logger.info("🔓 Message encryption DISABLED (plain JSON mode)")
        
        # Initialize database
        self._init_database()
        
        # WebSocket connections
        self.active_connections = {}
        
        # Real-time monitoring
        self.realtime_metrics = {
            'cpu_usage': {},
            'memory_usage': {},
            'network_activity': {},
            'security_events': [],
            'threat_indicators': []
        }
        
        # Virtual agent manager for auto-deployment (DISABLED BY DEFAULT - USE REAL AGENTS)
        self.virtual_agent_manager = None
        if auto_deploy_agents and VIRTUAL_AGENTS_AVAILABLE:
            logger.warning("⚠️ Virtual agents are for demo only. Deploy real agents for production.")
            self._init_virtual_agents()
        else:
            logger.info("✅ Ready for real agent connections. Virtual agents disabled.")
        
        # Reset all agents to offline on startup
        self._reset_agent_status()
        
        logger.info("Endpoint Security Controller initialized - Real-time mode")
    
    def _reset_agent_status(self):
        """Reset all agents to offline status on startup"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE agents SET status = 'offline'")
            conn.commit()
            logger.info("Reset all agents to offline status")
        except Exception as e:
            logger.error(f"Error resetting agent status: {e}")
        finally:
            conn.close()
    
    def _init_virtual_agents(self):
        """Initialize virtual demo agents automatically"""
        try:
            num_agents = self.config.get('virtual_agents_count', 5)
            logger.info(f"🚀 Auto-deploying {num_agents} virtual demo agents...")
            
            self.virtual_agent_manager = get_virtual_agent_manager(num_agents=num_agents)
            
            # Register virtual agents as connected
            for agent_status in self.virtual_agent_manager.get_all_agents():
                self.connected_agents[agent_status['agent_id']] = {
                    'agent_id': agent_status['agent_id'],
                    'hostname': agent_status['hostname'],
                    'platform': agent_status['platform'],
                    'ip_address': agent_status['ip_address'],
                    'status': 'online',
                    'connected_at': datetime.now(),
                    'last_seen': datetime.now(),
                    'system_info': agent_status['system_info'],
                    'commands_executed': 0,
                    'is_virtual': True  # Mark as virtual agent
                }
            
            logger.info(f"✅ Successfully auto-deployed {len(self.connected_agents)} virtual agents")
        except Exception as e:
            logger.error(f"❌ Error initializing virtual agents: {e}")
            self.virtual_agent_manager = None
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load controller configuration"""
        default_config = {
            'host': '0.0.0.0',
            'port': 8001,
            'auth_token': 'default_token_change_me',
            'ssl_cert': None,
            'ssl_key': None,
            'database_path': 'controller.db',
            'log_retention_days': 30,
            'command_timeout': 300,
            'max_agents': 1000,
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
                'emergency_shutdown',
                'network_isolation',
                'process_terminate',
                'file_quarantine',
                'block_mac',
                'unblock_mac',
                'shutdown_agent'
            ]
        }
        
        # Resolve config file path relative to this script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, config_file)
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Error loading config file: {e}")
        else:
            logger.warning(f"Config file not found at {config_path}, using defaults")
        
        return default_config
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from auth token"""
        password = self.config['auth_token'].encode()
        salt = b'endpoint_security_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _init_database(self):
        """Initialize SQLite database for agent management"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        # Agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                platform TEXT NOT NULL,
                system_info TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT DEFAULT 'offline',
                ip_address TEXT,
                port INTEGER,
                cpu_usage REAL DEFAULT 0,
                memory_usage REAL DEFAULT 0
            )
        """)
        
        # Commands table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                command_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                params TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT,
                created_at TEXT NOT NULL,
                executed_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        """)
        
        # Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def _encrypt_message(self, message: str) -> str:
        """Encrypt message using Fernet (only if encryption is enabled)"""
        if not self.use_encryption:
            return message  # Return plain message if encryption is disabled
        
        try:
            f = Fernet(self.encryption_key)
            encrypted = f.encrypt(message.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            return message
    
    def _decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt message using Fernet (only if encryption is enabled)"""
        if not self.use_encryption:
            return encrypted_message  # Return plain message if encryption is disabled
        
        try:
            f = Fernet(self.encryption_key)
            decoded = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = f.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            # Try to return as plain text in case agent sent unencrypted
            logger.warning("Decryption failed, attempting to use as plain text")
            return encrypted_message
    
    def _generate_command_signature(self, command: Dict[str, Any]) -> str:
        """Generate HMAC signature for command"""
        try:
            command_copy = command.copy()
            command_copy.pop('signature', None)
            
            signature = hmac.new(
                self.config['auth_token'].encode(),
                json.dumps(command_copy, sort_keys=True).encode(),
                hashlib.sha256
            ).hexdigest()
            
            return signature
        except Exception as e:
            logger.error(f"Error generating signature: {e}")
            return ""
    
    def _store_agent(self, agent_data: Dict[str, Any]):
        """Store agent information in database"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO agents 
                (agent_id, hostname, platform, system_info, first_seen, last_seen, status, ip_address, port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_data['agent_id'],
                agent_data['hostname'],
                agent_data['platform'],
                json.dumps(agent_data.get('system_info', {})),
                agent_data.get('first_seen', datetime.now().isoformat()),
                datetime.now().isoformat(),
                'online',
                agent_data.get('ip_address', ''),
                agent_data.get('port', 0)
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error storing agent: {e}")
        finally:
            conn.close()
    
    def _store_command(self, command_data: Dict[str, Any]):
        """Store command in database"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO commands 
                (command_id, agent_id, action, params, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                command_data['command_id'],
                command_data['agent_id'],
                command_data['action'],
                json.dumps(command_data.get('params', {})),
                'pending',
                datetime.now().isoformat()
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error storing command: {e}")
        finally:
            conn.close()
    
    def _update_command_result(self, command_id: str, result: Dict[str, Any]):
        """Update command result in database"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE commands 
                SET status = ?, result = ?, executed_at = ?
                WHERE command_id = ?
            """, (
                'completed',
                json.dumps(result),
                datetime.now().isoformat(),
                command_id
            ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error updating command result: {e}")
        finally:
            conn.close()
    
    def _log_event(self, agent_id: str, level: str, message: str):
        """Log event to database"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO logs (agent_id, level, message, timestamp)
                VALUES (?, ?, ?, ?)
            """, (agent_id, level, message, datetime.now().isoformat()))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error logging event: {e}")
        finally:
            conn.close()
    
    async def handle_agent_connection(self, websocket: WebSocket, agent_id: str):
        """Handle agent WebSocket connection"""
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        
        logger.info(f"Agent {agent_id} connected")
        self._log_event(agent_id, 'INFO', 'Agent connected')
        
        try:
            while True:
                # Receive message from agent
                data = await websocket.receive_text()
                
                # Try to decrypt message, fall back to plain JSON
                try:
                    decrypted_data = self._decrypt_message(data)
                    message = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    # Maybe it's plain JSON (not encrypted)
                    try:
                        message = json.loads(data)
                        logger.info(f"Received unencrypted message from {agent_id}")
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse message from {agent_id}: {e}")
                        continue
                
                if message.get('type') == 'agent_registration':
                    # Handle agent registration
                    agent_data = message
                    agent_data['ip_address'] = websocket.client.host
                    agent_data['port'] = websocket.client.port
                    
                    self.connected_agents[agent_id] = {
                        'websocket': websocket,
                        'data': agent_data,
                        'last_heartbeat': time.time()
                    }
                    
                    self._store_agent(agent_data)
                    logger.info(f"Agent {agent_id} registered: {agent_data.get('hostname', 'Unknown')}")
                
                elif message.get('type') == 'command_response':
                    # Handle command response
                    command_id = message.get('command_id')
                    result = message.get('result', {})
                    
                    self._update_command_result(command_id, result)
                    logger.info(f"Command {command_id} completed for agent {agent_id}")
                
                elif message.get('type') == 'heartbeat':
                    # Handle heartbeat
                    if agent_id in self.connected_agents:
                        self.connected_agents[agent_id]['last_heartbeat'] = time.time()
                
                # Handle enhanced message types (Bluetooth, WiFi, Syslog, Anomalies)
                elif message.get('type') in ['device_update', 'syslog_update', 'anomaly_alert']:
                    try:
                        # Import enhanced handler
                        from .enhanced_module8_controller import handle_enhanced_agent_message
                        await handle_enhanced_agent_message(agent_id, message)
                        device_count = len(message.get('devices', [])) if message.get('type') == 'device_update' else len(message.get('logs', []))
                        logger.info(f"✅ Handled enhanced message '{message.get('type')}' from {agent_id} - {device_count} items")
                    except ImportError as e:
                        logger.error(f"❌ Enhanced Module 8 not available: {e}")
                    except Exception as e:
                        logger.error(f"❌ Error handling enhanced message from {agent_id}: {e}")
                        import traceback
                        traceback.print_exc()
                
                # Handle custom agent formats (wifi, process, bluetooth)
                elif message.get('type') in ['wifi', 'process', 'bluetooth']:
                    try:
                        from .enhanced_module8_controller import handle_enhanced_agent_message
                        
                        # DEBUG: Log the exact message structure
                        logger.info(f"🔍 DEBUG - Message from {agent_id}: {json.dumps(message, indent=2)}")
                        
                        # Convert custom format to standard format
                        # Agent sends data in 'message' field as formatted string
                        msg_text = message.get('message', '')
                        
                        if message.get('type') == 'wifi':
                            # Parse: "SSID: eduroam, BSSID: 3c:78:43:05:69:a0:"
                            import re
                            ssid_match = re.search(r'SSID:\s*([^,]*)', msg_text)
                            bssid_match = re.search(r'BSSID:\s*([A-Fa-f0-9:]+)', msg_text)
                            
                            ssid = ssid_match.group(1).strip() if ssid_match else ''
                            bssid = bssid_match.group(1).strip() if bssid_match else ''
                            
                            standard_message = {
                                'type': 'device_update',
                                'agent_id': agent_id,
                                'device_type': 'wifi',
                                'devices': [{
                                    'ssid': ssid,
                                    'mac_address': bssid,
                                    'signal_strength': 'N/A',
                                    'channel': 'N/A',
                                    'timestamp': message.get('timestamp', datetime.now().isoformat())
                                }],
                                'timestamp': message.get('timestamp', datetime.now().isoformat())
                            }
                            await handle_enhanced_agent_message(agent_id, standard_message)
                            logger.info(f"✅ WiFi: SSID={ssid}, BSSID={bssid}")
                            
                        elif message.get('type') == 'process':
                            # Parse: "Process: chrome.exe, PID: 17104"
                            import re
                            process_match = re.search(r'Process:\s*([^,]+)', msg_text)
                            pid_match = re.search(r'PID:\s*(\d+)', msg_text)
                            
                            process_name = process_match.group(1).strip() if process_match else 'Unknown'
                            pid = pid_match.group(1) if pid_match else 'N/A'
                            
                            standard_message = {
                                'type': 'syslog_update',
                                'agent_id': agent_id,
                                'logs': [{
                                    'process_name': process_name,
                                    'log_content': f"Process: {process_name}, PID: {pid}",
                                    'source': 'windows_process_monitor',
                                    'timestamp': message.get('timestamp', datetime.now().isoformat())
                                }],
                                'timestamp': message.get('timestamp', datetime.now().isoformat())
                            }
                            await handle_enhanced_agent_message(agent_id, standard_message)
                            logger.info(f"✅ Process: {process_name}, PID: {pid}")
                            
                        elif message.get('type') == 'bluetooth':
                            # Parse: "Device: None, Address: 6B:44:79:F5:09:09"
                            import re
                            device_match = re.search(r'Device:\s*([^,]+)', msg_text)
                            address_match = re.search(r'Address:\s*([A-Fa-f0-9:]+)', msg_text)
                            
                            device_name = device_match.group(1).strip() if device_match else 'Unknown Device'
                            address = address_match.group(1).strip() if address_match else ''
                            
                            if device_name == 'None':
                                device_name = 'Unknown Device'
                            
                            standard_message = {
                                'type': 'device_update',
                                'agent_id': agent_id,
                                'device_type': 'bluetooth',
                                'devices': [{
                                    'mac_address': address,
                                    'name': device_name,
                                    'rssi': -100,
                                    'device_type': 'bluetooth',
                                    'timestamp': message.get('timestamp', datetime.now().isoformat())
                                }],
                                'timestamp': message.get('timestamp', datetime.now().isoformat())
                            }
                            await handle_enhanced_agent_message(agent_id, standard_message)
                            logger.info(f"✅ Bluetooth: Device={device_name}, Address={address}")
                            
                    except Exception as e:
                        logger.error(f"❌ Error converting custom format from {agent_id}: {e}")
                        import traceback
                        traceback.print_exc()
                
                else:
                    logger.warning(f"Unknown message type from agent {agent_id}: {message.get('type')}")
                
        except WebSocketDisconnect:
            logger.info(f"Agent {agent_id} disconnected")
            self._log_event(agent_id, 'INFO', 'Agent disconnected')
        except Exception as e:
            logger.error(f"Error handling agent {agent_id}: {e}")
            self._log_event(agent_id, 'ERROR', f'Connection error: {str(e)}')
        finally:
            # Clean up connection
            if agent_id in self.active_connections:
                del self.active_connections[agent_id]
            if agent_id in self.connected_agents:
                del self.connected_agents[agent_id]
            
            # Update agent status to offline
            conn = sqlite3.connect(self.config['database_path'])
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET status = 'offline' WHERE agent_id = ?", (agent_id,))
            conn.commit()
            conn.close()
    
    async def send_command(self, agent_id: str, action: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send command to agent (supports virtual agents)"""
        if agent_id not in self.connected_agents:
            raise HTTPException(status_code=404, detail="Agent not connected")
        
        # Generate command ID
        command_id = f"cmd_{int(time.time())}_{agent_id[:8]}"
        
        # Create command
        command = {
            'command_id': command_id,
            'action': action,
            'params': params or {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Add signature
        command['signature'] = self._generate_command_signature(command)
        
        # Store command
        command_data = {
            'command_id': command_id,
            'agent_id': agent_id,
            'action': action,
            'params': params or {}
        }
        self._store_command(command_data)
        
        # Update enhanced storage for block_mac
        if action == 'block_mac':
            try:
                from .enhanced_module8_controller import enhanced_storage
                mac_address = params.get('mac_address')
                reason = params.get('reason', '')
                if mac_address:
                    enhanced_storage.block_mac_address(agent_id, mac_address, reason)
                    logger.info(f"Updated enhanced storage: Blocked MAC {mac_address}")
            except Exception as e:
                logger.error(f"Failed to update enhanced storage for block_mac: {e}")
        
        # Update enhanced storage for unblock_mac
        elif action == 'unblock_mac':
            try:
                from .enhanced_module8_controller import enhanced_storage
                mac_address = params.get('mac_address')
                if mac_address:
                    enhanced_storage.unblock_mac_address(mac_address)
                    logger.info(f"Updated enhanced storage: Unblocked MAC {mac_address}")
            except Exception as e:
                logger.error(f"Failed to update enhanced storage for unblock_mac: {e}")
        
        # Check if this is a virtual agent
        is_virtual = self.connected_agents[agent_id].get('is_virtual', False)
        
        if is_virtual and self.virtual_agent_manager:
            # Execute command on virtual agent
            try:
                result = self.virtual_agent_manager.execute_command(agent_id, action, params)
                
                # Update command status
                conn = sqlite3.connect(self.config['database_path'])
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE commands 
                    SET status = ?, result = ?, executed_at = ?
                    WHERE command_id = ?
                """, (result['status'], json.dumps(result.get('result', {})), datetime.now().isoformat(), command_id))
                conn.commit()
                conn.close()
                
                # Update agent
                self.connected_agents[agent_id]['last_seen'] = datetime.now()
                self.connected_agents[agent_id]['commands_executed'] = self.connected_agents[agent_id].get('commands_executed', 0) + 1
                
                logger.info(f"✅ Command {command_id} executed on virtual agent {agent_id}: {result['status']}")
                self._log_event(agent_id, 'INFO', f'Command executed: {action}')
                
                return {
                    'command_id': command_id,
                    'status': 'completed',
                    'message': 'Command executed successfully on virtual agent',
                    'result': result
                }
                
            except Exception as e:
                logger.error(f"Error executing command on virtual agent {agent_id}: {e}")
                self._log_event(agent_id, 'ERROR', f'Failed to execute command: {str(e)}')
                raise HTTPException(status_code=500, detail=f"Failed to execute command: {str(e)}")
        
        # Send command to real agent via WebSocket
        try:
            websocket = self.connected_agents[agent_id]['websocket']
            message = json.dumps(command)
            encrypted_message = self._encrypt_message(message)
            await websocket.send_text(encrypted_message)
            
            logger.info(f"Command {command_id} sent to agent {agent_id}")
            self._log_event(agent_id, 'INFO', f'Command sent: {action}')
            
            return {
                'command_id': command_id,
                'status': 'sent',
                'message': 'Command sent successfully'
            }
            
        except Exception as e:
            logger.error(f"Error sending command to agent {agent_id}: {e}")
            self._log_event(agent_id, 'ERROR', f'Failed to send command: {str(e)}')
            raise HTTPException(status_code=500, detail=f"Failed to send command: {str(e)}")
    
    def get_agents(self) -> List[Dict[str, Any]]:
        """Get list of all agents (includes virtual agents and connected agents)"""
        agents = []
        agent_ids_seen = set()
        
        # Get connected agents from memory FIRST (real-time data)
        for agent_id, agent_wrapper in self.connected_agents.items():
            # Get the actual agent data from the wrapper
            agent_data = agent_wrapper.get('data', {})
            
            agents.append({
                'agent_id': agent_id,
                'hostname': agent_data.get('hostname', 'Unknown'),
                'platform': agent_data.get('platform', 'Unknown'),
                'system_info': agent_data.get('system_info', {}),
                'last_seen': agent_wrapper.get('last_seen', datetime.now()).isoformat() if isinstance(agent_wrapper.get('last_seen'), datetime) else agent_wrapper.get('last_seen'),
                'status': agent_wrapper.get('status', 'online'),
                'ip_address': agent_data.get('ip_address', 'N/A'),
                'is_virtual': agent_wrapper.get('is_virtual', False),
                'commands_executed': agent_wrapper.get('commands_executed', 0)
            })
            agent_ids_seen.add(agent_id)
        
        # Get virtual agents if available
        if self.virtual_agent_manager:
            try:
                for agent_status in self.virtual_agent_manager.get_all_agents():
                    if agent_status['agent_id'] not in agent_ids_seen:
                        agents.append({
                            'agent_id': agent_status['agent_id'],
                            'hostname': agent_status['hostname'],
                            'platform': agent_status['platform'],
                            'system_info': agent_status['system_info'],
                            'last_seen': agent_status['last_seen'],
                            'status': agent_status['status'],
                            'ip_address': agent_status['ip_address'],
                            'is_virtual': True,
                            'commands_executed': agent_status.get('commands_executed', 0)
                        })
                        agent_ids_seen.add(agent_status['agent_id'])
            except Exception as e:
                logger.error(f"Error getting virtual agents: {e}")
        
        # Get real agents from database (for historical data)
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT agent_id, hostname, platform, system_info, last_seen, status, ip_address
                FROM agents 
                ORDER BY last_seen DESC
            """)
            
            for row in cursor.fetchall():
                agent_id = row[0]
                # Skip if already added from connected_agents
                if agent_id not in agent_ids_seen:
                    agents.append({
                        'agent_id': agent_id,
                        'hostname': row[1],
                        'platform': row[2],
                        'system_info': json.loads(row[3]) if row[3] else {},
                        'last_seen': row[4],
                        'status': row[5],
                        'ip_address': row[6] if len(row) > 6 else '127.0.0.1',
                        'is_virtual': False
                    })
                    agent_ids_seen.add(agent_id)
            
            return agents
        except Exception as e:
            logger.error(f"Error getting agents from database: {e}")
            return agents  # Return at least virtual agents if database fails
        finally:
            conn.close()
    
    def _get_local_ip(self):
        """Get local IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_commands(self, agent_id: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get command history"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            if agent_id:
                cursor.execute("""
                    SELECT command_id, agent_id, action, params, status, result, created_at, executed_at
                    FROM commands 
                    WHERE agent_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (agent_id, limit))
            else:
                cursor.execute("""
                    SELECT command_id, agent_id, action, params, status, result, created_at, executed_at
                    FROM commands 
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
            
            commands = []
            for row in cursor.fetchall():
                commands.append({
                    'command_id': row[0],
                    'agent_id': row[1],
                    'action': row[2],
                    'params': json.loads(row[3]) if row[3] else {},
                    'status': row[4],
                    'result': json.loads(row[5]) if row[5] else {},
                    'created_at': row[6],
                    'executed_at': row[7]
                })
            
            return commands
        except Exception as e:
            logger.error(f"Error getting commands: {e}")
            return []
        finally:
            conn.close()
    
    def get_logs(self, agent_id: str = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get logs"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            if agent_id:
                cursor.execute("""
                    SELECT log_id, agent_id, level, message, timestamp
                    FROM logs 
                    WHERE agent_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (agent_id, limit))
            else:
                cursor.execute("""
                    SELECT log_id, agent_id, level, message, timestamp
                    FROM logs 
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
            
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'log_id': row[0],
                    'agent_id': row[1],
                    'level': row[2],
                    'message': row[3],
                    'timestamp': row[4]
                })
            
            return logs
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return []
        finally:
            conn.close()
    
    def cleanup_old_data(self):
        """Clean up old data based on retention policy"""
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            cutoff_date = (datetime.now() - timedelta(days=self.config['log_retention_days'])).isoformat()
            
            # Clean up old logs
            cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
            deleted_logs = cursor.rowcount
            
            # Clean up old commands
            cursor.execute("DELETE FROM commands WHERE created_at < ?", (cutoff_date,))
            deleted_commands = cursor.rowcount
            
            conn.commit()
            
            if deleted_logs > 0 or deleted_commands > 0:
                logger.info(f"Cleaned up {deleted_logs} old logs and {deleted_commands} old commands")
                
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
        finally:
            conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get controller statistics (includes virtual agents)"""
        # Get virtual agent stats first
        virtual_stats = {
            'total_agents': 0,
            'online_agents': 0,
            'total_commands': 0,
            'completed_commands': 0
        }
        
        if self.virtual_agent_manager:
            try:
                vm_stats = self.virtual_agent_manager.get_statistics()
                virtual_stats = {
                    'total_agents': vm_stats.get('total_agents', 0),
                    'online_agents': vm_stats.get('online_agents', 0),
                    'total_commands': vm_stats.get('total_commands', 0),
                    'completed_commands': vm_stats.get('completed_commands', 0)
                }
            except Exception as e:
                logger.error(f"Error getting virtual agent statistics: {e}")
        
        conn = sqlite3.connect(self.config['database_path'])
        cursor = conn.cursor()
        
        try:
            # Get real agent statistics
            cursor.execute("SELECT COUNT(*) FROM agents")
            db_total_agents = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM agents WHERE status = 'online'")
            db_online_agents = cursor.fetchone()[0]
            
            # Get command statistics
            cursor.execute("SELECT COUNT(*) FROM commands")
            db_total_commands = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM commands WHERE status = 'completed'")
            db_completed_commands = cursor.fetchone()[0]
            
            # Get recent activity
            cursor.execute("""
                SELECT COUNT(*) FROM logs 
                WHERE timestamp > datetime('now', '-1 hour')
            """)
            recent_logs = cursor.fetchone()[0]
            
            return {
                'total_agents': virtual_stats['total_agents'] + db_total_agents,
                'online_agents': virtual_stats['online_agents'] + db_online_agents,
                'total_commands': virtual_stats['total_commands'] + db_total_commands,
                'completed_commands': virtual_stats['completed_commands'] + db_completed_commands,
                'recent_logs': recent_logs,
                'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0,
                'virtual_agents': virtual_stats['total_agents'],
                'real_agents': db_total_agents
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            # Return at least virtual agent stats
            return {
                **virtual_stats,
                'recent_logs': 0,
                'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0,
                'virtual_agents': virtual_stats['total_agents'],
                'real_agents': 0
            }
        finally:
            conn.close()
    
    def get_realtime_metrics(self, agent_id: str = None) -> Dict[str, Any]:
        """Get real-time system metrics from agents"""
        if agent_id:
            # Return metrics for specific agent
            return {
                'agent_id': agent_id,
                'cpu_usage': self.realtime_metrics['cpu_usage'].get(agent_id, 0),
                'memory_usage': self.realtime_metrics['memory_usage'].get(agent_id, 0),
                'network_activity': self.realtime_metrics['network_activity'].get(agent_id, {}),
                'timestamp': datetime.now().isoformat()
            }
        else:
            # Return aggregated metrics for all agents
            total_cpu = sum(self.realtime_metrics['cpu_usage'].values())
            num_cpu_agents = len(self.realtime_metrics['cpu_usage'])
            avg_cpu = round(total_cpu / num_cpu_agents, 2) if num_cpu_agents > 0 else 0
            
            total_mem = sum(self.realtime_metrics['memory_usage'].values())
            num_mem_agents = len(self.realtime_metrics['memory_usage'])
            avg_mem = round(total_mem / num_mem_agents, 2) if num_mem_agents > 0 else 0
            
            return {
                'total_agents': len(self.connected_agents),
                'online_agents': len([a for a in self.connected_agents.values() if a['status'] == 'online']),
                'average_cpu_usage': avg_cpu,
                'average_memory_usage': avg_mem,
                'active_security_events': len(self.realtime_metrics.get('security_events', [])),
                'threat_indicators': len(self.realtime_metrics.get('threat_indicators', [])),
                'metrics': self.realtime_metrics,
                'timestamp': datetime.now().isoformat()
            }
    
    def update_agent_metrics(self, agent_id: str, metrics: Dict[str, Any]):
        """Update real-time metrics for an agent"""
        try:
            if 'cpu_usage' in metrics:
                self.realtime_metrics['cpu_usage'][agent_id] = float(metrics['cpu_usage'])
            if 'memory_usage' in metrics:
                self.realtime_metrics['memory_usage'][agent_id] = float(metrics['memory_usage'])
            if 'network_activity' in metrics:
                self.realtime_metrics['network_activity'][agent_id] = metrics['network_activity']
            
            # Update last_seen timestamp in database
            if agent_id in self.connected_agents:
                self.connected_agents[agent_id]['last_seen'] = datetime.now()
                
                # Update in database
                conn = sqlite3.connect(self.config['database_path'])
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        UPDATE agents 
                        SET last_seen = ?, 
                            cpu_usage = ?,
                            memory_usage = ?
                        WHERE agent_id = ?
                    """, (
                        datetime.now().isoformat(),
                        metrics.get('cpu_usage', 0),
                        metrics.get('memory_usage', 0),
                        agent_id
                    ))
                    conn.commit()
                finally:
                    conn.close()
            
            logger.debug(f"Updated metrics for agent {agent_id}")
        except Exception as e:
            logger.error(f"Error updating agent metrics: {e}")
    
    def report_security_event(self, agent_id: str, event_type: str, details: Dict[str, Any]):
        """Report a security event from an agent"""
        try:
            event = {
                'event_id': f"evt_{int(time.time()*1000)}_{agent_id}",
                'agent_id': agent_id,
                'event_type': event_type,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'severity': details.get('severity', 'medium')
            }
            
            # Store in memory
            self.realtime_metrics['security_events'].append(event)
            
            # Keep only last 1000 events in memory
            if len(self.realtime_metrics['security_events']) > 1000:
                self.realtime_metrics['security_events'] = self.realtime_metrics['security_events'][-1000:]
            
            # Check if it's a threat indicator
            threat_types = ['malware_detected', 'suspicious_process', 'unauthorized_access', 
                          'network_anomaly', 'ransomware_detected', 'data_exfiltration',
                          'privilege_escalation', 'lateral_movement']
            
            if event_type in threat_types:
                self.realtime_metrics['threat_indicators'].append(event)
                if len(self.realtime_metrics['threat_indicators']) > 500:
                    self.realtime_metrics['threat_indicators'] = self.realtime_metrics['threat_indicators'][-500:]
                logger.critical(f"🚨 THREAT DETECTED - Agent: {agent_id}, Type: {event_type}")
            
            # Store in database
            conn = sqlite3.connect(self.config['database_path'])
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO logs (agent_id, level, message, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (
                    agent_id,
                    'WARNING' if event['severity'] in ['high', 'critical'] else 'INFO',
                    f"Security Event: {event_type} - {details.get('message', 'No details')}",
                    event['timestamp']
                ))
                conn.commit()
            finally:
                conn.close()
            
            logger.warning(f"Security event from {agent_id}: {event_type} - {details.get('message', '')}")
        except Exception as e:
            logger.error(f"Error reporting security event: {e}")

# Global controller instance
controller = None

def get_controller() -> EndpointSecurityController:
    """Get global controller instance"""
    global controller
    if controller is None:
        controller = EndpointSecurityController()
        controller.start_time = time.time()
    return controller

# FastAPI app
app = FastAPI(title="Endpoint Security Controller", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/{agent_id}")
async def websocket_endpoint(websocket: WebSocket, agent_id: str):
    """WebSocket endpoint for agent connections"""
    controller = get_controller()
    await controller.handle_agent_connection(websocket, agent_id)

@app.get("/api/agents")
async def get_agents():
    """Get list of all agents"""
    controller = get_controller()
    return controller.get_agents()

@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get specific agent information"""
    controller = get_controller()
    agents = controller.get_agents()
    
    for agent in agents:
        if agent['agent_id'] == agent_id:
            return agent
    
    raise HTTPException(status_code=404, detail="Agent not found")

@app.post("/api/agents/{agent_id}/commands")
async def send_command_to_agent(agent_id: str, command: CommandRequest):
    """Send command to specific agent"""
    controller = get_controller()
    
    # Validate action
    if command.action not in controller.config['allowed_actions']:
        raise HTTPException(status_code=400, detail=f"Action not allowed: {command.action}")
    
    return await controller.send_command(agent_id, command.action, command.params)

@app.post("/api/module8/send-command")
async def send_simple_command(request: dict):
    """Simplified endpoint for sending commands from frontend"""
    controller = get_controller()
    
    agent_id = request.get('agent_id')
    action = request.get('action')
    params = request.get('params', {})
    
    if not agent_id or not action:
        raise HTTPException(status_code=400, detail="agent_id and action are required")
    
    # Validate action
    if action not in controller.config['allowed_actions']:
        raise HTTPException(status_code=400, detail=f"Action not allowed: {action}")
    
    return await controller.send_command(agent_id, action, params)

@app.get("/api/commands")
async def get_commands(agent_id: str = None, limit: int = 100):
    """Get command history"""
    controller = get_controller()
    return controller.get_commands(agent_id, limit)

@app.get("/api/logs")
async def get_logs(agent_id: str = None, limit: int = 1000):
    """Get logs"""
    controller = get_controller()
    return controller.get_logs(agent_id, limit)

@app.get("/api/statistics")
async def get_statistics():
    """Get controller statistics"""
    controller = get_controller()
    return controller.get_statistics()

@app.post("/api/cleanup")
async def cleanup_data():
    """Clean up old data"""
    controller = get_controller()
    controller.cleanup_old_data()
    return {"message": "Cleanup completed"}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/realtime/metrics")
async def get_realtime_metrics(agent_id: str = None):
    """Get real-time system metrics from agents"""
    controller = get_controller()
    return controller.get_realtime_metrics(agent_id)

@app.get("/api/realtime/security-events")
async def get_security_events(limit: int = 100, severity: str = None):
    """Get recent security events"""
    controller = get_controller()
    events = controller.realtime_metrics.get('security_events', [])
    
    if severity:
        events = [e for e in events if e.get('severity') == severity]
    
    return events[-limit:]

@app.get("/api/realtime/threat-indicators")
async def get_threat_indicators(limit: int = 50):
    """Get threat indicators"""
    controller = get_controller()
    indicators = controller.realtime_metrics.get('threat_indicators', [])
    return indicators[-limit:]

@app.post("/api/agents/{agent_id}/metrics")
async def update_agent_metrics(agent_id: str, metrics: dict):
    """Update real-time metrics for an agent"""
    controller = get_controller()
    controller.update_agent_metrics(agent_id, metrics)
    return {"status": "success"}

@app.post("/api/agents/{agent_id}/security-event")
async def report_security_event(agent_id: str, event: dict):
    """Report a security event from an agent"""
    controller = get_controller()
    controller.report_security_event(
        agent_id, 
        event.get('event_type', 'unknown'),
        event.get('details', {})
    )
    return {"status": "success", "event_id": event.get('event_id')}

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Endpoint Security Controller')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8001, help='Port to bind to')
    parser.add_argument('--config', default='controller_config.json', help='Configuration file')
    
    args = parser.parse_args()
    
    # Start cleanup thread
    def cleanup_worker():
        while True:
            time.sleep(3600)  # Run every hour
            controller = get_controller()
            controller.cleanup_old_data()
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    
    # Start server
    logger.info(f"Starting Endpoint Security Controller on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


@app.delete("/api/module8/cleanup")
async def cleanup_offline_agents():
    """Delete all offline agents and their data"""
    try:
        controller = get_controller() # Ensure controller is initialized
        
        # Get offline agents
        conn = sqlite3.connect(controller.config['database_path'])
        cursor = conn.cursor()
        
        cursor.execute("SELECT agent_id FROM agents WHERE status = 'offline'")
        offline_agents = [row[0] for row in cursor.fetchall()]
        
        deleted_count = 0
        orphans_cleaned = 0
        
        # 1. Delete from Core DB
        if offline_agents:
            logger.info(f"Cleaning up {len(offline_agents)} offline agents: {offline_agents}")
            
            for agent_id in offline_agents:
                # Delete logs
                cursor.execute("DELETE FROM logs WHERE agent_id = ?", (agent_id,))
                # Delete commands
                cursor.execute("DELETE FROM commands WHERE agent_id = ?", (agent_id,))
                # Delete agent
                cursor.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
                
                # Remove from in-memory connected_agents
                if agent_id in controller.connected_agents:
                    del controller.connected_agents[agent_id]
                    logger.info(f"Removed {agent_id} from connected_agents")
            
            deleted_count = len(offline_agents)
            
        # Commit core DB changes
        conn.commit()
        conn.close()

        # 2. Delete from Enhanced DB (Direct Access)
        # CRITICAL: Always clean enhanced DB, even if no offline agents in main DB
        # There may be orphaned data from previously deleted agents
        enhanced_deleted = 0
        orphans_cleaned = 0
        try:
            # Determine path to enhanced DB
            base_dir = os.path.dirname(os.path.abspath(__file__))
            enhanced_db_path = os.path.join(base_dir, 'enhanced_module8.db')
            
            if os.path.exists(enhanced_db_path):
                logger.info(f"Enhanced DB found at {enhanced_db_path}, proceeding with cleanup")
                enhanced_conn = sqlite3.connect(enhanced_db_path)
                enhanced_cursor = enhanced_conn.cursor()
                
                # Tables to clean
                tables = ['bluetooth_devices', 'wifi_networks', 'connected_devices', 
                          'syslogs', 'anomalies', 'agent_baselines', 'blocked_macs']
                
                # Step 1: Delete data for offline agents (if any)
                if offline_agents:
                    logger.info(f"Deleting enhanced DB data for {len(offline_agents)} offline agents")
                    for agent_id in offline_agents:
                        for table in tables:
                            try:
                                enhanced_cursor.execute(f"DELETE FROM {table} WHERE agent_id = ?", (agent_id,))
                                rows_deleted = enhanced_cursor.rowcount
                                if rows_deleted > 0:
                                    logger.info(f"Deleted {rows_deleted} rows from {table} for agent {agent_id}")
                                    enhanced_deleted += rows_deleted
                            except Exception as e:
                                logger.error(f"Error deleting from {table} for {agent_id}: {e}", exc_info=True)
                        logger.info(f"Completed enhanced data deletion for {agent_id}")

                # Step 2: ALWAYS cleanup orphans (agents in enhanced DB but not in main DB)
                # This is CRITICAL - even if there were no offline agents, there may be orphaned data
                logger.info("Checking for orphaned data in enhanced DB...")
                conn = sqlite3.connect(controller.config['database_path'])
                cursor = conn.cursor()
                cursor.execute("SELECT agent_id FROM agents")
                active_agents = set(row[0] for row in cursor.fetchall())
                conn.close()
                logger.info(f"Found {len(active_agents)} active agents in main DB")
                
                # Find all agents in enhanced DB
                all_enhanced_agents = set()
                for table in tables:
                    try:
                        enhanced_cursor.execute(f"SELECT DISTINCT agent_id FROM {table}")
                        for row in enhanced_cursor.fetchall():
                            all_enhanced_agents.add(row[0])
                    except Exception as e:
                        logger.warning(f"Error checking table {table} for orphans: {e}")
                
                logger.info(f"Found {len(all_enhanced_agents)} unique agents in enhanced DB")
                
                # Identify orphans (agents in enhanced DB but NOT in main DB)
                orphans = list(all_enhanced_agents - active_agents)
                
                if orphans:
                    logger.info(f"Found {len(orphans)} orphaned agents in enhanced DB: {orphans}")
                    for agent_id in orphans:
                        for table in tables:
                            try:
                                enhanced_cursor.execute(f"DELETE FROM {table} WHERE agent_id = ?", (agent_id,))
                                rows_deleted = enhanced_cursor.rowcount
                                if rows_deleted > 0:
                                    logger.info(f"Deleted {rows_deleted} orphaned rows from {table} for {agent_id}")
                                    enhanced_deleted += rows_deleted
                            except Exception as e:
                                logger.error(f"Error deleting orphan from {table}: {e}", exc_info=True)
                    orphans_cleaned = len(orphans)
                    logger.info(f"Cleaned up {orphans_cleaned} orphaned agents from enhanced DB")
                else:
                    logger.info("No orphaned agents found in enhanced DB")
                
                # CRITICAL: Commit the changes
                enhanced_conn.commit()
                logger.info(f"✅ Enhanced DB cleanup committed: {enhanced_deleted} total rows deleted")
                enhanced_conn.close()
                
                # Try to clear in-memory caches if module is loaded
                try:
                    from .enhanced_module8_controller import enhanced_storage
                    # Clear caches for deleted agents
                    all_deleted_agents = (offline_agents if offline_agents else []) + orphans
                    for agent_id in all_deleted_agents:
                        if agent_id in enhanced_storage.bluetooth_devices: 
                            del enhanced_storage.bluetooth_devices[agent_id]
                            logger.debug(f"Cleared bluetooth cache for {agent_id}")
                        if agent_id in enhanced_storage.wifi_networks: 
                            del enhanced_storage.wifi_networks[agent_id]
                            logger.debug(f"Cleared wifi cache for {agent_id}")
                        if agent_id in enhanced_storage.connected_devices: 
                            del enhanced_storage.connected_devices[agent_id]
                            logger.debug(f"Cleared connected devices cache for {agent_id}")
                    logger.info("Cleared in-memory caches for deleted agents")
                except Exception as cache_error:
                    logger.warning(f"Could not clear in-memory caches: {cache_error}")
                    
            else:
                logger.warning(f"Enhanced DB not found at {enhanced_db_path}")

        except Exception as e:
            logger.error(f"Error during enhanced DB cleanup: {e}", exc_info=True)
            # Don't fail the entire cleanup if enhanced DB cleanup fails
            # The core DB cleanup already succeeded


        
        if deleted_count == 0 and orphans_cleaned == 0:
            logger.info("No offline agents or orphans to cleanup")
            return {"success": True, "message": "No offline agents to cleanup", "count": 0}
        
        logger.info(f"Successfully cleaned up {deleted_count} offline agents and {orphans_cleaned} orphans")
        return {
            "success": True, 
            "message": f"Successfully removed {deleted_count} offline agents and {orphans_cleaned} orphaned records", 
            "count": deleted_count + orphans_cleaned,
            "agents": offline_agents
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up agents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
