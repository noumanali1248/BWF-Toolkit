#!/usr/bin/env python3
"""
Enhanced Module 8: Backend Toolkit Extension
Handles new agent features:
- Bluetooth device monitoring
- WiFi device scanning
- Syslog collection
- MAC address blocking
- Anomaly detection alerts
- Device baseline tracking
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedModule8Storage:
    """Enhanced storage for new Module 8 features"""
    
    def __init__(self):
        import os
        self.db_path = os.path.join(os.path.dirname(__file__), 'enhanced_module8.db')
        self._init_database()
        
        # In-memory caches
        self.bluetooth_devices = defaultdict(list)
        self.wifi_networks = defaultdict(list)
        self.connected_devices = defaultdict(list)
        self.syslogs = deque(maxlen=10000)
        self.anomalies = deque(maxlen=1000)
        self.blocked_macs = set()
        
        logger.info("Enhanced Module 8 storage initialized")
    
    def _init_database(self):
        """Initialize enhanced database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Bluetooth devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bluetooth_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                device_name TEXT,
                rssi INTEGER,
                device_type TEXT,
                timestamp TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        ''')
        
        # WiFi networks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wifi_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                ssid TEXT,
                mac_address TEXT NOT NULL,
                signal_strength TEXT,
                channel TEXT,
                timestamp TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        ''')
        
        # Connected devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connected_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                ip_address TEXT,
                vendor TEXT,
                hostname TEXT,
                device_type TEXT,
                timestamp TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        ''')
        
        # Syslogs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS syslogs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                log_level TEXT,
                message TEXT,
                source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Blocked MACs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_macs (
                mac_address TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                reason TEXT,
                blocked_at TEXT NOT NULL,
                unblocked_at TEXT,
                status TEXT DEFAULT 'blocked'
            )
        ''')
        
        # Agent baselines table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                baseline_value REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sample_count INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info("Enhanced Module 8 database initialized")
    
    def store_bluetooth_devices(self, agent_id: str, devices: List[Dict[str, Any]]):
        """Store Bluetooth devices"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            mac = device.get('mac_address', '')
            timestamp = device.get('timestamp', datetime.now().isoformat())
            
            # Check if device exists
            cursor.execute(
                'SELECT first_seen FROM bluetooth_devices WHERE agent_id = ? AND mac_address = ?',
                (agent_id, mac)
            )
            result = cursor.fetchone()
            first_seen = result[0] if result else timestamp
            
            # Insert or update
            cursor.execute('''
                INSERT INTO bluetooth_devices 
                (agent_id, mac_address, device_name, rssi, device_type, timestamp, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_id,
                mac,
                device.get('name', 'Unknown'),
                device.get('rssi'),
                device.get('device_type', 'bluetooth'),
                timestamp,
                first_seen,
                timestamp
            ))
        
        conn.commit()
        conn.close()
        
        # Update cache
        self.bluetooth_devices[agent_id] = devices
        
        logger.info(f"Stored {len(devices)} Bluetooth devices for agent {agent_id}")
    
    def store_wifi_networks(self, agent_id: str, networks: List[Dict[str, Any]]):
        """Store WiFi networks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for network in networks:
            mac = network.get('mac_address', '')
            timestamp = network.get('timestamp', datetime.now().isoformat())
            
            # Check if network exists
            cursor.execute(
                'SELECT first_seen FROM wifi_networks WHERE agent_id = ? AND mac_address = ?',
                (agent_id, mac)
            )
            result = cursor.fetchone()
            first_seen = result[0] if result else timestamp
            
            # Insert or update
            cursor.execute('''
                INSERT INTO wifi_networks 
                (agent_id, ssid, mac_address, signal_strength, channel, timestamp, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_id,
                network.get('ssid', 'Unknown'),
                mac,
                network.get('signal_strength', 'Unknown'),
                network.get('channel', 'Unknown'),
                timestamp,
                first_seen,
                timestamp
            ))
        
        conn.commit()
        conn.close()
        
        # Update cache
        self.wifi_networks[agent_id] = networks
        
        logger.info(f"Stored {len(networks)} WiFi networks for agent {agent_id}")
    
    def store_connected_devices(self, agent_id: str, devices: List[Dict[str, Any]]):
        """Store connected devices"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            mac = device.get('mac_address', '')
            timestamp = device.get('timestamp', datetime.now().isoformat())
            
            # Check if device exists
            cursor.execute(
                'SELECT first_seen FROM connected_devices WHERE agent_id = ? AND mac_address = ?',
                (agent_id, mac)
            )
            result = cursor.fetchone()
            first_seen = result[0] if result else timestamp
            
            # Insert or update
            cursor.execute('''
                INSERT INTO connected_devices 
                (agent_id, mac_address, ip_address, vendor, hostname, device_type, timestamp, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_id,
                mac,
                device.get('ip_address', 'Unknown'),
                device.get('vendor', 'Unknown Vendor'),
                device.get('hostname', 'Unknown'),
                device.get('device_type', 'Unknown Device'),
                timestamp,
                first_seen,
                timestamp
            ))
        
        conn.commit()
        conn.close()
        
        # Update cache
        self.connected_devices[agent_id] = devices
        
        logger.info(f"Stored {len(devices)} connected devices for agent {agent_id}")
    
    def store_syslogs(self, agent_id: str, logs: List[Dict[str, Any]]):
        """Store syslogs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for log in logs:
            cursor.execute('''
                INSERT INTO syslogs (agent_id, timestamp, log_level, message, source)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                agent_id,
                log.get('timestamp', datetime.now().isoformat()),
                log.get('log_level', 'INFO'),
                log.get('message', ''),
                log.get('source', 'Unknown')
            ))
            
            # Add to deque
            self.syslogs.append({
                'agent_id': agent_id,
                **log
            })
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored {len(logs)} syslogs for agent {agent_id}")
    
    def block_mac_address(self, agent_id: str, mac_address: str, reason: str):
        """Block MAC address"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_macs (mac_address, agent_id, reason, blocked_at, status)
            VALUES (?, ?, ?, ?, 'blocked')
        ''', (mac_address, agent_id, reason, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        self.blocked_macs.add(mac_address)
        
        logger.warning(f"Blocked MAC address {mac_address} for agent {agent_id}: {reason}")
    
    def unblock_mac_address(self, mac_address: str):
        """Unblock MAC address"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE blocked_macs 
            SET status = 'unblocked', unblocked_at = ?
            WHERE mac_address = ?
        ''', (datetime.now().isoformat(), mac_address))
        
        conn.commit()
        conn.close()
        
        if mac_address in self.blocked_macs:
            self.blocked_macs.remove(mac_address)
        
        logger.info(f"Unblocked MAC address {mac_address}")
    
    def get_agent_devices(self, agent_id: str) -> Dict[str, Any]:
        """Get all devices for an agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get Bluetooth devices
        cursor.execute('''
            SELECT mac_address, device_name, rssi, device_type, last_seen
            FROM bluetooth_devices 
            WHERE agent_id = ?
            ORDER BY last_seen DESC
            LIMIT 100
        ''', (agent_id,))
        
        bluetooth_devices = []
        for row in cursor.fetchall():
            bluetooth_devices.append({
                'mac_address': row[0],
                'name': row[1],
                'rssi': row[2],
                'device_type': row[3],
                'last_seen': row[4]
            })
        
        # Get WiFi networks
        cursor.execute('''
            SELECT ssid, mac_address, signal_strength, channel, last_seen
            FROM wifi_networks 
            WHERE agent_id = ?
            ORDER BY last_seen DESC
            LIMIT 100
        ''', (agent_id,))
        
        wifi_networks = []
        for row in cursor.fetchall():
            wifi_networks.append({
                'ssid': row[0],
                'mac_address': row[1],
                'signal_strength': row[2],
                'channel': row[3],
                'last_seen': row[4]
            })
        
        # Get connected devices (only latest for each MAC)
        cursor.execute('''
            SELECT mac_address, ip_address, vendor, hostname, device_type, last_seen
            FROM connected_devices 
            WHERE agent_id = ? 
            AND (mac_address, last_seen) IN (
                SELECT mac_address, MAX(last_seen)
                FROM connected_devices
                WHERE agent_id = ?
                GROUP BY mac_address
            )
            ORDER BY last_seen DESC
        ''', (agent_id, agent_id))
        
        connected_devices = []
        for row in cursor.fetchall():
            connected_devices.append({
                'mac_address': row[0],
                'ip_address': row[1],
                'vendor': row[2],
                'hostname': row[3],
                'device_type': row[4],
                'last_seen': row[5]
            })
        
        conn.close()
        
        return {
            'bluetooth_devices': bluetooth_devices,
            'wifi_networks': wifi_networks,
            'connected_devices': connected_devices
        }
    
    def get_agent_syslogs(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get syslogs for an agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, log_level, message, source
            FROM syslogs 
            WHERE agent_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (agent_id, limit))
        
        syslogs = []
        for row in cursor.fetchall():
            syslogs.append({
                'timestamp': row[0],
                'log_level': row[1],
                'message': row[2],
                'source': row[3]
            })
        
        conn.close()
        
        return syslogs
    
    def get_blocked_macs(self) -> List[Dict[str, Any]]:
        """Get all blocked MAC addresses"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT mac_address, agent_id, reason, blocked_at, status
                FROM blocked_macs 
                WHERE status = 'blocked'
                ORDER BY blocked_at DESC
            ''')
            
            blocked_macs = []
            for row in cursor.fetchall():
                blocked_macs.append({
                    'mac_address': row[0],
                    'agent_id': row[1],
                    'reason': row[2],
                    'blocked_at': row[3],
                    'status': row[4]
                })
            
            return blocked_macs
        except Exception as e:
            logger.error(f"Error getting blocked MACs: {e}")
            return []
        finally:
            conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Count Bluetooth devices
        cursor.execute('SELECT COUNT(DISTINCT mac_address) FROM bluetooth_devices')
        stats['total_bluetooth_devices'] = cursor.fetchone()[0]
        
        # Count WiFi networks
        cursor.execute('SELECT COUNT(DISTINCT mac_address) FROM wifi_networks')
        stats['total_wifi_networks'] = cursor.fetchone()[0]
        
        # Count connected devices
        cursor.execute('SELECT COUNT(DISTINCT mac_address) FROM connected_devices')
        stats['total_connected_devices'] = cursor.fetchone()[0]
        
        # Count syslogs
        cursor.execute('SELECT COUNT(*) FROM syslogs')
        stats['total_syslogs'] = cursor.fetchone()[0]
        
        # Count blocked MACs
        cursor.execute('SELECT COUNT(*) FROM blocked_macs WHERE status = "blocked"')
        stats['blocked_macs'] = cursor.fetchone()[0]
        
        conn.close()
        
        return stats

    def cleanup_agent_data(self, agent_id: str):
        """Delete all data for a specific agent"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete from all tables
            cursor.execute('DELETE FROM bluetooth_devices WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM wifi_networks WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM connected_devices WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM syslogs WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM blocked_macs WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM agent_baselines WHERE agent_id = ?', (agent_id,))
            
            conn.commit()
            logger.info(f"Cleaned up data for agent {agent_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning up agent data: {e}")
        finally:
            if conn:
                conn.close()
        
        # Clear in-memory caches
        if agent_id in self.bluetooth_devices:
            del self.bluetooth_devices[agent_id]
        if agent_id in self.wifi_networks:
            del self.wifi_networks[agent_id]
            
        # Remove from deques (more expensive, but necessary for complete cleanup)
        self.syslogs = deque([l for l in self.syslogs if l.get('agent_id') != agent_id], maxlen=10000)
        
        logger.info(f"Cleaned up all enhanced data for agent {agent_id}")


# Create global storage instance
enhanced_storage = EnhancedModule8Storage()



def delete_agent_data(agent_id: str):
    """Delete all enhanced data for an agent (called by core controller)"""
    try:
        enhanced_storage.cleanup_agent_data(agent_id)
        return True
    except Exception as e:
        logger.error(f"Error deleting enhanced data for {agent_id}: {e}")
        return False


def cleanup_orphaned_data(active_agent_ids: List[str]) -> List[str]:
    """Delete data for agents that are not in the active list (orphans)"""
    conn = None
    try:
        conn = sqlite3.connect(enhanced_storage.db_path)
        cursor = conn.cursor()
        
        # Get all agent IDs in enhanced DB
        tables = ['bluetooth_devices', 'wifi_networks', 'connected_devices', 'syslogs', 'blocked_macs', 'agent_baselines']
        all_enhanced_agents = set()
        
        for table in tables:
            try:
                cursor.execute(f"SELECT DISTINCT agent_id FROM {table}")
                for row in cursor.fetchall():
                    all_enhanced_agents.add(row[0])
            except Exception as e:
                logger.warning(f"Error checking table {table} for orphans: {e}")
                
        # Find orphans (agents in enhanced DB but not in active list)
        orphans = list(all_enhanced_agents - set(active_agent_ids))
        
        cleaned_count = 0
        for agent_id in orphans:
            if delete_agent_data(agent_id):
                cleaned_count += 1
                
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} orphaned agents from enhanced storage")
            
        return orphans
    except Exception as e:
        logger.error(f"Error cleaning up orphaned data: {e}")
        return []
    finally:
        if conn:
            conn.close()


# API Router for enhanced features
router = APIRouter(prefix="/api/module8/enhanced", tags=["Enhanced Module 8"])


@router.get("/devices/{agent_id}")
async def get_agent_devices(agent_id: str):
    """Get all devices for an agent"""
    try:
        devices = enhanced_storage.get_agent_devices(agent_id)
        return {
            'success': True,
            'agent_id': agent_id,
            'devices': devices
        }
    except Exception as e:
        logger.error(f"Error getting devices for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/syslogs/{agent_id}")
async def get_agent_syslogs(agent_id: str, limit: int = 100):
    """Get syslogs for an agent"""
    try:
        syslogs = enhanced_storage.get_agent_syslogs(agent_id, limit)
        return {
            'success': True,
            'agent_id': agent_id,
            'syslogs': syslogs,
            'count': len(syslogs)
        }
    except Exception as e:
        logger.error(f"Error getting syslogs for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blocked-macs")
async def get_blocked_macs():
    """Get all blocked MAC addresses"""
    try:
        blocked_macs = enhanced_storage.get_blocked_macs()
        return {
            'success': True,
            'blocked_macs': blocked_macs,
            'count': len(blocked_macs)
        }
    except Exception as e:
        logger.error(f"Error getting blocked MACs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/block-mac")
async def block_mac(agent_id: str, mac_address: str, reason: str = ''):
    """Block a MAC address"""
    try:
        enhanced_storage.block_mac_address(agent_id, mac_address, reason)
        return {
            'success': True,
            'message': f'Blocked MAC address {mac_address}',
            'mac_address': mac_address,
            'agent_id': agent_id
        }
    except Exception as e:
        logger.error(f"Error blocking MAC {mac_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock-mac")
async def unblock_mac(mac_address: str):
    """Unblock a MAC address"""
    try:
        enhanced_storage.unblock_mac_address(mac_address)
        return {
            'success': True,
            'message': f'Unblocked MAC address {mac_address}',
            'mac_address': mac_address
        }
    except Exception as e:
        logger.error(f"Error unblocking MAC {mac_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_statistics():
    """Get overall statistics with recent scan data"""
    try:
        stats = enhanced_storage.get_statistics()
        
        # Get recent scan data (last 2 minutes) instead of total
        conn = sqlite3.connect(enhanced_storage.db_path)
        cursor = conn.cursor()
        
        # Get WiFi networks from last scan (last 2 minutes)
        cursor.execute('''
            SELECT COUNT(DISTINCT mac_address) 
            FROM wifi_networks 
            WHERE datetime(last_seen) > datetime('now', '-2 minutes')
        ''')
        recent_wifi = cursor.fetchone()[0] or 0
        
        # Get Bluetooth devices from last scan (last 2 minutes)
        cursor.execute('''
            SELECT COUNT(DISTINCT mac_address) 
            FROM bluetooth_devices 
            WHERE datetime(last_seen) > datetime('now', '-2 minutes')
        ''')
        recent_bluetooth = cursor.fetchone()[0] or 0
        
        conn.close()
        
        # Override with recent scan data
        stats['wifi_networks'] = recent_wifi
        stats['bluetooth_devices'] = recent_bluetooth
        
        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Message handler for enhanced agent messages
async def handle_enhanced_agent_message(agent_id: str, message: Dict[str, Any]):
    """Handle enhanced agent messages"""
    message_type = message.get('type', '')
    
    try:
        if message_type == 'device_update':
            device_type = message.get('device_type', '')
            devices = message.get('devices', [])
            
            if device_type in ['bluetooth', 'bluetooth_classic']:
                enhanced_storage.store_bluetooth_devices(agent_id, devices)
            elif device_type == 'wifi':
                enhanced_storage.store_wifi_networks(agent_id, devices)
            elif device_type == 'connected_devices':
                enhanced_storage.store_connected_devices(agent_id, devices)
                
            logger.info(f"Stored {len(devices)} {device_type} devices from agent {agent_id}")
            
        elif message_type == 'syslog_update':
            logs = message.get('logs', [])
            enhanced_storage.store_syslogs(agent_id, logs)
            logger.info(f"Stored {len(logs)} syslogs from agent {agent_id}")
            
        elif message_type == 'blocked_mac_update':
            mac_data = message.get('blocked_mac', {})
            if mac_data:
                enhanced_storage.block_mac_address(
                    agent_id,
                    mac_data.get('mac_address', ''),
                    mac_data.get('reason', 'Blocked by agent')
                )
            logger.info(f"Processed blocked MAC update from agent {agent_id}")
            
    except Exception as e:
        logger.error(f"Error handling enhanced message from agent {agent_id}: {e}")

# Export storage and handler
__all__ = ['enhanced_storage', 'router', 'handle_enhanced_agent_message']



