#!/usr/bin/env python3
"""
Module 6: Automated Forensic Reporting
Collects real-time data from Modules 1-5 and provides comprehensive reporting
"""
import json
import csv
import sqlite3
import requests
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
import threading
from dataclasses import dataclass, asdict
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'module6_forensic.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ForensicEvent:
    """Unified schema for all forensic events"""
    event_id: str
    timestamp: str
    module: str
    event_type: str
    severity: str
    source: str
    destination: str
    details: Dict[str, Any]
    risk_score: float
    category: str

class Module6ForensicReporter:
    """Main Module 6 implementation for automated forensic reporting"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.events_buffer: List[ForensicEvent] = []
        self.aggregated_data: Dict[str, Any] = {}
        self.running = False
        self.collection_thread = None
        
        # Initialize database
        self.db_path = os.path.join(os.path.dirname(__file__), 'module6_forensic.db')
        self._init_database()
        
        # Initialize output directories
        self._init_directories()
        
        logger.info("Module 6 Forensic Reporter initialized")
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for Module 6"""
        return {
            'collection_interval': 5,  # seconds
            'buffer_size': 1000,
            'database_path': 'module6_forensic.db',
            'output_dirs': {
                'reports': 'reports',
                'exports': 'exports',
                'logs': 'logs'
            },
            'api_endpoints': {
                'module1': 'http://localhost:8000/api/scan/results',
                'module2': 'http://localhost:8000/api/module2/status',  # Use status instead of rogue-devices
                'module3': 'http://localhost:8000/api/module3/status',
                'module4': 'http://localhost:8000/api/module4/status',  # Use status instead of alerts
                'module5': 'http://localhost:8000/api/module5/anomalies'
            }
        }
    
    def _init_database(self):
        """Initialize SQLite database for forensic data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create forensic events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT,
                module TEXT,
                event_type TEXT,
                severity TEXT,
                source TEXT,
                destination TEXT,
                details TEXT,
                risk_score REAL,
                category TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create aggregated reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS aggregated_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE,
                report_type TEXT,
                timestamp TEXT,
                data TEXT,
                summary TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def _init_directories(self):
        """Initialize output directories"""
        for dir_name, dir_path in self.config['output_dirs'].items():
            Path(dir_path).mkdir(exist_ok=True)
        logger.info("Output directories initialized")
    
    def start_collection(self):
        """Start real-time data collection from all modules"""
        if self.running:
            logger.warning("Collection already running")
            return
        
        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collection_thread.start()
        logger.info("Started real-time data collection")
    
    def stop_collection(self):
        """Stop data collection"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Stopped data collection")
    
    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                # Collect data from all modules
                self._collect_module1_data()
                self._collect_module2_data()
                self._collect_module3_data()
                self._collect_module4_data()
                self._collect_module5_data()
                
                # Process and store events
                self._process_events()
                
                # Update aggregated data
                self._update_aggregated_data()
                
                time.sleep(self.config['collection_interval'])
                
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _collect_module1_data(self):
        """Collect data from Module 1 (WiFi/Bluetooth scans)"""
        try:
            response = requests.get(self.config['api_endpoints']['module1'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Process WiFi networks
                for network in data.get('wifi_networks', []):
                    event = ForensicEvent(
                        event_id=f"MOD1_WIFI_{uuid.uuid4().hex[:8]}",
                        timestamp=network.get('first_seen', datetime.now().isoformat()),
                        module='Module1',
                        event_type='wifi_scan',
                        severity='info',
                        source=network.get('bssid', 'unknown'),
                        destination='scanner',
                        details={
                            'ssid': network.get('ssid', ''),
                            'rssi': network.get('rssi', 0),
                            'security': network.get('security', ''),
                            'channel': network.get('channel', 0),
                            'frequency': network.get('frequency', 0)
                        },
                        risk_score=self._calculate_wifi_risk(network),
                        category='network_discovery'
                    )
                    self.events_buffer.append(event)
                
                # Process Bluetooth devices
                for device in data.get('bluetooth_devices', []):
                    event = ForensicEvent(
                        event_id=f"MOD1_BT_{uuid.uuid4().hex[:8]}",
                        timestamp=device.get('first_seen', datetime.now().isoformat()),
                        module='Module1',
                        event_type='bluetooth_scan',
                        severity='info',
                        source=device.get('address', 'unknown'),
                        destination='scanner',
                        details={
                            'name': device.get('name', ''),
                            'device_class': device.get('device_class', 0),
                            'paired': device.get('paired', False),
                            'connectable': device.get('connectable', False)
                        },
                        risk_score=self._calculate_bluetooth_risk(device),
                        category='device_discovery'
                    )
                    self.events_buffer.append(event)
                
                logger.debug(f"Collected {len(data.get('wifi_networks', []))} WiFi networks and {len(data.get('bluetooth_devices', []))} Bluetooth devices")
                
        except Exception as e:
            logger.error(f"Error collecting Module 1 data: {e}")
    
    def _collect_module2_data(self):
        """Collect data from Module 2 (Rogue device detection)"""
        try:
            response = requests.get(self.config['api_endpoints']['module2'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Create event for Module 2 status
                event = ForensicEvent(
                    event_id=f"MOD2_STATUS_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now().isoformat(),
                    module='Module2',
                    event_type='rogue_detection_status',
                    severity='info',
                    source='rogue_detector',
                    destination='forensic_reporter',
                    details={
                        'available': data.get('available', False),
                        'running': data.get('running', False),
                        'rules_loaded': data.get('rules_loaded', 0),
                        'real_time_only': data.get('real_time_only', True)
                    },
                    risk_score=0.3,  # Low risk for status updates
                    category='system_status'
                )
                self.events_buffer.append(event)
                
                logger.debug(f"Collected Module 2 status: {data}")
            else:
                logger.debug(f"Module 2 API returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error collecting Module 2 data: {e}")
    
    def _collect_module3_data(self):
        """Collect data from Module 3 (Packet capture)"""
        try:
            response = requests.get(self.config['api_endpoints']['module3'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('queue_size', 0) > 0:
                    event = ForensicEvent(
                        event_id=f"MOD3_PACKET_{uuid.uuid4().hex[:8]}",
                        timestamp=datetime.now().isoformat(),
                        module='Module3',
                        event_type='packet_capture',
                        severity='info',
                        source='network_interface',
                        destination='packet_analyzer',
                        details={
                            'queue_size': data.get('queue_size', 0),
                            'files_created': data.get('files_created', 0),
                            'database_path': data.get('database_path', ''),
                            'real_data_only': data.get('real_data_only', True)
                        },
                        risk_score=0.3,  # Medium risk for packet capture activity
                        category='network_monitoring'
                    )
                    self.events_buffer.append(event)
                
                logger.debug(f"Collected packet capture data: {data.get('queue_size', 0)} packets")
                
        except Exception as e:
            logger.error(f"Error collecting Module 3 data: {e}")
    
    def _collect_module4_data(self):
        """Collect data from Module 4 (Attack detection)"""
        try:
            response = requests.get(self.config['api_endpoints']['module4'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Create event for Module 4 status
                event = ForensicEvent(
                    event_id=f"MOD4_STATUS_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now().isoformat(),
                    module='Module4',
                    event_type='attack_detection_status',
                    severity='info',
                    source='attack_detector',
                    destination='forensic_reporter',
                    details={
                        'available': data.get('available', False),
                        'running': data.get('running', False),
                        'rules_loaded': data.get('rules_loaded', 0),
                        'alerts_dir': data.get('alerts_dir', ''),
                        'real_time_only': data.get('real_time_only', True)
                    },
                    risk_score=0.3,  # Low risk for status updates
                    category='system_status'
                )
                self.events_buffer.append(event)
                
                logger.debug(f"Collected Module 4 status: {data}")
            else:
                logger.debug(f"Module 4 API returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error collecting Module 4 data: {e}")
    
    def _collect_module5_data(self):
        """Collect data from Module 5 (Anomaly detection)"""
        try:
            response = requests.get(self.config['api_endpoints']['module5'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                for anomaly in data:
                    event = ForensicEvent(
                        event_id=f"MOD5_ANOMALY_{uuid.uuid4().hex[:8]}",
                        timestamp=anomaly.get('timestamp', datetime.now().isoformat()),
                        module='Module5',
                        event_type='anomaly_detection',
                        severity=anomaly.get('severity', 'medium'),
                        source=anomaly.get('device_id', 'unknown'),
                        destination='anomaly_detector',
                        details={
                            'rule_name': anomaly.get('rule_name', ''),
                            'combined_score': anomaly.get('combined_score', 0.0),
                            'explanation': anomaly.get('explanation', []),
                            'evidence': anomaly.get('evidence', {})
                        },
                        risk_score=anomaly.get('combined_score', 0.5),
                        category='behavioral_analysis'
                    )
                    self.events_buffer.append(event)
                
                logger.debug(f"Collected {len(data)} anomalies")
                
        except Exception as e:
            logger.error(f"Error collecting Module 5 data: {e}")
    
    def _calculate_wifi_risk(self, network: Dict[str, Any]) -> float:
        """Calculate risk score for WiFi network"""
        risk = 0.0
        
        # Open networks are high risk
        if network.get('security', '').lower() in ['open', 'none']:
            risk += 0.7
        
        # Hidden networks are medium risk
        if 'Hidden Network' in network.get('ssid', ''):
            risk += 0.4
        
        # Weak signal might indicate proximity
        if network.get('rssi', -100) > -50:
            risk += 0.2
        
        return min(risk, 1.0)
    
    def _calculate_bluetooth_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk score for Bluetooth device"""
        risk = 0.0
        
        # Paired devices are higher risk
        if device.get('paired', False):
            risk += 0.5
        
        # Unknown devices are medium risk
        if device.get('name', '').lower() in ['unknown', '']:
            risk += 0.3
        
        return min(risk, 1.0)
    
    def _calculate_attack_risk(self, alert: Dict[str, Any]) -> float:
        """Calculate risk score for attack alert"""
        severity_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        return severity_map.get(alert.get('severity', 'medium'), 0.6)
    
    def _process_events(self):
        """Process and store events from buffer"""
        if not self.events_buffer:
            return
        
        # Store events in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for event in self.events_buffer:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO forensic_events 
                    (event_id, timestamp, module, event_type, severity, source, destination, 
                     details, risk_score, category)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp,
                    event.module,
                    event.event_type,
                    event.severity,
                    event.source,
                    event.destination,
                    json.dumps(event.details),
                    event.risk_score,
                    event.category
                ))
            except Exception as e:
                logger.error(f"Error storing event {event.event_id}: {e}")
        
        conn.commit()
        conn.close()
        
        # Clear buffer
        self.events_buffer.clear()
        logger.debug(f"Processed and stored events")
    
    def _update_aggregated_data(self):
        """Update aggregated data summary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get summary statistics
        cursor.execute("""
            SELECT 
                module,
                event_type,
                severity,
                COUNT(*) as count,
                AVG(risk_score) as avg_risk
            FROM forensic_events 
            WHERE timestamp >= datetime('now', '-1 hour')
            GROUP BY module, event_type, severity
        """)
        
        stats = cursor.fetchall()
        
        # Get recent events
        cursor.execute("""
            SELECT * FROM forensic_events 
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        
        recent_events = cursor.fetchall()
        
        conn.close()
        
        self.aggregated_data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': stats,
            'recent_events': recent_events,
            'total_events': len(recent_events)
        }
    
    def get_aggregated_data(self) -> Dict[str, Any]:
        """Get current aggregated data"""
        return self.aggregated_data
    
    def export_to_json(self, filename: str = None) -> str:
        """Export comprehensive forensic data to JSON"""
        if not filename:
            filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.config['output_dirs']['exports'], filename)
        
        # Ensure directory exists
        os.makedirs(self.config['output_dirs']['exports'], exist_ok=True)
        
        # Get all events from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT event_id, timestamp, module, event_type, severity, 
                   source, destination, risk_score, category, details
            FROM forensic_events 
            ORDER BY timestamp DESC
        """)
        
        events = []
        for row in cursor.fetchall():
            events.append({
                'event_id': row[0],
                'timestamp': row[1],
                'module': row[2],
                'event_type': row[3],
                'severity': row[4],
                'source': row[5],
                'destination': row[6],
                'risk_score': row[7],
                'category': row[8],
                'details': json.loads(row[9]) if row[9] else {}
            })
        
        conn.close()
        
        # Collect data from all modules for comprehensive report
        module_data = {}
        try:
            # Module 1 data
            response = requests.get(self.config['api_endpoints']['module1'], timeout=5)
            if response.status_code == 200:
                module_data['module1'] = response.json()
        except:
            module_data['module1'] = {'error': 'Unable to fetch Module 1 data'}
        
        try:
            # Module 2 data
            response = requests.get(self.config['api_endpoints']['module2'], timeout=5)
            if response.status_code == 200:
                module_data['module2'] = response.json()
        except:
            module_data['module2'] = {'error': 'Unable to fetch Module 2 data'}
        
        try:
            # Module 3 data
            response = requests.get(self.config['api_endpoints']['module3'], timeout=5)
            if response.status_code == 200:
                module_data['module3'] = response.json()
        except:
            module_data['module3'] = {'error': 'Unable to fetch Module 3 data'}
        
        try:
            # Module 4 data
            response = requests.get(self.config['api_endpoints']['module4'], timeout=5)
            if response.status_code == 200:
                module_data['module4'] = response.json()
        except:
            module_data['module4'] = {'error': 'Unable to fetch Module 4 data'}
        
        try:
            # Module 5 data
            response = requests.get(self.config['api_endpoints']['module5'], timeout=5)
            if response.status_code == 200:
                module_data['module5'] = response.json()
        except:
            module_data['module5'] = {'error': 'Unable to fetch Module 5 data'}
        
        # Create comprehensive report
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_id': f'FORENSIC_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'total_events': len(events),
                'modules_analyzed': list(set(event['module'] for event in events)),
                'export_type': 'JSON',
                'data_completeness': 'Full data from all modules'
            },
            'summary_statistics': self.get_aggregated_data(),
            'module_data': module_data,
            'forensic_events': events,
            'recommendations': self._generate_recommendations([], [])
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Comprehensive JSON report exported to {filepath}")
        return filepath
    
    def export_to_csv(self, filename: str = None) -> str:
        """Export comprehensive events to CSV"""
        if not filename:
            filename = f"forensic_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = os.path.join(self.config['output_dirs']['exports'], filename)
        
        # Ensure directory exists
        os.makedirs(self.config['output_dirs']['exports'], exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT event_id, timestamp, module, event_type, severity, 
                   source, destination, risk_score, category, details
            FROM forensic_events 
            ORDER BY timestamp DESC
        """)
        
        events = cursor.fetchall()
        conn.close()
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Event ID', 'Timestamp', 'Module', 'Event Type', 'Severity',
                'Source', 'Destination', 'Risk Score', 'Category', 'Details'
            ])
            
            for event in events:
                writer.writerow([
                    event[0], event[1], event[2], event[3], event[4],
                    event[5], event[6], event[7], event[8], json.dumps(event[9])
                ])
        
        logger.info(f"Comprehensive CSV report exported: {filepath}")
        return filepath
    
    def export_to_pdf(self, filename: str = None) -> str:
        """Export comprehensive report to PDF"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
        except ImportError:
            logger.error("ReportLab not installed. Install with: pip install reportlab")
            return None
        
        if not filename:
            filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        filepath = os.path.join(self.config['output_dirs']['exports'], filename)
        
        # Ensure directory exists
        os.makedirs(self.config['output_dirs']['exports'], exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("BWF Toolkit - Forensic Report", title_style))
        story.append(Spacer(1, 12))
        
        # Report metadata
        story.append(Paragraph("Report Information", styles['Heading2']))
        metadata = f"""
        <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Report ID:</b> FORENSIC_{datetime.now().strftime('%Y%m%d_%H%M%S')}<br/>
        <b>Export Type:</b> PDF<br/>
        <b>Data Completeness:</b> Full data from all modules
        """
        story.append(Paragraph(metadata, styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Get data from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Summary statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT module) as modules_active,
                AVG(risk_score) as avg_risk_score
            FROM forensic_events
        """)
        stats = cursor.fetchone()
        
        story.append(Paragraph("Summary Statistics", styles['Heading2']))
        summary_data = [
            ['Metric', 'Value'],
            ['Total Events', str(stats[0])],
            ['Active Modules', str(stats[1])],
            ['Average Risk Score', f"{stats[2]:.3f}" if stats[2] else "0.000"]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))
        
        # Recent events table
        cursor.execute("""
            SELECT event_id, timestamp, module, event_type, severity, risk_score
            FROM forensic_events 
            ORDER BY timestamp DESC
            LIMIT 20
        """)
        recent_events = cursor.fetchall()
        
        if recent_events:
            story.append(Paragraph("Recent Forensic Events", styles['Heading2']))
            events_data = [['Event ID', 'Timestamp', 'Module', 'Type', 'Severity', 'Risk Score']]
            for event in recent_events:
                events_data.append([
                    event[0][:8] + '...',  # Truncate event ID
                    event[1][:19],  # Truncate timestamp
                    event[2],
                    event[3],
                    event[4],
                    f"{event[5]:.3f}" if event[5] else "0.000"
                ])
            
            events_table = Table(events_data)
            events_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            story.append(events_table)
            story.append(Spacer(1, 12))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        recommendations = [
            "Regularly review network scan results for unauthorized devices",
            "Monitor anomaly detection alerts for behavioral changes",
            "Maintain updated security policies based on threat patterns",
            "Conduct periodic security assessments using collected forensic data"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        conn.close()
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"Comprehensive PDF report exported: {filepath}")
        return filepath
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive summary report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get comprehensive statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT module) as modules_active,
                COUNT(DISTINCT event_type) as event_types,
                AVG(risk_score) as avg_risk_score,
                MAX(risk_score) as max_risk_score
            FROM forensic_events
        """)
        
        summary_stats = cursor.fetchone()
        
        # Get module breakdown
        cursor.execute("""
            SELECT module, COUNT(*) as event_count, AVG(risk_score) as avg_risk
            FROM forensic_events 
            GROUP BY module
            ORDER BY event_count DESC
        """)
        
        module_breakdown = cursor.fetchall()
        
        # Get severity breakdown
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM forensic_events 
            GROUP BY severity
            ORDER BY count DESC
        """)
        
        severity_breakdown = cursor.fetchall()
        
        # Get recent high-risk events
        cursor.execute("""
            SELECT * FROM forensic_events 
            WHERE risk_score > 0.7
            ORDER BY timestamp DESC 
            LIMIT 10
        """)
        
        high_risk_events = cursor.fetchall()
        
        conn.close()
        
        report = {
            'report_id': f"FORENSIC_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'summary_statistics': {
                'total_events': summary_stats[0],
                'modules_active': summary_stats[1],
                'event_types': summary_stats[2],
                'average_risk_score': round(summary_stats[3], 3) if summary_stats[3] else 0,
                'maximum_risk_score': round(summary_stats[4], 3) if summary_stats[4] else 0
            },
            'module_breakdown': [
                {'module': row[0], 'event_count': row[1], 'avg_risk': round(row[2], 3)}
                for row in module_breakdown
            ],
            'severity_breakdown': [
                {'severity': row[0], 'count': row[1]}
                for row in severity_breakdown
            ],
            'high_risk_events': high_risk_events[:5],  # Top 5 high-risk events
            'recommendations': self._generate_recommendations(severity_breakdown, high_risk_events)
        }
        
        return report
    
    def _generate_recommendations(self, severity_breakdown: List, high_risk_events: List) -> List[str]:
        """Generate security recommendations based on data"""
        recommendations = []
        
        # Check for high severity events
        high_severity_count = sum(row[1] for row in severity_breakdown if row[0] in ['critical', 'high'])
        if high_severity_count > 0:
            recommendations.append(f"Immediate attention required: {high_severity_count} high/critical severity events detected")
        
        # Check for high-risk events
        if len(high_risk_events) > 0:
            recommendations.append(f"Review {len(high_risk_events)} high-risk events for potential security threats")
        
        # General recommendations
        recommendations.extend([
            "Regularly review network scan results for unauthorized devices",
            "Monitor anomaly detection alerts for behavioral changes",
            "Maintain updated security policies based on threat patterns",
            "Conduct periodic security assessments using collected forensic data"
        ])
        
        return recommendations

# Global instance
forensic_reporter = None

def get_forensic_reporter() -> Module6ForensicReporter:
    """Get global forensic reporter instance"""
    global forensic_reporter
    if forensic_reporter is None:
        forensic_reporter = Module6ForensicReporter()
    return forensic_reporter
