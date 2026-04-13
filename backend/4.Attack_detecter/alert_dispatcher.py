#!/usr/bin/env python3
"""
Module 4 Alert Dispatcher

Handles alert distribution and notification:
- File-based alerts (default)
- Optional REST API integration
- Optional SMTP email notifications
- Alert aggregation and deduplication
"""

import os
import json
import smtplib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

class AlertDispatcher:
    """Alert distribution and notification handler"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alert_history = {}
        self.deduplication_window = timedelta(minutes=5)
        
    def dispatch_alert(self, alert: Dict[str, Any]):
        """Dispatch alert through configured channels"""
        try:
            # Check for deduplication
            if self.is_duplicate(alert):
                logger.info(f"Alert {alert['alert_id']} is duplicate, skipping dispatch")
                return
            
            # File-based dispatch (always enabled)
            self.dispatch_to_file(alert)
            
            # REST API dispatch (if configured)
            if self.config.get('rest_api', {}).get('enabled', False):
                self.dispatch_to_rest(alert)
            
            # Email dispatch (if configured)
            if self.config.get('smtp', {}).get('enabled', False):
                self.dispatch_to_email(alert)
            
            # Update history for deduplication
            self.update_history(alert)
            
        except Exception as e:
            logger.error(f"Error dispatching alert {alert.get('alert_id', 'unknown')}: {e}")
    
    def is_duplicate(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is a duplicate within deduplication window"""
        rule_id = alert.get('rule_id', '')
        src_mac = alert.get('evidence', {}).get('src_mac', '')
        key = f"{rule_id}:{src_mac}"
        
        if key in self.alert_history:
            last_alert_time = self.alert_history[key]
            if datetime.now() - last_alert_time < self.deduplication_window:
                return True
        
        return False
    
    def update_history(self, alert: Dict[str, Any]):
        """Update alert history for deduplication"""
        rule_id = alert.get('rule_id', '')
        src_mac = alert.get('evidence', {}).get('src_mac', '')
        key = f"{rule_id}:{src_mac}"
        
        self.alert_history[key] = datetime.now()
    
    def dispatch_to_file(self, alert: Dict[str, Any]):
        """Dispatch alert to file system"""
        try:
            alerts_dir = Path(self.config.get('alerts_dir', os.path.join(os.path.dirname(__file__), 'alerts')))
            alerts_dir.mkdir(exist_ok=True)
            
            # Write individual alert file
            alert_file = alerts_dir / f"{alert['alert_id']}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            # Append to aggregated log
            log_file = alerts_dir / 'alerts.log'
            with open(log_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()}: {json.dumps(alert)}\n")
            
            logger.info(f"Alert {alert['alert_id']} written to file")
            
        except Exception as e:
            logger.error(f"Error writing alert to file: {e}")
    
    def dispatch_to_rest(self, alert: Dict[str, Any]):
        """Dispatch alert to REST API"""
        try:
            api_config = self.config.get('rest_api', {})
            url = api_config.get('url', '')
            headers = api_config.get('headers', {'Content-Type': 'application/json'})
            
            response = requests.post(url, json=alert, headers=headers, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Alert {alert['alert_id']} sent to REST API")
            else:
                logger.warning(f"REST API returned status {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending alert to REST API: {e}")
    
    def dispatch_to_email(self, alert: Dict[str, Any]):
        """Dispatch alert via email"""
        try:
            smtp_config = self.config.get('smtp', {})
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = smtp_config.get('from', 'alerts@bwf-toolkit.local')
            msg['To'] = smtp_config.get('to', 'admin@bwf-toolkit.local')
            msg['Subject'] = f"BWF Toolkit Alert: {alert.get('rule_id', 'Unknown')}"
            
            # Create email body
            body = self.format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(smtp_config.get('host', 'localhost'), 
                                smtp_config.get('port', 587))
            server.starttls()
            
            if smtp_config.get('username'):
                server.login(smtp_config['username'], smtp_config.get('password', ''))
            
            text = msg.as_string()
            server.sendmail(msg['From'], msg['To'], text)
            server.quit()
            
            logger.info(f"Alert {alert['alert_id']} sent via email")
            
        except Exception as e:
            logger.error(f"Error sending alert via email: {e}")
    
    def format_email_body(self, alert: Dict[str, Any]) -> str:
        """Format alert as HTML email body"""
        severity_colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        severity = alert.get('severity', 'medium')
        color = severity_colors.get(severity, '#6c757d')
        
        evidence = alert.get('evidence', {})
        metrics = alert.get('metrics', {})
        
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 20px;">
            <h2 style="color: {color}; border-bottom: 2px solid {color}; padding-bottom: 10px;">
                🚨 BWF Toolkit Security Alert
            </h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <h3>Alert Details</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="font-weight: bold; padding: 5px;">Alert ID:</td><td style="padding: 5px;">{alert.get('alert_id', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Rule:</td><td style="padding: 5px;">{alert.get('rule_id', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Severity:</td><td style="padding: 5px; color: {color};">{severity.upper()}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Timestamp:</td><td style="padding: 5px;">{alert.get('timestamp', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Description:</td><td style="padding: 5px;">{alert.get('rule_description', 'N/A')}</td></tr>
                </table>
            </div>
            
            <div style="background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <h3>Evidence</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="font-weight: bold; padding: 5px;">Protocol:</td><td style="padding: 5px;">{evidence.get('protocol', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Source MAC:</td><td style="padding: 5px;">{evidence.get('src_mac', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Destination MAC:</td><td style="padding: 5px;">{evidence.get('dst_mac', 'N/A')}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Packet Length:</td><td style="padding: 5px;">{evidence.get('length', 'N/A')} bytes</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">PCAP File:</td><td style="padding: 5px;">{evidence.get('pcap_file', 'N/A')}</td></tr>
                </table>
            </div>
            
            <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <h3>Metrics</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="font-weight: bold; padding: 5px;">Confidence:</td><td style="padding: 5px;">{metrics.get('confidence', 0):.2%}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Device Risk Score:</td><td style="padding: 5px;">{metrics.get('device_risk_score', 0):.2f}</td></tr>
                    <tr><td style="font-weight: bold; padding: 5px;">Window Size:</td><td style="padding: 5px;">{metrics.get('window_size', 'N/A')}</td></tr>
                </table>
            </div>
            
            <div style="margin-top: 20px; padding: 10px; background-color: #fff3cd; border-radius: 5px;">
                <p style="margin: 0; font-size: 12px; color: #856404;">
                    This alert was generated by the BWF Toolkit Module 4 - Attack Detection & Threat Intelligence Engine.
                    Please review the evidence and take appropriate action.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def get_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert summary for specified time period"""
        try:
            alerts_dir = Path(self.config.get('alerts_dir', './alerts'))
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            alerts = []
            for alert_file in alerts_dir.glob('*.json'):
                try:
                    with open(alert_file, 'r') as f:
                        alert = json.load(f)
                    
                    alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', ''))
                    if alert_time > cutoff_time:
                        alerts.append(alert)
                
                except Exception as e:
                    logger.error(f"Error reading alert file {alert_file}: {e}")
            
            # Analyze alerts
            severity_counts = {}
            rule_counts = {}
            
            for alert in alerts:
                severity = alert.get('severity', 'unknown')
                rule_id = alert.get('rule_id', 'unknown')
                
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            return {
                'total_alerts': len(alerts),
                'severity_breakdown': severity_counts,
                'rule_breakdown': rule_counts,
                'time_period_hours': hours
            }
            
        except Exception as e:
            logger.error(f"Error generating alert summary: {e}")
            return {'error': str(e)}

def main():
    """Test alert dispatcher functionality"""
    config = {
        'alerts_dir': './alerts',
        'rest_api': {
            'enabled': False,
            'url': 'http://localhost:8080/api/alerts',
            'headers': {'Content-Type': 'application/json'}
        },
        'smtp': {
            'enabled': False,
            'host': 'localhost',
            'port': 587,
            'username': '',
            'password': '',
            'from': 'alerts@bwf-toolkit.local',
            'to': 'admin@bwf-toolkit.local'
        }
    }
    
    dispatcher = AlertDispatcher(config)
    
    # Test alert
    test_alert = {
        'alert_id': 'test-123',
        'rule_id': 'deauth_flood',
        'severity': 'high',
        'timestamp': datetime.now().isoformat() + 'Z',
        'evidence': {
            'src_mac': '00:11:22:33:44:55',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'protocol': 'Wi-Fi',
            'length': 42,
            'pcap_file': 'test.pcap'
        },
        'metrics': {
            'confidence': 0.85,
            'device_risk_score': 0.9
        },
        'rule_description': 'Deauthentication flood detected'
    }
    
    print("Testing alert dispatcher...")
    dispatcher.dispatch_alert(test_alert)
    
    summary = dispatcher.get_alert_summary(24)
    print(f"Alert summary: {summary}")

if __name__ == '__main__':
    main()

