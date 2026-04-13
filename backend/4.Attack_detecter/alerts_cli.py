#!/usr/bin/env python3
"""
Module 4 Alerts CLI - Simple command-line tool for viewing alerts

Usage:
    python alerts_cli.py show                    # Show latest alerts
    python alerts_cli.py show --severity high    # Show high severity alerts
    python alerts_cli.py show --rule deauth_flood # Show specific rule alerts
    python alerts_cli.py summary                 # Show alert summary
    python alerts_cli.py stats                   # Show statistics
"""

import os
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

class AlertsCLI:
    """Command-line interface for Module 4 alerts"""
    
    def __init__(self, alerts_dir: str = './alerts'):
        self.alerts_dir = Path(alerts_dir)
    
    def show_alerts(self, limit: int = 10, severity: Optional[str] = None, 
                   rule: Optional[str] = None, hours: int = 24):
        """Show latest alerts with optional filtering"""
        alerts = self.load_alerts(severity, rule, hours)
        
        if not alerts:
            print("No alerts found matching criteria")
            return
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Limit results
        alerts = alerts[:limit]
        
        print(f"\n{'='*80}")
        print(f"MODULE 4 ALERTS ({len(alerts)} shown)")
        print(f"{'='*80}")
        
        for alert in alerts:
            self.print_alert(alert)
            print("-" * 80)
    
    def show_summary(self, hours: int = 24):
        """Show alert summary statistics"""
        alerts = self.load_alerts(hours=hours)
        
        if not alerts:
            print("No alerts found in the specified time period")
            return
        
        # Calculate statistics
        severity_counts = {}
        rule_counts = {}
        hourly_counts = {}
        
        for alert in alerts:
            severity = alert.get('severity', 'unknown')
            rule_id = alert.get('rule_id', 'unknown')
            timestamp = alert.get('timestamp', '')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            try:
                alert_time = datetime.fromisoformat(timestamp.replace('Z', ''))
                hour_key = alert_time.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
            except:
                pass
        
        print(f"\n{'='*60}")
        print(f"ALERT SUMMARY (Last {hours} hours)")
        print(f"{'='*60}")
        print(f"Total Alerts: {len(alerts)}")
        
        print(f"\nSeverity Breakdown:")
        for severity, count in sorted(severity_counts.items()):
            color = self.get_severity_color(severity)
            print(f"  {color}{severity.upper():<10}{self.reset_color()} {count}")
        
        print(f"\nRule Breakdown:")
        for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rule:<20} {count}")
        
        if hourly_counts:
            print(f"\nHourly Distribution:")
            for hour, count in sorted(hourly_counts.items()):
                print(f"  {hour.strftime('%Y-%m-%d %H:00')} {count}")
    
    def show_stats(self):
        """Show detailed statistics"""
        alerts = self.load_alerts(hours=24*7)  # Last week
        
        if not alerts:
            print("No alerts found in the last week")
            return
        
        # Calculate MTTD
        mttd_times = []
        for alert in alerts:
            try:
                alert_ts = datetime.fromisoformat(alert['timestamp'].replace('Z', ''))
                event_ts = datetime.fromisoformat(alert['evidence']['event_timestamp'].replace('Z', ''))
                mttd = (alert_ts - event_ts).total_seconds()
                mttd_times.append(mttd)
            except:
                pass
        
        print(f"\n{'='*60}")
        print("DETAILED STATISTICS")
        print(f"{'='*60}")
        
        print(f"Total Alerts (7 days): {len(alerts)}")
        
        if mttd_times:
            avg_mttd = sum(mttd_times) / len(mttd_times)
            min_mttd = min(mttd_times)
            max_mttd = max(mttd_times)
            
            print(f"\nMTTD (Mean Time To Detection):")
            print(f"  Average: {avg_mttd:.2f} seconds")
            print(f"  Minimum: {min_mttd:.2f} seconds")
            print(f"  Maximum: {max_mttd:.2f} seconds")
        
        # Alert rate
        first_alert = min(alerts, key=lambda x: x.get('timestamp', ''))
        last_alert = max(alerts, key=lambda x: x.get('timestamp', ''))
        
        try:
            first_ts = datetime.fromisoformat(first_alert['timestamp'].replace('Z', ''))
            last_ts = datetime.fromisoformat(last_alert['timestamp'].replace('Z', ''))
            duration_hours = (last_ts - first_ts).total_seconds() / 3600
            
            if duration_hours > 0:
                rate = len(alerts) / duration_hours
                print(f"\nAlert Rate: {rate:.2f} alerts/hour")
        except:
            pass
    
    def load_alerts(self, severity: Optional[str] = None, rule: Optional[str] = None, 
                   hours: int = 24) -> List[Dict[str, Any]]:
        """Load alerts with optional filtering"""
        if not self.alerts_dir.exists():
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        alerts = []
        
        for alert_file in self.alerts_dir.glob('*.json'):
            try:
                with open(alert_file, 'r') as f:
                    alert = json.load(f)
                
                # Filter by timestamp
                try:
                    alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', ''))
                    if alert_time < cutoff_time:
                        continue
                except:
                    continue
                
                # Filter by severity
                if severity and alert.get('severity', '').lower() != severity.lower():
                    continue
                
                # Filter by rule
                if rule and alert.get('rule_id', '') != rule:
                    continue
                
                alerts.append(alert)
                
            except Exception as e:
                print(f"Error reading {alert_file}: {e}")
        
        return alerts
    
    def print_alert(self, alert: Dict[str, Any]):
        """Print a single alert in formatted form"""
        severity = alert.get('severity', 'unknown')
        color = self.get_severity_color(severity)
        
        print(f"{color}[ALERT] {severity.upper()}{self.reset_color()} - {alert.get('rule_id', 'unknown')}")
        print(f"ID: {alert.get('alert_id', 'N/A')}")
        print(f"Time: {alert.get('timestamp', 'N/A')}")
        print(f"Description: {alert.get('rule_description', 'N/A')}")
        
        evidence = alert.get('evidence', {})
        if evidence:
            print(f"Evidence:")
            print(f"  Protocol: {evidence.get('protocol', 'N/A')}")
            print(f"  Source MAC: {evidence.get('src_mac', 'N/A')}")
            print(f"  Dest MAC: {evidence.get('dst_mac', 'N/A')}")
            print(f"  Length: {evidence.get('length', 'N/A')} bytes")
            if evidence.get('pcap_file'):
                print(f"  PCAP: {evidence.get('pcap_file')}")
        
        metrics = alert.get('metrics', {})
        if metrics:
            print(f"Metrics:")
            print(f"  Confidence: {metrics.get('confidence', 0):.2%}")
            print(f"  Device Risk: {metrics.get('device_risk_score', 0):.2f}")
    
    def get_severity_color(self, severity: str) -> str:
        """Get ANSI color code for severity"""
        colors = {
            'critical': '\033[91m',  # Red
            'high': '\033[91m',      # Red
            'medium': '\033[93m',    # Yellow
            'low': '\033[92m',       # Green
            'info': '\033[94m'       # Blue
        }
        return colors.get(severity.lower(), '\033[0m')
    
    def reset_color(self) -> str:
        """Reset ANSI color"""
        return '\033[0m'

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Module 4 Alerts CLI')
    parser.add_argument('command', choices=['show', 'summary', 'stats'], 
                       help='Command to execute')
    parser.add_argument('--alerts-dir', default=os.path.join(os.path.dirname(__file__), 'alerts'), 
                       help='Alerts directory')
    parser.add_argument('--limit', type=int, default=10, 
                       help='Number of alerts to show')
    parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'],
                       help='Filter by severity')
    parser.add_argument('--rule', help='Filter by rule ID')
    parser.add_argument('--hours', type=int, default=24,
                       help='Time window in hours')
    
    args = parser.parse_args()
    
    cli = AlertsCLI(args.alerts_dir)
    
    if args.command == 'show':
        cli.show_alerts(args.limit, args.severity, args.rule, args.hours)
    elif args.command == 'summary':
        cli.show_summary(args.hours)
    elif args.command == 'stats':
        cli.show_stats()

if __name__ == '__main__':
    main()
