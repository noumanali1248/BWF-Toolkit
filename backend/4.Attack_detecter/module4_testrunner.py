#!/usr/bin/env python3
"""
Module 4 Test Runner - Real-time Analysis Only

Provides comprehensive analysis for Module 4:
- Live telemetry analysis (real Module 3 events only)
- MTTD (Mean Time To Detection) calculation
- Detection coverage analysis
- Precision estimation
- Automated report generation

NO SIMULATIONS - REAL-TIME DATA ONLY
"""

import os
import sys
import json
import sqlite3
import argparse
import statistics
import subprocess
import glob
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import csv

class Module4TestRunner:
    """Comprehensive testing and analysis for Module 4"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results = {
            'test_timestamp': datetime.now().isoformat(),
            'test_type': config.get('test_type', 'unknown'),
            'mttd': {},
            'coverage': {},
            'precision': {},
            'throughput': {},
            'alerts_summary': {},
            'rules_evaluation': {}
        }
    
    def run_live_test(self, duration_minutes: int = 10) -> Dict[str, Any]:
        """Run live testing with real Module 3 telemetry"""
        print(f"Starting live test for {duration_minutes} minutes...")
        
        # Monitor alerts directory
        alerts_dir = Path(self.config.get('alerts_dir', './alerts'))
        alerts_dir.mkdir(exist_ok=True)
        
        # Get initial alert count
        initial_alert_count = len(list(alerts_dir.glob('*.json')))
        
        print(f"Initial alert count: {initial_alert_count}")
        print("Monitoring for new alerts...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        alerts_generated = []
        
        while datetime.now() < end_time:
            # Check for new alerts
            current_alerts = list(alerts_dir.glob('*.json'))
            new_alerts = current_alerts[initial_alert_count:]
            
            for alert_file in new_alerts:
                try:
                    with open(alert_file, 'r') as f:
                        alert = json.load(f)
                    alerts_generated.append(alert)
                    print(f"New alert: {alert['rule_id']} - {alert['severity']}")
                except Exception as e:
                    print(f"Error reading alert {alert_file}: {e}")
            
            initial_alert_count = len(current_alerts)
            time.sleep(5)  # Check every 5 seconds
        
        print(f"Live test completed. Generated {len(alerts_generated)} alerts")
        return self.analyze_alerts(alerts_generated)
    
    def run_real_time_analysis(self, duration_minutes: int = 10) -> Dict[str, Any]:
        """Run real-time analysis with live Module 3 data"""
        print(f"Starting real-time analysis for {duration_minutes} minutes...")
        print("Monitoring real Module 3 telemetry only - no simulations")
        
        # Monitor alerts directory for real-time alerts
        alerts_dir = Path(self.config.get('alerts_dir', './alerts'))
        alerts_dir.mkdir(exist_ok=True)
        
        # Get initial alert count
        initial_alert_count = len(list(alerts_dir.glob('*.json')))
        
        print(f"Initial alert count: {initial_alert_count}")
        print("Monitoring for real-time alerts from Module 3...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        alerts_generated = []
        
        while datetime.now() < end_time:
            # Check for new alerts
            current_alerts = list(alerts_dir.glob('*.json'))
            new_alerts = current_alerts[initial_alert_count:]
            
            for alert_file in new_alerts:
                try:
                    with open(alert_file, 'r') as f:
                        alert = json.load(f)
                    alerts_generated.append(alert)
                    print(f"Real-time alert detected: {alert['rule_id']} - {alert['severity']}")
                except Exception as e:
                    print(f"Error reading alert {alert_file}: {e}")
            
            initial_alert_count = len(current_alerts)
            time.sleep(5)  # Check every 5 seconds
        
        print(f"Real-time analysis completed. Detected {len(alerts_generated)} real alerts")
        return self.analyze_alerts(alerts_generated)
    
    
    def calculate_mttd(self, alerts: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate Mean Time To Detection metrics"""
        if not alerts:
            return {'count': 0, 'mean': 0, 'median': 0, 'max': 0}
        
        detection_times = []
        
        for alert in alerts:
            try:
                alert_ts = datetime.fromisoformat(alert['timestamp'].replace('Z', ''))
                event_ts = datetime.fromisoformat(alert['evidence']['event_timestamp'].replace('Z', ''))
                
                mttd_seconds = (alert_ts - event_ts).total_seconds()
                detection_times.append(mttd_seconds)
            
            except Exception as e:
                print(f"Error calculating MTTD for alert {alert.get('alert_id', 'unknown')}: {e}")
        
        if not detection_times:
            return {'count': 0, 'mean': 0, 'median': 0, 'max': 0}
        
        return {
            'count': len(detection_times),
            'mean': statistics.mean(detection_times),
            'median': statistics.median(detection_times),
            'max': max(detection_times),
            'min': min(detection_times)
        }
    
    def calculate_coverage(self) -> Dict[str, Any]:
        """Calculate detection coverage against system scan"""
        try:
            # Get distinct BSSIDs from Module 3 database
            db_path = self.config.get('database', 'capture_metadata.db')
            if not os.path.exists(db_path):
                return {'error': 'Database not found'}
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(DISTINCT bssid) FROM packet_metadata WHERE bssid != ''")
            db_bssid_count = cursor.fetchone()[0]
            
            conn.close()
            
            # Get system scan count (Windows)
            system_count = self.get_system_scan_count()
            
            coverage_ratio = db_bssid_count / system_count if system_count > 0 else 0
            
            return {
                'database_bssids': db_bssid_count,
                'system_scan_bssids': system_count,
                'coverage_ratio': coverage_ratio,
                'coverage_percentage': coverage_ratio * 100
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def get_system_scan_count(self) -> int:
        """Get BSSID count from system Wi-Fi scan"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    bssid_count = sum(1 for line in lines if 'BSSID' in line)
                    return bssid_count
            else:  # Linux/Mac
                # Use iwlist or similar
                pass
        except Exception as e:
            print(f"Error getting system scan count: {e}")
        
        return 0
    
    def calculate_precision(self, labels_file: str = 'labels.csv') -> Dict[str, Any]:
        """Calculate precision from labeled alerts"""
        try:
            if not os.path.exists(labels_file):
                return {'error': f'Labels file not found: {labels_file}'}
            
            # Load labels
            labels = {}
            with open(labels_file, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) >= 2:
                        labels[row[0]] = int(row[1])  # alert_id -> label (1=TP, 0=FP)
            
            # Load alerts
            alerts_dir = Path(self.config.get('alerts_dir', './alerts'))
            alert_files = list(alerts_dir.glob('*.json'))
            
            tp = fp = 0
            labeled_count = 0
            
            for alert_file in alert_files:
                try:
                    with open(alert_file, 'r') as f:
                        alert = json.load(f)
                    
                    alert_id = alert['alert_id']
                    if alert_id in labels:
                        labeled_count += 1
                        if labels[alert_id] == 1:
                            tp += 1
                        else:
                            fp += 1
                
                except Exception as e:
                    print(f"Error reading alert file {alert_file}: {e}")
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            
            return {
                'labeled_alerts': labeled_count,
                'true_positives': tp,
                'false_positives': fp,
                'precision': precision,
                'recall': 'N/A'  # Would need ground truth for recall
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_throughput(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate alert throughput and daily rates"""
        if not alerts:
            return {'alerts_per_hour': 0, 'alerts_per_day': 0, 'peak_rate': 0}
        
        # Group alerts by hour
        hourly_counts = {}
        for alert in alerts:
            try:
                timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', ''))
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
            except Exception as e:
                print(f"Error processing alert timestamp: {e}")
        
        if not hourly_counts:
            return {'alerts_per_hour': 0, 'alerts_per_day': 0, 'peak_rate': 0}
        
        avg_per_hour = sum(hourly_counts.values()) / len(hourly_counts)
        peak_rate = max(hourly_counts.values())
        
        return {
            'alerts_per_hour': avg_per_hour,
            'alerts_per_day': avg_per_hour * 24,
            'peak_rate': peak_rate,
            'total_alerts': len(alerts)
        }
    
    def analyze_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Comprehensive alert analysis"""
        if not alerts:
            return {'error': 'No alerts to analyze'}
        
        # Calculate MTTD
        mttd_results = self.calculate_mttd(alerts)
        
        # Calculate throughput
        throughput_results = self.calculate_throughput(alerts)
        
        # Rule analysis
        rule_counts = {}
        severity_counts = {}
        
        for alert in alerts:
            rule_id = alert.get('rule_id', 'unknown')
            severity = alert.get('severity', 'unknown')
            
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'mttd': mttd_results,
            'throughput': throughput_results,
            'rule_counts': rule_counts,
            'severity_counts': severity_counts,
            'total_alerts': len(alerts)
        }
    
    def generate_report(self, output_file: str = 'module4_report.json'):
        """Generate comprehensive test report"""
        print("Generating comprehensive test report...")
        
        # Calculate coverage
        coverage_results = self.calculate_coverage()
        
        # Calculate precision
        precision_results = self.calculate_precision()
        
        # Compile final results
        self.results.update({
            'coverage': coverage_results,
            'precision': precision_results
        })
        
        # Write report
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Report generated: {output_file}")
        return self.results
    
    def print_terminal_summary(self):
        """Print terminal-friendly summary"""
        print("\n" + "="*60)
        print("MODULE 4 TEST RESULTS SUMMARY")
        print("="*60)
        
        # MTTD Results
        if 'mttd' in self.results:
            mttd = self.results['mttd']
            print(f"MTTD (Mean Time To Detection):")
            print(f"  Count: {mttd.get('count', 0)}")
            print(f"  Mean: {mttd.get('mean', 0):.2f} seconds")
            print(f"  Median: {mttd.get('median', 0):.2f} seconds")
            print(f"  Max: {mttd.get('max', 0):.2f} seconds")
        
        # Coverage Results
        if 'coverage' in self.results:
            coverage = self.results['coverage']
            if 'error' not in coverage:
                print(f"\nDetection Coverage:")
                print(f"  Database BSSIDs: {coverage.get('database_bssids', 0)}")
                print(f"  System Scan BSSIDs: {coverage.get('system_scan_bssids', 0)}")
                print(f"  Coverage: {coverage.get('coverage_percentage', 0):.1f}%")
        
        # Precision Results
        if 'precision' in self.results:
            precision = self.results['precision']
            if 'error' not in precision:
                print(f"\nPrecision Analysis:")
                print(f"  Labeled Alerts: {precision.get('labeled_alerts', 0)}")
                print(f"  True Positives: {precision.get('true_positives', 0)}")
                print(f"  False Positives: {precision.get('false_positives', 0)}")
                print(f"  Precision: {precision.get('precision', 0):.3f}")
        
        # Throughput Results
        if 'throughput' in self.results:
            throughput = self.results['throughput']
            print(f"\nAlert Throughput:")
            print(f"  Alerts per Hour: {throughput.get('alerts_per_hour', 0):.1f}")
            print(f"  Alerts per Day: {throughput.get('alerts_per_day', 0):.1f}")
            print(f"  Peak Rate: {throughput.get('peak_rate', 0)} alerts/hour")
        
        print("\n" + "="*60)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Module 4 Real-time Analysis Runner')
    parser.add_argument('--live', action='store_true', help='Run real-time analysis with live telemetry')
    parser.add_argument('--duration', type=int, default=10, help='Analysis duration in minutes')
    parser.add_argument('--alerts-dir', default='./alerts', help='Alerts directory')
    parser.add_argument('--database', default='capture_metadata.db', help='Module 3 database')
    parser.add_argument('--rules', default='rules.yml', help='Rules configuration')
    parser.add_argument('--output', default='module4_report.json', help='Output report file')
    parser.add_argument('--labels', default='labels.csv', help='Labels file for precision')
    
    args = parser.parse_args()
    
    if not args.live:
        parser.error("Must specify --live for real-time analysis (no simulations allowed)")
    
    # Initialize test runner
    config = {
        'alerts_dir': args.alerts_dir,
        'database': args.database,
        'rules_file': args.rules,
        'labels_file': args.labels
    }
    
    runner = Module4TestRunner(config)
    
    # Run real-time analysis
    config['test_type'] = 'real_time'
    results = runner.run_real_time_analysis(args.duration)
    
    # Generate report
    runner.results.update(results)
    runner.generate_report(args.output)
    runner.print_terminal_summary()

if __name__ == '__main__':
    main()
