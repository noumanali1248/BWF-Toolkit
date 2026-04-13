#!/usr/bin/env python3
"""
Enhanced Module 5 - Real-time Anomaly Detection
Integrates with Modules 1, 3, and 4 for comprehensive anomaly detection
Now with REAL Machine Learning (Isolation Forest & One-Class SVM)
"""

import asyncio
import json
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import requests
from collections import defaultdict, deque
import numpy as np

# Try to import sklearn, handle if not present (though we should have installed it)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ scikit-learn not found. ML models will be disabled.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLManager:
    """Manages Real ML Models (Isolation Forest & One-Class SVM)"""
    
    def __init__(self):
        self.feature_history = deque(maxlen=1000)  # Store last 1000 data points for training
        
        if SKLEARN_AVAILABLE:
            self.scaler = StandardScaler()
            # Initialize Models
            self.iso_forest = IsolationForest(contamination=0.1, random_state=42)
            self.oc_svm = OneClassSVM(nu=0.1, kernel="rbf", gamma=0.1)
        else:
            self.scaler = None
            self.iso_forest = None
            self.oc_svm = None
        
        self.is_fitted = False
        self.last_training_time = datetime.min
        
        # Performance Metrics (Ground Truth = Rule-Based System)
        self.metrics = {
            'isolation_forest': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
            'one_class_svm': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
        }

        self.feature_names = [
            "Network Volume", 
            "Device Count", 
            "Connection Patterns", 
            "Packet Size", 
            "Scan Frequency", 
            "Attack Patterns"
        ]

    def add_data_point(self, features: List[float], rule_based_anomaly: bool):
        """Add a data point and retrain if necessary"""
        self.feature_history.append({
            'features': features,
            'is_anomaly': rule_based_anomaly,
            'timestamp': datetime.now()
        })
        
        # Retrain every 50 new points or if not fitted yet (and we have enough data)
        if len(self.feature_history) >= 20:
            if not self.is_fitted or (datetime.now() - self.last_training_time).seconds > 60:
                self.train_models()

    def train_models(self):
        """Train models on historical data"""
        if not SKLEARN_AVAILABLE or len(self.feature_history) < 20:
            return

        try:
            # Prepare training data
            X = np.array([item['features'] for item in self.feature_history])
            
            # Scale data
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            # Train Isolation Forest
            self.iso_forest.fit(X_scaled)
            
            # Train One-Class SVM
            self.oc_svm.fit(X_scaled)
            
            self.is_fitted = True
            self.last_training_time = datetime.now()
            logger.info(f"🤖 ML Models Retrained on {len(X)} samples")
            
        except Exception as e:
            logger.error(f"❌ Model training failed: {e}")

    def predict(self, features: List[float], rule_based_anomaly: bool) -> Dict[str, Any]:
        """Predict anomaly score for new data"""
        if not self.is_fitted or not SKLEARN_AVAILABLE:
            return {
                'isolation_forest': {'is_anomaly': False, 'score': 0.0, 'reason': 'Model not ready'},
                'one_class_svm': {'is_anomaly': False, 'score': 0.0, 'reason': 'Model not ready'}
            }

        try:
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            
            # Identify most significant feature (highest absolute Z-score)
            # We use the scaled values to determine deviation from mean
            max_deviation_idx = np.argmax(np.abs(X_scaled[0]))
            reason = f"Abnormal {self.feature_names[max_deviation_idx]}"
            
            # Isolation Forest (-1 is anomaly, 1 is normal)
            if_pred = self.iso_forest.predict(X_scaled)[0]
            if_score = self.iso_forest.decision_function(X_scaled)[0] # Average anomaly score of X of the base classifiers.
            # Convert to 0-1 scale (approx)
            if_prob = 0.5 - (if_score * 0.5) 
            
            # One-Class SVM (-1 is anomaly, 1 is normal)
            svm_pred = self.oc_svm.predict(X_scaled)[0]
            svm_score = self.oc_svm.decision_function(X_scaled)[0]
            # Convert to 0-1 scale (approx)
            svm_prob = 0.5 - (svm_score * 0.5)

            # Update Metrics
            self._update_metrics('isolation_forest', if_pred == -1, rule_based_anomaly)
            self._update_metrics('one_class_svm', svm_pred == -1, rule_based_anomaly)

            return {
                'isolation_forest': {
                    'is_anomaly': if_pred == -1,
                    'score': float(if_prob),
                    'reason': reason
                },
                'one_class_svm': {
                    'is_anomaly': svm_pred == -1,
                    'score': float(svm_prob),
                    'reason': reason
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Prediction failed: {e}")
            return {
                'isolation_forest': {'is_anomaly': False, 'score': 0.0, 'reason': 'Error'},
                'one_class_svm': {'is_anomaly': False, 'score': 0.0, 'reason': 'Error'}
            }

    def _update_metrics(self, model_name: str, ml_anomaly: bool, rule_anomaly: bool):
        """Update TP/FP/TN/FN metrics"""
        if ml_anomaly and rule_anomaly:
            self.metrics[model_name]['tp'] += 1
        elif ml_anomaly and not rule_anomaly:
            self.metrics[model_name]['fp'] += 1
        elif not ml_anomaly and not rule_anomaly:
            self.metrics[model_name]['tn'] += 1
        elif not ml_anomaly and rule_anomaly:
            self.metrics[model_name]['fn'] += 1

    def get_performance_stats(self):
        """Calculate Accuracy, Precision, Recall"""
        stats = {}
        for model_name, counts in self.metrics.items():
            tp = counts['tp']
            fp = counts['fp']
            tn = counts['tn']
            fn = counts['fn']
            total = tp + fp + tn + fn
            
            if total == 0:
                stats[model_name] = {'accuracy': 0, 'precision': 0, 'recall': 0}
                continue
                
            accuracy = (tp + tn) / total
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            
            stats[model_name] = {
                'accuracy': round(accuracy, 3),
                'precision': round(precision, 3),
                'recall': round(recall, 3)
            }
        return stats

class EnhancedAnomalyDetector:
    """Enhanced anomaly detector that integrates with all modules"""
    
    def __init__(self):
        self.running = False
        self.anomalies = deque(maxlen=1000)  # Keep last 1000 anomalies
        self.device_profiles = {}
        self.attack_patterns = defaultdict(list)
        self.network_baseline = {}
        self.last_update = datetime.now()
        
        # ML Manager
        self.ml_manager = MLManager()
        self.current_features = [] # Store latest feature vector
        
        # ML thresholds (Rule-based)
        self.thresholds = {
            'network_volume': 1000,  # packets per minute
            'device_count': 50,      # new devices per hour
            'attack_frequency': 5,   # attacks per hour
            'bluetooth_density': 20, # bluetooth devices per scan
            'wifi_density': 30,      # wifi networks per scan
            'packet_size_anomaly': 1500,  # large packet threshold
            'connection_anomaly': 100,    # connections per minute
            'scan_frequency': 10          # scans per minute
        }
        
        # Initialize database
        self.init_database()
        
        logger.info("🔍 Enhanced Module 5 Anomaly Detector initialized")
    
    def init_database(self):
        """Initialize SQLite database for anomaly storage"""
        try:
            import os
            db_path = os.path.join(os.path.dirname(__file__), 'enhanced_module5_anomalies.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create anomalies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_module TEXT NOT NULL,
                    device_id TEXT,
                    details TEXT,
                    score REAL,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Create device profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_profiles (
                    device_id TEXT PRIMARY KEY,
                    device_type TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    anomaly_count INTEGER DEFAULT 0,
                    total_events INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0
                )
            ''')
            
            # Create attack patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    severity TEXT,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Enhanced Module 5 database initialized")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
    
    def start(self):
        """Start the anomaly detection system"""
        if self.running:
            logger.info("🔍 Anomaly detector already running")
            return
        
        self.running = True
        # Start background monitoring
        threading.Thread(target=self._monitoring_loop, daemon=True).start()
        logger.info("🚀 Enhanced Module 5 anomaly detection started")
    
    def stop(self):
        """Stop the anomaly detection system"""
        self.running = False
        logger.info("🛑 Enhanced Module 5 anomaly detection stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs continuously"""
        while self.running:
            try:
                # 1. Collect Features from all modules
                features, rule_based_anomalies = self._collect_features_and_check_rules()
                self.current_features = features
                
                # 2. Determine if Rule-Based System thinks it's an anomaly
                is_rule_anomaly = len(rule_based_anomalies) > 0
                
                # 3. Feed to ML Models
                self.ml_manager.add_data_point(features, is_rule_anomaly)
                ml_predictions = self.ml_manager.predict(features, is_rule_anomaly)
                
                # 4. Process ML Anomalies
                self._process_ml_results(ml_predictions, rule_based_anomalies)
                
                # 5. Update Device Profiles
                self._update_device_profiles()
                
                self.last_update = datetime.now()
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"❌ Error in monitoring loop: {e}")
                time.sleep(10)  # Wait longer on error

    def _collect_features_and_check_rules(self):
        """Collect features and run rule-based checks"""
        features = [0.0] * 6 # [network_vol, device_count, conn_patterns, packet_size, scan_freq, attack_patterns]
        anomalies = []
        
        # --- Module 1: WiFi/Bluetooth ---
        try:
            resp1 = requests.get("http://localhost:8000/api/scan/results", timeout=2)
            if resp1.status_code == 200:
                data1 = resp1.json()
                wifi_count = len(data1.get('wifi_networks', []))
                bt_count = len(data1.get('bluetooth_devices', []))
                
                features[1] = float(wifi_count + bt_count) # Device Count
                features[4] = 1.0 # Scan Frequency (placeholder, assuming 1 scan per cycle)
                
                # Rules
                if wifi_count > self.thresholds['wifi_density']:
                    anomalies.append(self._create_anomaly_obj('wifi_density', 'medium', 'module1', f"High WiFi: {wifi_count}"))
                if bt_count > self.thresholds['bluetooth_density']:
                    anomalies.append(self._create_anomaly_obj('bt_density', 'medium', 'module1', f"High BT: {bt_count}"))
        except: pass

        # --- Module 3: Packet Sniffing ---
        try:
            resp3 = requests.get("http://localhost:8000/api/live-capture/statistics", timeout=2)
            if resp3.status_code == 200:
                data3 = resp3.json()
                total_packets = data3.get('total_packets', 0)
                
                features[0] = float(total_packets) # Network Volume
                features[3] = float(data3.get('avg_packet_size', 500)) # Packet Size (estimate)
                
                # Rules
                if total_packets > self.thresholds['network_volume']:
                    anomalies.append(self._create_anomaly_obj('high_traffic', 'high', 'module3', f"High Traffic: {total_packets}"))
        except: pass
        
        # --- Module 4: Attacks ---
        try:
            resp4 = requests.get("http://localhost:8000/api/module4/real-attacks", timeout=2)
            if resp4.status_code == 200:
                data4 = resp4.json()
                events = data4.get('events', [])
                
                features[5] = float(len(events)) # Attack Patterns
                
                # Rules
                
                # 1. Frequency Check
                if len(events) > self.thresholds['attack_frequency']:
                    anomalies.append(self._create_anomaly_obj('attack_surge', 'critical', 'module4', f"Attack Surge: {len(events)}"))
                
                # 2. Severity Check (Immediate Alert)
                for event in events:
                    severity = event.get('severity', 'low').lower()
                    if severity in ['critical', 'high']:
                        # Check if we already have this specific anomaly to avoid duplicates
                        # We use a simple check based on description for now
                        desc = f"Critical Attack Detected: {event.get('title', 'Unknown Attack')}"
                        is_duplicate = any(a['description'] == desc for a in anomalies)
                        
                        if not is_duplicate:
                            anomalies.append(self._create_anomaly_obj(
                                'critical_attack', 
                                severity, 
                                'module4', 
                                desc,
                                score=10.0 if severity == 'critical' else 8.0
                            ))
        except: pass
        
        # --- System Connections ---
        try:
            import subprocess
            res = subprocess.run(['ss', '-tun'], capture_output=True, text=True)
            conn_count = len(res.stdout.split('\n'))
            features[2] = float(conn_count) # Connection Patterns
            
            if conn_count > self.thresholds['connection_anomaly']:
                anomalies.append(self._create_anomaly_obj('high_connections', 'medium', 'system', f"High Connections: {conn_count}"))
        except: pass
        
        return features, anomalies

    def _create_anomaly_obj(self, type_name, severity, source, desc, score=1.0):
        """Helper to create anomaly dict without saving yet"""
        return {
            'timestamp': datetime.now().isoformat(),
            'anomaly_type': type_name,
            'severity': severity,
            'source_module': source,
            'description': desc,
            'score': score
        }

    def _process_ml_results(self, ml_preds, rule_anomalies):
        """Combine ML and Rule-based results"""
        
        # 1. Save Rule-Based Anomalies
        for anomaly in rule_anomalies:
            self._save_anomaly(anomaly)
            
        # 2. Save ML Anomalies (if not already covered by rules, or to reinforce)
        # We only alert on ML if it's confident and we want to show it explicitly
        
        if ml_preds['isolation_forest']['is_anomaly']:
            reason = ml_preds['isolation_forest'].get('reason', 'Unknown')
            self._save_anomaly({
                'timestamp': datetime.now().isoformat(),
                'anomaly_type': 'ml_isolation_forest',
                'severity': 'high',
                'source_module': 'ml_engine',
                'description': f"Isolation Forest detected anomaly: {reason} (Score: {ml_preds['isolation_forest']['score']:.2f})",
                'score': ml_preds['isolation_forest']['score'] * 10
            })
            
        if ml_preds['one_class_svm']['is_anomaly']:
            reason = ml_preds['one_class_svm'].get('reason', 'Unknown')
            self._save_anomaly({
                'timestamp': datetime.now().isoformat(),
                'anomaly_type': 'ml_one_class_svm',
                'severity': 'medium',
                'source_module': 'ml_engine',
                'description': f"One-Class SVM detected anomaly: {reason} (Score: {ml_preds['one_class_svm']['score']:.2f})",
                'score': ml_preds['one_class_svm']['score'] * 10
            })

    def _save_anomaly(self, anomaly):
        """Save anomaly to DB and memory"""
        # Add to memory
        self.anomalies.append(anomaly)
        
        # Save to database
        try:
            import os
            db_path = os.path.join(os.path.dirname(__file__), 'enhanced_module5_anomalies.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies 
                (timestamp, anomaly_type, severity, source_module, device_id, details, score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                anomaly['timestamp'],
                anomaly['anomaly_type'],
                anomaly['severity'],
                anomaly['source_module'],
                anomaly.get('device_id'),
                json.dumps({'description': anomaly['description']}),
                anomaly['score']
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"🚨 Anomaly Saved: {anomaly['anomaly_type']}")
            
        except Exception as e:
            logger.error(f"Failed to save anomaly: {e}")

    def _update_device_profiles(self):
        """Update device profiles with anomaly counts"""
        try:
            import os
            db_path = os.path.join(os.path.dirname(__file__), 'enhanced_module5_anomalies.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get anomaly counts per device
            cursor.execute('''
                SELECT device_id, COUNT(*) as anomaly_count
                FROM anomalies
                WHERE device_id IS NOT NULL
                AND timestamp > datetime('now', '-1 hour')
                GROUP BY device_id
            ''')
            
            for device_id, count in cursor.fetchall():
                if count > 5:  # Device with many anomalies
                    self._save_anomaly({
                        'timestamp': datetime.now().isoformat(),
                        'anomaly_type': 'device_risk_anomaly',
                        'severity': 'high',
                        'source_module': 'profile',
                        'description': f"High-risk device: {device_id} ({count} anomalies in 1 hour)",
                        'device_id': device_id,
                        'score': min(count / 5, 3.0)
                    })
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Device profile update failed: {e}")
    
    def get_recent_anomalies(self, limit=50):
        """Get recent anomalies"""
        return list(self.anomalies)[-limit:]
    
    def get_anomaly_statistics(self):
        """Get anomaly statistics"""
        if not self.anomalies:
            return {
                'total_anomalies': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'last_update': self.last_update.isoformat()
            }
        
        severity_counts = defaultdict(int)
        for anomaly in self.anomalies:
            severity_counts[anomaly['severity']] += 1
        
        return {
            'total_anomalies': len(self.anomalies),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'last_update': self.last_update.isoformat()
        }

    def get_device_risk_scores(self):
        """Get risk scores for all devices"""
        try:
            import os
            db_path = os.path.join(os.path.dirname(__file__), 'enhanced_module5_anomalies.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT device_id, risk_score FROM device_profiles')
            profiles = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            return profiles
        except Exception as e:
            logger.error(f"Error getting risk scores: {e}")
            return {}
    
    def get_model_statistics(self):
        """Get ML model performance statistics"""
        try:
            perf_stats = self.ml_manager.get_performance_stats()
            
            return {
                'isolation_forest_models': 1,
                'one_class_svm_models': 1,
                'dbscan_models': 0, # Removed as requested (only 2 best models)
                'streaming_models': 0,
                'total_models': 2,
                'active_models': 2,
                'model_performance': {
                    'isolation_forest': perf_stats.get('isolation_forest', {'accuracy': 0, 'precision': 0, 'recall': 0}),
                    'one_class_svm': perf_stats.get('one_class_svm', {'accuracy': 0, 'precision': 0, 'recall': 0}),
                    'dbscan': {'accuracy': 0, 'precision': 0, 'recall': 0},
                    'streaming_ml': {'accuracy': 0, 'precision': 0, 'recall': 0}
                }
            }
        except Exception as e:
            logger.error(f"Error getting model statistics: {e}")
            return {
                'isolation_forest_models': 0,
                'one_class_svm_models': 0,
                'dbscan_models': 0,
                'streaming_models': 0,
                'total_models': 0,
                'active_models': 0,
                'model_performance': {}
            }

# Global instance
enhanced_anomaly_detector = EnhancedAnomalyDetector()

def get_enhanced_anomaly_detector():
    """Get the global enhanced anomaly detector instance"""
    return enhanced_anomaly_detector

if __name__ == "__main__":
    # Test the detector
    detector = get_enhanced_anomaly_detector()
    detector.start()
    
    try:
        while True:
            time.sleep(10)
            stats = detector.get_anomaly_statistics()
            print(f"Anomalies detected: {stats['total_anomalies']}")
            print(f"Model Stats: {detector.get_model_statistics()}")
    except KeyboardInterrupt:
        detector.stop()
        print("Enhanced anomaly detector stopped")
