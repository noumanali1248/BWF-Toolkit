import sys
import os
import time
import logging

# Add backend to path
sys.path.append('/home/kali/Videos/Complete Project.100%/Module 1 - Bluetooth & Wi-Fi Discovery Scanner/backend')

try:
    from enhanced_module5_anomaly_detector import get_enhanced_anomaly_detector, MLManager
    print("✅ Successfully imported enhanced_module5_anomaly_detector")
except ImportError as e:
    print(f"❌ Failed to import: {e}")
    sys.exit(1)

def test_ml_manager():
    print("\nTesting MLManager...")
    ml_manager = MLManager()
    
    # Simulate data
    print("  - Simulating 60 data points...")
    for i in range(60):
        # Normal data
        features = [100.0, 5.0, 10.0, 500.0, 1.0, 0.0] 
        ml_manager.add_data_point(features, False)
        
    if ml_manager.is_fitted:
        print("  ✅ Models fitted successfully")
    else:
        print("  ❌ Models failed to fit")
        
    # Test prediction
    pred = ml_manager.predict([10000.0, 50.0, 100.0, 1500.0, 10.0, 5.0], True)
    print(f"  - Prediction result: {pred}")
    
    if pred['isolation_forest']['score'] != 0.0:
        print("  ✅ Prediction returned valid scores")
    else:
        print("  ⚠️ Prediction returned 0.0 scores (might be expected if models disabled)")

def test_detector_integration():
    print("\nTesting EnhancedAnomalyDetector Integration...")
    detector = get_enhanced_anomaly_detector()
    
    # We won't start the thread, just call the internal method once
    print("  - Running one monitoring cycle...")
    try:
        features, anomalies = detector._collect_features_and_check_rules()
        print(f"  - Collected features: {features}")
        print(f"  - Rule-based anomalies: {len(anomalies)}")
        
        detector.ml_manager.add_data_point(features, len(anomalies) > 0)
        print("  ✅ Cycle completed without error")
    except Exception as e:
        print(f"  ❌ Cycle failed: {e}")

if __name__ == "__main__":
    test_ml_manager()
    test_detector_integration()
