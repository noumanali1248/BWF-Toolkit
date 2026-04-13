# Module 5 - Device Profiling & Anomaly Detection

## Overview
Module 5 is the brain that learns what "normal" devices do and detects when something behaves anomalously. It processes real-time data from Module 1 (WiFi/Bluetooth scans) and Module 3 (packet captures) to build behavioral profiles and detect deviations.

## Key Features
- **Real-time device profiling** - Builds behavioral baselines for each device
- **Anomaly detection** - Rule-based and ML-based detection of unusual behavior
- **Explainable results** - Provides clear explanations for detected anomalies
- **Forensic evidence** - Links anomalies to PCAP files and packet indices
- **No simulated attacks** - Only processes real network data

## Files Structure
```
backend/
├── module5_ingestor.py          # Main anomaly detection engine
├── module5_real_data_processor.py # Processes real data from Module 1 & 3
├── module5_kpi_scripts.py       # KPI analysis and testing scripts
├── module5_test_runner.py       # Comprehensive test suite
├── module5_config.yml           # Configuration file
├── MODULE5_README.md            # This file
├── events_for_module2/          # Event files for processing
├── anomalies/                   # Generated anomaly JSON files
├── module5_profiles.db          # SQLite database for device profiles
└── module5_test_results/        # Test results and reports
```

## Installation & Setup

### 1. Install Dependencies
```bash
pip install scikit-learn numpy pandas
```

### 2. Create Required Directories
```bash
mkdir events_for_module2
mkdir anomalies
mkdir module5_test_results
```

### 3. Initialize Database
The database will be created automatically when you first run the ingestor.

## Usage

### 1. Start Real Data Processing
Process real data from Module 1 and Module 3:
```bash
python module5_real_data_processor.py
```

### 2. Start Anomaly Detection
Start the main anomaly detection engine:
```bash
python module5_ingestor.py
```

### 3. Run Comprehensive Tests
Run the complete test suite:
```bash
python module5_test_runner.py
```

## Terminal Testing Commands

### Real-time Monitoring
```bash
# Monitor events being generated
tail -f events_for_module2/*.json

# Monitor anomalies being detected
tail -f anomalies/*.json

# Monitor with jq for pretty formatting
tail -f anomalies/*.json | jq '.'
```

### KPI Analysis
```bash
# Calculate MTTD (Mean Time To Detect)
python module5_kpi_scripts.py --action mttd

# Calculate detection coverage
python module5_kpi_scripts.py --action coverage

# Calculate anomaly rates
python module5_kpi_scripts.py --action rates --hours 24

# Calculate precision (requires labels.csv)
python module5_kpi_scripts.py --action precision

# Generate device report
python module5_kpi_scripts.py --action device-report

# Run comprehensive analysis
python module5_kpi_scripts.py --action comprehensive
```

### Database Queries
```bash
# Check device profiles
sqlite3 module5_profiles.db "SELECT device_id, first_seen, last_seen, baseline_pps FROM device_profiles LIMIT 10;"

# Check anomaly events
sqlite3 module5_profiles.db "SELECT device_id, rule, severity, timestamp FROM anomaly_events ORDER BY timestamp DESC LIMIT 10;"

# Count total devices
sqlite3 module5_profiles.db "SELECT COUNT(*) FROM device_profiles;"

# Count total anomalies
sqlite3 module5_profiles.db "SELECT COUNT(*) FROM anomaly_events;"
```

### File Analysis
```bash
# Count anomaly files
ls anomalies/*.json | wc -l

# Show latest anomalies
ls -lt anomalies/*.json | head -5

# Analyze anomaly types
jq -r '.rule' anomalies/*.json | sort | uniq -c

# Analyze severity distribution
jq -r '.severity' anomalies/*.json | sort | uniq -c
```

## Real-time Test Scenarios

### 1. Baseline Sanity Check
```bash
# Start the system
python module5_real_data_processor.py &
python module5_ingestor.py &

# Check that device profiles are being created
sqlite3 module5_profiles.db "SELECT device_id, first_seen, last_seen FROM devices LIMIT 20;"
```

### 2. MAC Randomization Detection
```bash
# Have a phone toggle randomized MAC, then check for mac_churn events
tail -f anomalies/*.json | jq '. | select(.rule=="mac_churn")'
```

### 3. Traffic Spike Detection
```bash
# Start a large file transfer, then check for pps_spike events
tail -f anomalies/*.json | jq '. | select(.rule=="pps_spike")'
```

### 4. RSSI Drift Detection
```bash
# Move a device around, then check for rssi_jump events
tail -f anomalies/*.json | jq '. | select(.rule=="rssi_jump")'
```

## Performance Monitoring

### Real-time Statistics
```bash
# Monitor processing statistics
watch -n 5 'python -c "
from module5_ingestor import Module5Ingestor
i = Module5Ingestor()
print(i.get_statistics())
"'
```

### Memory and CPU Usage
```bash
# Monitor Python processes
top -p $(pgrep -f module5)

# Monitor memory usage
ps aux | grep module5
```

## Configuration

### Edit Configuration
```bash
# Edit the configuration file
nano module5_config.yml
```

### Key Configuration Options
- `thresholds`: Detection thresholds for different anomaly types
- `windows`: Time windows for feature calculation
- `ml_models`: ML model parameters
- `whitelist`: Devices to ignore for anomaly detection

## Troubleshooting

### Common Issues

1. **No events being generated**
   ```bash
   # Check if Module 1 and Module 3 are running
   ps aux | grep -E "(main.py|module3)"
   
   # Check event directory
   ls -la events_for_module2/
   ```

2. **No anomalies detected**
   ```bash
   # Check if ingestor is running
   ps aux | grep module5_ingestor
   
   # Check database
   sqlite3 module5_profiles.db ".tables"
   ```

3. **ML models not working**
   ```bash
   # Check scikit-learn installation
   python -c "import sklearn; print(sklearn.__version__)"
   
   # Check if enough training data
   sqlite3 module5_profiles.db "SELECT COUNT(*) FROM feature_history;"
   ```

### Log Analysis
```bash
# Check logs
tail -f module5.log

# Filter for errors
grep ERROR module5.log

# Filter for anomalies
grep "Anomaly detected" module5.log
```

## Integration with Main Dashboard

Module 5 will be integrated into the main dashboard with:
- Real-time anomaly monitoring
- Device profile visualization
- Anomaly drill-down capabilities
- Evidence linking to PCAP files

## Acceptance Criteria

### Terminal-checkable Criteria
1. **Profiles exist for >95% of devices** seen by Module 3
2. **MTTD median < 30 seconds** for anomaly detection
3. **Detection coverage > 98%** against Module 3 data
4. **Precision > 0.7** for labeled anomalies
5. **Each anomaly includes** pcap_file, pcap_sha256, and event_timestamp

### Verification Commands
```bash
# Check profile coverage
python module5_kpi_scripts.py --action coverage

# Check MTTD
python module5_kpi_scripts.py --action mttd

# Check precision
python module5_kpi_scripts.py --action precision

# Verify anomaly format
jq '.evidence' anomalies/*.json | head -5
```

## Support

For issues or questions:
1. Check the logs: `tail -f module5.log`
2. Run diagnostics: `python module5_test_runner.py`
3. Check database: `sqlite3 module5_profiles.db ".schema"`
4. Verify configuration: `cat module5_config.yml`

