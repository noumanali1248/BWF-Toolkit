# Module 4: Real-time Attack Detection & Threat Intelligence

A production-grade real-time threat detection system that ingests ONLY real Module 3 telemetry, evaluates explainable rules, correlates with Module 2 device profiles, and emits immutable alert JSONs with forensic evidence.

**NO SIMULATED ATTACKS - REAL-TIME DETECTION ONLY**

## 🚀 Quick Start

### Prerequisites
```bash
pip install pyyaml watchdog requests
```

### Basic Usage
```bash
# Start Module 4 service (real-time only)
python module4_service.py --watch-dir ./events_for_module2 --rules rules.yml --alerts-dir ./alerts --db capture_metadata.db

# Run real-time analysis
python module4_testrunner.py --live --duration 10
```

## 📋 Terminal Commands & Verification

### A. Start the Service

**PowerShell:**
```powershell
python module4_service.py --watch-dir .\events_for_module2 --rules rules.yml --alerts-dir .\alerts --db capture_metadata.db
```

**Bash:**
```bash
python3 module4_service.py --watch-dir ./events_for_module2 --rules rules.yml --alerts-dir ./alerts --db capture_metadata.db
```

### B. Live Monitoring (Tailing)

**PowerShell:**
```powershell
Get-Content .\events_for_module2\*.json -Wait
Get-Content .\alerts\*.json -Wait
```

**Bash:**
```bash
tail -F events_for_module2/*.json
tail -F alerts/*.json
```

### C. Compute MTTD (Mean Time To Detect)

**Bash Script:**
```bash
python3 - <<'PY'
import glob, json, datetime, statistics
ds=[]
for f in glob.glob('alerts/*.json'):
    a=json.load(open(f))
    alert_ts = datetime.datetime.fromisoformat(a['timestamp'].replace('Z',''))
    ev_ts = datetime.datetime.fromisoformat(a['evidence']['event_timestamp'].replace('Z',''))
    ds.append((alert_ts-ev_ts).total_seconds())
if ds:
    print("MTTD_count",len(ds),"mean",statistics.mean(ds),"median",statistics.median(ds),"max",max(ds))
else:
    print("No alerts found.")
PY
```

**PowerShell Equivalent:**
```powershell
Get-ChildItem alerts\*.json | ForEach-Object {
  $a = Get-Content $_.FullName | ConvertFrom-Json
  ([datetime]$a.timestamp - [datetime]$a.evidence.event_timestamp).TotalSeconds
} | Measure-Object -Average -Minimum -Maximum
```

### D. Detection Coverage Analysis

**Count distinct BSSIDs captured by Module 3:**
```bash
sqlite3 capture_metadata.db "SELECT COUNT(DISTINCT bssid) FROM packet_metadata WHERE bssid != '';"
```

**Compare to system scan snapshot (Windows):**
```powershell
netsh wlan show networks mode=bssid > netsh_scan.txt
(Select-String 'BSSID' netsh_scan.txt).Count
```

**Interpretation:** Coverage = (DB distinct BSSIDs) / (netsh BSSID count). Aim > 0.98 in stable environments.

### E. Alert Throughput & Daily Rates

**Alerts in last 24h (Bash):**
```bash
jq -s 'map(select(.timestamp > "'$(date -d '24 hours ago' --iso-8601=seconds)'")) | length' alerts/*.json
```

**Alerts in last 24h (SQLite):**
```bash
sqlite3 capture_metadata.db "SELECT COUNT(*) FROM packets WHERE flags <> '' AND timestamp > (strftime('%s','now') - 86400);"
```

### F. False Positive / Precision Estimation

**Create labels.csv with format: alert_id,label (1=TP,0=FP)**
```csv
alert-123,1
alert-456,0
alert-789,1
```

**Compute precision:**
```bash
python3 - <<'PY'
import csv, glob, json
labels = {r[0]:int(r[1]) for r in csv.reader(open('labels.csv'))}
tp=fp=0
for f in glob.glob('alerts/*.json'):
    a=json.load(open(f)); aid=a['alert_id']
    if aid in labels:
        if labels[aid]==1: tp+=1
        else: fp+=1
print("labeled:",tp+fp,"precision:", tp/(tp+fp) if tp+fp else "N/A")
PY
```

**Aim:** Initial precision > 0.70, iterate rules.yml to tighten thresholds.

### G. Real-time Verification Only

**Monitor real Module 3 events:**
```bash
# Watch for real events from Module 3
tail -F events_for_module2/*.json
```

**Watch Module 4 alerts:**
```bash
tail -F alerts/*.json
```

This monitors real-time detection from actual network traffic only.

### H. Acceptance Criteria (Terminal-Checkable)

1. **Module 4 writes alert JSONs** to `alerts/` referencing `pcap_file` + `pcap_sha256` and `evidence.event_timestamp`
2. **MTTD (script above) mean < 30s** (configurable)
3. **Detection coverage > 98%** against netsh snapshot in controlled test
4. **Precision (via labels.csv) > 0.7** for demo data
5. **Idempotency:** Reprocessing same Module 3 event should not duplicate alerts

## 🔧 Configuration

### Rules Configuration (rules.yml)
```yaml
deauth_flood:
  type: deauth_flood
  description: "Detects deauthentication flood attacks"
  severity: high
  threshold: 5
  window_seconds: 60
  enabled: true
```

### Alert Dispatcher Configuration
```python
config = {
    'alerts_dir': './alerts',
    'rest_api': {
        'enabled': False,
        'url': 'http://localhost:8080/api/alerts'
    },
    'smtp': {
        'enabled': False,
        'host': 'localhost',
        'port': 587,
        'username': 'alerts@company.com',
        'password': 'password'
    }
}
```

## 📊 Testing & Analysis

### Automated Test Runner
```bash
# Live testing with real telemetry
python module4_testrunner.py --live --duration 10 --output live_report.json

# Offline testing with PCAP
python module4_testrunner.py --offline sample_capture.pcap --output offline_report.json

# Generate comprehensive report
python module4_testrunner.py --live --duration 5 --labels labels.csv
```

### Key Performance Indicators (KPIs)

1. **MTTD (Mean Time To Detection)**
   - Target: < 30 seconds
   - Measurement: Alert timestamp - Event timestamp

2. **Detection Coverage**
   - Target: > 98%
   - Measurement: (DB BSSIDs) / (System Scan BSSIDs)

3. **Precision**
   - Target: > 70%
   - Measurement: True Positives / (True Positives + False Positives)

4. **Alert Throughput**
   - Target: Configurable based on environment
   - Measurement: Alerts per hour/day

## 🚨 Supported Attack Detection Rules

### Wi-Fi Attacks
- **Deauthentication Flood** - DoS attacks via deauth frames
- **Evil Twin** - Multiple APs with same SSID
- **High PPS** - Packet flooding attacks
- **MAC Churn** - MAC randomization abuse
- **Network Scanning** - Aggressive scanning behavior
- **Beacon Flood** - Beacon frame flooding
- **Channel Hopping** - Rapid channel switching
- **Rogue AP** - Unauthorized access points
- **Wi-Fi MITM** - Man-in-the-middle attacks
- **KRACK Attack** - Key reinstallation attacks
- **DragonBlood** - WPA3 attack patterns

### Bluetooth Attacks
- **BT Pairing Flood** - Bluetooth pairing floods
- **BT HCI Flood** - HCI command flooding
- **BlueBorne** - BlueBorne attack patterns
- **BT Sniffing** - Passive Bluetooth sniffing
- **IoT Exploitation** - IoT device attacks

## 🔒 Security & Ethics

### Hard Constraints
- **NO simulated attacks** - Only real-time detection
- **NO artificial data** - Use only real Module 3 captured data
- **Live telemetry only** - Real network traffic analysis
- **Forensic evidence** - All alerts include immutable PCAP references

### Real-time Detection Only
1. **Live network telemetry** from Module 3
2. **Real-time threat detection** from actual traffic
3. **Authentic attack patterns** from real network behavior

## 📁 File Structure

```
backend/
├── module4_service.py          # Main service (CLI)
├── rules.yml                   # Detection rules configuration
├── alert_dispatcher.py         # Alert distribution handler
├── module4_testrunner.py       # Real-time analysis & KPI
├── alerts_cli.py               # Alert management CLI
├── MODULE4_README.md           # This documentation
├── events_for_module2/         # Real Module 3 events only
├── alerts/                     # Alert JSON output directory
└── labels.csv                  # Precision evaluation labels
```

## 🎯 Integration with Other Modules

### Module 3 Integration
- Ingests real-time packet metadata
- References PCAP files with SHA256 hashes
- Maintains event timestamps for MTTD calculation

### Module 2 Integration
- Correlates with device profiles
- Uses risk scores for severity calculation
- Leverages known device database

### Dashboard Integration
- REST API endpoints for alert queries
- Real-time alert streaming
- Historical analysis and reporting

## 🚀 Advanced Features

### Extras (Developer-Friendly)
- `--dry-run` flag to validate rules without writing alerts
- `alerts_cli.py` for colorized latest alerts
- Automated real-time metrics runner with JSON output
- Comprehensive terminal-first UX for real-time analysis

### Alert Management
```bash
# Show latest alerts with color coding
python -c "
import json, glob
from datetime import datetime
alerts = []
for f in sorted(glob.glob('alerts/*.json'))[-10:]:
    with open(f) as file: alerts.append(json.load(file))
for a in alerts:
    color = {'high': '\033[91m', 'medium': '\033[93m', 'low': '\033[92m'}.get(a['severity'], '\033[0m')
    print(f'{color}{a[\"severity\"].upper()}\033[0m {a[\"rule_id\"]} - {a[\"timestamp\"]}')
"
```

## 📈 Performance Monitoring

### Real-time Metrics
```bash
# Monitor alert generation rate
watch -n 1 'ls alerts/*.json | wc -l'

# Monitor service status
tail -f module4_service.log

# Check rule evaluation performance
grep "Rule evaluation" module4_service.log | tail -10
```

### Health Checks
```bash
# Verify service is running
ps aux | grep module4_service

# Check alert directory permissions
ls -la alerts/

# Verify database connectivity
sqlite3 capture_metadata.db "SELECT COUNT(*) FROM packet_metadata;"
```

## 🛠️ Troubleshooting

### Common Issues

1. **Service not detecting events**
   - Check watch directory permissions
   - Verify Module 3 is writing events
   - Check file system events are enabled

2. **High false positive rate**
   - Adjust rule thresholds in rules.yml
   - Review device profiles in Module 2
   - Use labels.csv for precision tuning

3. **Slow MTTD**
   - Optimize rule evaluation logic
   - Reduce window sizes for faster detection
   - Check system resource usage

4. **Database locking errors**
   - Ensure single service instance
   - Check database file permissions
   - Verify SQLite version compatibility

### Debug Mode
```bash
python module4_service.py --log-level DEBUG --watch-dir ./events --rules rules.yml
```

## 📞 Support

For issues and questions:
1. Check the logs: `module4_service.log`
2. Verify configuration: `rules.yml`
3. Test with offline PCAP first
4. Review terminal output for errors

---

**Remember:** This is a production-grade security tool. Always test in controlled environments and follow responsible disclosure practices for any discovered vulnerabilities.
