# SecureFlux – Complete Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [Architecture](#architecture)
4. [Setup & Installation](#setup--installation)
5. [Running the Application](#running-the-application)
6. [Frontend User Guide](#frontend-user-guide)
7. [API Reference](#api-reference)
8. [ML Models](#ml-models)
9. [Configuration](#configuration)
10. [Troubleshooting](#troubleshooting)
11. [File Structure](#file-structure)

---

## Project Overview

**SecureFlux** is an ML-driven network anomaly detection system designed for real-time traffic analysis and offline log evaluation. It combines three Isolation Forest models (Home, Industrial, Live Baseline) to detect behavioral anomalies with **explainability**, **severity-based prioritization**, and **WAF rule recommendations**.

### Core Use Cases
- **Real-time Network Monitoring**: Live packet capture and ML-based anomaly detection
- **Offline Analysis**: Upload CSV logs and perform batch anomaly detection with downloadable WAF rules
- **System Monitoring**: Monitor host processes, CPU/memory, and network activity for suspicious behavior
- **False Positive Management**: Mark alerts as false positives to improve the live baseline model
- **WAF Integration**: Generate administrator-approved security rule recommendations in JSON format

---

## Key Features

### 🔴 Real-Time Network Anomaly Detection
- **Packet Capture**: Captures live network traffic using Scapy
- **Flow Tracking**: Maintains bidirectional network flow statistics
- **ML Prediction**: Three-model ensemble decision:
  - **Home Model**: Pre-trained on home network traffic (21 features)
  - **Industrial Model**: Pre-trained on CSECICIDS2018 dataset (27 features)
  - **Live Model**: Adaptive baseline trained on your network's normal behavior
- **Severity Scoring**: CRITICAL, HIGH, MEDIUM, LOW based on model consensus

### 📊 Explainability
For each anomaly, SecureFlux provides:
- Detection decision (ALERT or ALLOW)
- Anomaly severity and score
- **Top feature deviations** explaining why the flow was flagged
- Model confidence scores from each model

### 📁 Offline CSV Analysis
- Upload network logs in CSV format
- Bulk anomaly detection across all records
- Downloadable analysis results (CSV)
- Downloadable WAF rules (JSON)

### 🧠 Continuous Learning
- **False Positive Handling**: Mark incorrect alerts as false positives
- **Live Baseline Retraining**: Automatically retrains every 500 new normal flows
- Reduces false positives and improves detection accuracy over time

### 🔐 WAF Rule Generation
- Pattern-based rule suggestions (REPEATED_PAIR, SRC_SCAN, BURST, etc.)
- Actions: MONITOR_ONLY, RATE_LIMIT_IP, TEMP_BLOCK_IP, etc.
- Scopes: SOURCE_IP, SRC_DST_PAIR, ENDPOINT
- Requires administrator approval before enforcement

### 🖥️ System Monitoring
- **Process Monitoring**: Detect suspicious processes by risk score
- **Resource Analysis**: Track CPU, memory, and network usage
- **Persistence Tracking**: Identify processes with abnormal persistence
- **Network Mapping**: Link processes to network connections
- **Whitelist Support**: Reduced penalties for trusted system processes

---

## Architecture

### High-Level Flow

```
┌──────────────────────┐
│   Packet Capture     │ (Scapy on Wi-Fi interface)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Flow Tracker       │ (Bidirectional flow aggregation)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Feature Extraction │ (21/27 features per flow)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│   ML Prediction Engine (Three-Model Ensemble) │
│   ├─ Home Model (IF + Scaler)                │
│   ├─ Industrial Model (IF + Scaler)          │
│   └─ Live Baseline Model (Adaptive)          │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│   Decision Logic     │ (CRITICAL/HIGH/MEDIUM/LOW)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Alert Management   │ (OPEN, False Positive, Closed)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   WAF Rule Engine    │ (Pattern → Action)
└──────────────────────┘
```

### Component Breakdown

| Component | File | Purpose |
|-----------|------|---------|
| **Flask App** | `app.py` | Main server, routing, alert persistence |
| **Flow Predictor** | `predict.py` | ML model loading, inference, explainability |
| **Flow Tracker** | `flow_tracker.py` | Bidirectional flow aggregation & feature extraction |
| **Host Monitor** | `host_monitor.py` | System metrics, process analysis, baseline learning |
| **Templates** | `templates/*.html` | Frontend UI (Bootstrap 5) |
| **Models** | `ml/models/` | Pickled IF models, scalers, thresholds |
| **Data** | `data/` | Persistent JSON files (logs, alerts, baselines) |

---

## Setup & Installation

### Prerequisites
- **Windows 10/11**
- **Python 3.11+**
- **Administrator Privileges** (for packet capture)
- **Npcap** installed (for Scapy raw packet capture on Windows)

### Step 1: Clone / Navigate to Project
```powershell
cd C:\Users\rushi\OneDrive\Desktop\ZeroTracex
```

### Step 2: Create Virtual Environment
```powershell
python -m venv venv
```

### Step 3: Activate Virtual Environment
```powershell
venv\Scripts\Activate.ps1
```

> **Note**: If PowerShell blocks script execution, run:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Verify Installation
```powershell
python -c "import scapy; import pandas; import sklearn; print('[✓] All dependencies installed')"
```

---

## Running the Application

### Option 1: Direct Execution
```powershell
python app.py
```
- Runs Flask in debug mode on `http://127.0.0.1:5000`
- Auto-reloads on code changes

### Option 2: Flask CLI
```powershell
flask --app app run --debug
```

### Option 3: Production Mode (Not Recommended for Development)
```powershell
flask --app app run --host 0.0.0.0 --port 5000
```

### Expected Startup Output
```
[i] Live baseline warming up - no model found yet
[i] Packet capture thread started
[*] Host Monitor started.
[i] Loaded N OPEN alerts from disk
 * Running on http://127.0.0.1:5000
```

---

## Frontend User Guide

### 1. **Home Page** (`/`)
- Dashboard overview
- Quick navigation to Live Monitoring, System Monitoring, and Offline Analysis
- High-level statistics

### 2. **Live Monitoring** (`/live`)

#### Realtime Logs Tab
- **Purpose**: Monitor network flows in real-time
- **Columns**:
  - Time: Packet timestamp
  - Source: Source IP
  - Destination: Destination IP
  - Protocol: TCP/UDP/ICMP
  - Decision: ALERT or ALLOW
  - Severity: CRITICAL/HIGH/MEDIUM/LOW

- **Filters**:
  - **Severity**: Filter by severity level
  - **Decision**: Show only ALERT or ALLOW
  - **Source IP**: Filter by source IP substring
  - **Destination IP**: Filter by destination IP substring

- **Controls**:
  - "Apply Filters": Apply filter criteria
  - "Clear": Reset all filters
  - "↑ Back to Latest": Jump to newest logs

- **How It Works**:
  - Logs update every 2-3 seconds from `/captured_data` endpoint
  - Live baseline status shown (WARMING UP, LEARNING, TRAINED)
  - Model metadata badge shows versions of each model

#### Alerts Tab
- **Purpose**: View and manage anomalies
- **Columns**:
  - Time: Alert timestamp
  - Source: Source IP
  - Destination: Destination IP
  - Severity: Alert severity
  - Score: ML anomaly score
  - Actions: Investigate, Mark False Positive, Close

- **Alert Actions**:
  - **Investigate**: Opens modal with:
    - Full flow details
    - ML scores from each model (Home, Industrial, Live)
    - Top feature deviations (explaining why flagged)
    - Detection pattern (SRC_SCAN, BURST, etc.)
    - **WAF Rule Recommendation**: Suggested action and scope
  - **Mark False Positive**: 
    - Removes from OPEN alerts
    - Feeds the flow into the live baseline for retraining
    - Improves future detection accuracy
  - **Close**: Closes the alert (status = CLOSED)

### 3. **System Monitoring** (`/system`)
- **CPU & Memory Usage**: Real-time graphs (60-second rolling window)
- **Network Activity**: Bytes sent/received per second
- **Suspicious Processes**: High-risk processes with risk scores
- **System Alerts**: Anomalous system behavior detected by ML

#### Process Details View
- Process name, PID, CPU%, Memory%
- Parent process and command line
- Risk score (0-10)
- Network connection info (if applicable)
- Persistence tracker (how long the process has been flagged)

### 4. **Offline Analysis** (`/offline`)
- **File Upload**: Select a CSV file with network flow features
- **Template Download**: Download a CSV template with required column headers
- **Analysis Results**: 
  - Total flows analyzed
  - Anomaly count
  - Normal count
- **Downloads**:
  - Analyzed CSV (includes decision, severity, scores for each flow)
  - WAF Rules (JSON with recommended actions for anomalies)

---

## API Reference

### Network Monitoring Endpoints

#### `GET /captured_data`
**Purpose**: Fetch recent network flows with ML predictions
**Response**:
```json
[
  {
    "timestamp": "2026-01-26 14:30:45",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "length": 1024,
    "scores": {
      "home": -0.45,
      "industrial": -0.50,
      "live": -0.48
    },
    "model_votes": {
      "home": "NORMAL",
      "industrial": "NORMAL",
      "live": "NORMAL"
    },
    "final_decision": "ALLOW",
    "severity": "LOW",
    "explainability": {
      "top_deviations": ["Flow Duration High", "Packet Count High"]
    }
  }
]
```

#### `GET /alerts_data`
**Purpose**: Fetch all OPEN alerts
**Response**:
```json
[
  {
    "timestamp": "2026-01-26 14:25:10",
    "src_ip": "203.0.113.50",
    "dst_ip": "192.168.1.1",
    "severity": "HIGH",
    "scores": {
      "home": 0.85,
      "industrial": 0.88,
      "live": 0.82
    },
    "final_decision": "ALERT",
    "status": "OPEN",
    "explainability": {
      "top_deviations": ["Unusual Flow Duration", "Port Scanning Pattern"]
    },
    "rule_recommendation": {
      "action": "RATE_LIMIT_IP",
      "scope": {"type": "SOURCE_IP", "value": "203.0.113.50"},
      "conditions": {"threshold": "50 req/sec", "duration_seconds": 600}
    }
  }
]
```

#### `POST /mark_false_positive`
**Purpose**: Mark an alert as false positive and retrain live baseline
**Request**:
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "timestamp": "2026-01-26 14:30:45"
}
```
**Response**:
```json
{
  "status": "success",
  "removed": true
}
```

### System Monitoring Endpoints

#### `GET /system_data`
**Purpose**: Fetch latest system metrics (CPU, memory, network, processes)
**Response**:
```json
{
  "timestamp": "14:30:45",
  "cpu_percent": 25.5,
  "memory_percent": 42.3,
  "net_sent_rate": 102400,
  "net_recv_rate": 204800,
  "suspicious_processes": [
    {
      "pid": 1234,
      "name": "unknown.exe",
      "cpu_percent": 85.0,
      "memory_percent": 50.0,
      "risk_score": 7,
      "parent_name": "explorer.exe"
    }
  ],
  "anomaly_status": {
    "anomaly": false,
    "severity": "LOW",
    "score": -0.15,
    "reason": "Normal system activity"
  }
}
```

#### `GET /system_logs`
**Purpose**: Fetch recent host_logs.json entries
**Response**: Array of JSON-serialized log lines (last 100)

#### `GET /system_suspicious`
**Purpose**: Fetch recent suspicious processes with risk score >= 3
**Response**: Array of suspicious process objects, sorted by risk score descending

#### `GET /system_alerts`
**Purpose**: Fetch persisted system alerts
**Response**: Array of system alert objects (newest first)

### Offline Analysis Endpoints

#### `GET /download_csv_template`
**Purpose**: Download CSV template with required columns
**Response**: CSV file with feature headers

#### `POST /analyze_csv` (multipart/form-data)
**Purpose**: Upload and analyze a CSV file
**Request**: Form with file upload
**Response**:
```json
{
  "status": "success",
  "cache_key": "1706272000123",
  "total_flows": 5000,
  "anomaly_count": 45,
  "normal_count": 4955,
  "filename": "network_flows.csv"
}
```

#### `GET /download_analyzed_csv/<cache_key>`
**Purpose**: Download analysis results as CSV
**Response**: CSV file with decision, severity, scores for each flow

#### `GET /download_waf_rules/<cache_key>`
**Purpose**: Download WAF rules as JSON
**Response**: JSON file with recommended security rules

---

## ML Models

### Model Architecture

All three models use **Isolation Forest** with the following hyperparameters:
```
contamination=0.01  (1% of data expected to be anomalous)
random_state=42
n_estimators=100
max_samples='auto'
```

### Models Overview

| Model | Purpose | Training Data | Features | Status |
|-------|---------|---------------|----------|--------|
| **Home** | Detect anomalies in home/small networks | home_flow_features.csv | 21 | Pre-trained ✓ |
| **Industrial** | Detect anomalies in industrial networks | CSECICIDS2018 dataset | 27 | Pre-trained ✓ |
| **Live Baseline** | Adaptive real-time baseline learning | Runtime collected flows | Dynamic | Adaptive |

### Feature Set (Home Model - 21 Features)
```
Flow Duration, Total Fwd Packets, Total Bwd Packets,
Total Length Fwd Packet, Total Length Bwd Packet,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,
Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s,
Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std
```

### Feature Set (Industrial Model - 27 Features)
Includes all Home features plus:
```
Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std,
Flags (PSH, RST, SYN, FIN), Initial Window Size (Fwd & Bwd)
```

### Severity Decision Logic

```
CRITICAL:  All 3 models detect anomaly OR anomaly_score < threshold × 2.0
HIGH:      2+ models detect anomaly
MEDIUM:    1 model detects anomaly
LOW:       Borderline scores / potential concern
```

### Live Baseline Training

- **Buffer Size**: 500 normal flows
- **Retraining Frequency**: Every 500 verified normal flows
- **Verification**: Flows marked as NORMAL by at least 2 models
- **Learning Rate**: Continuous incremental updates to scaler and IF model
- **Status Phases**:
  - WARMING UP: Collecting initial data
  - LEARNING: Training in progress
  - TRAINED: Model ready for prediction

---

## Configuration

### Network Interface

Edit [app.py](app.py#L21):
```python
INTERFACE = "Wi-Fi"  # Change to your active network adapter
```

**To find your interface name**, run:
```powershell
python -c "import scapy.all as s; print(s.get_if_list())"
```

### Model Paths

Default paths (edit in [predict.py](predict.py)):
```python
HOME_MODEL_PATH = "ml/models/home/"
INDUSTRIAL_MODEL_PATH = "ml/models/industrial/"
LIVE_MODEL_PATH = "ml/models/live/"
```

### Alert Storage Limits

Edit [app.py](app.py#L27-L28):
```python
MAX_ALERTS = 1000  # Maximum alerts to keep in memory
ALERT_WINDOW_SECONDS = 120  # Time window for alert correlation
```

### Host Monitor

Edit [host_monitor.py](host_monitor.py#L4-L5):
```python
log_file = "data/host_logs.json"  # Where to save system logs
history_size = 60  # Rolling window for graphs (seconds)
```

---

## Troubleshooting

### Issue: No logs appear on /live page

**Causes & Solutions**:

1. **Packet capture thread not running**
   - Verify: Check Flask startup logs for `[i] Packet capture thread started`
   - Solution: Restart the Flask app with `python app.py`

2. **Wrong network interface**
   - Verify: Run `python -c "import scapy.all as s; print(s.get_if_list())"`
   - Solution: Update `INTERFACE` in [app.py](app.py#L21) to exact adapter name

3. **Missing admin privileges**
   - Verify: Run PowerShell as Administrator
   - Solution: Right-click PowerShell → "Run as administrator"

4. **Npcap not installed**
   - Verify: Scapy error in Flask logs mentioning "Npcap"
   - Solution: Download and install Npcap from https://nmap.org/npcap/

5. **No network traffic**
   - Verify: Generate traffic (open browser, ping, etc.)
   - Solution: Browse a website or run `ping 8.8.8.8` on the monitored interface

### Issue: Model version warnings at startup

```
InconsistentVersionWarning: Trying to unpickle estimator ... from version 1.3.2 when using version 1.6.1
```

**Cause**: Models trained with scikit-learn 1.3.2, running with 1.6.1

**Solution** (optional):
- Retrain models to update them to 1.6.1, or
- Downgrade scikit-learn to 1.3.2 (not recommended), or
- Ignore warnings (models still work correctly)

### Issue: Alert modal doesn't display details

**Cause**: JavaScript fetch error or missing data

**Solution**:
1. Check browser console (F12 → Console tab)
2. Verify `/alerts_data` endpoint returns valid JSON
3. Check that alerts have `explainability` and `rule_recommendation` fields

### Issue: Offline analysis returns "missing columns"

**Cause**: Uploaded CSV missing required feature columns

**Solution**:
1. Download CSV template from Offline page
2. Ensure your CSV has exactly the required columns
3. Fill missing values with 0 or the feature's mean

### Issue: Live baseline stuck in "WARMING UP"

**Cause**: Not enough verified normal flows collected (need 500)

**Solution**:
- Let the system run for 5-10 minutes to collect baseline flows
- Ensure network activity is happening on monitored interface
- Check that flows are being classified as NORMAL by at least 2 models

---

## File Structure

```
SecureFlux/
│
├── app.py                               # Main Flask application
├── predict.py                           # ML prediction engine
├── flow_tracker.py                      # Network flow aggregation
├── host_monitor.py                      # System monitoring & process analysis
├── requirements.txt                     # Python dependencies
├── Readme                               # Quick start guide
├── DOCUMENTATION.md                     # This file
│
├── data/                                # Persistent JSON storage
│   ├── logs_store.json                  # Network flow logs
│   ├── alerts_store.json                # Persisted alerts
│   ├── host_logs.json                   # System metrics logs
│   ├── system_alerts.json               # System anomaly alerts
│   ├── whitelist.json                   # IP whitelist (optional)
│   └── process_baselines.json           # Process baseline statistics
│
├── ml/
│   └── models/
│       ├── home/                        # Home network model
│       │   ├── home_iforest.pkl         # Isolation Forest model
│       │   ├── home_scaler.pkl          # StandardScaler
│       │   ├── home_threshold.json      # Anomaly threshold
│       │   ├── home_feature_order.txt   # Feature names (21)
│       │   └── home_X_scaled.npy        # Scaled training data
│       │
│       ├── industrial/                  # Industrial network model
│       │   ├── isolation_forest.pkl     # Isolation Forest model
│       │   ├── scaler.pkl               # StandardScaler
│       │   ├── threshold.json           # Anomaly threshold
│       │   ├── feature_order.txt        # Feature names (27)
│       │   └── X_scaled.npy             # Scaled training data
│       │
│       └── live/                        # Live baseline model (adaptive)
│           ├── live_iforest.pkl         # Trained model
│           ├── live_scaler.pkl          # Preprocessor
│           ├── live_metadata.json       # Training statistics
│           └── live_baseline_buffer.csv # Training buffer
│
├── templates/                           # HTML frontend
│   ├── index.html                       # Home page
│   ├── online.html                      # Live monitoring page
│   ├── offline.html                     # Offline analysis page
│   └── system.html                      # System monitoring page
│
├── training/                            # Model training scripts
│   ├── home_network/
│   │   ├── step1.py                     # Data cleaning
│   │   ├── step2.py                     # Feature scaling
│   │   ├── step3.py                     # Model training
│   │   └── step4.py                     # Threshold calculation
│   │
│   └── industrial_network/
│       ├── Step_1_Extract.py            # Data extraction
│       ├── Step_2_preprocess.py         # Preprocessing
│       ├── Step_3_train_iforest.py      # Model training
│       └── Step_4_threshold.py          # Threshold calculation
│
├── venv/                                # Python virtual environment
└── __pycache__/                         # Python cache
```

---

## Advanced Topics

### Retraining Models

To retrain the Live Baseline model:
1. Ensure sufficient normal flows are collected (~500+)
2. The system auto-retrains every 500 verified normal flows
3. To manually retrain, run training scripts in `training/` folder

### Adding Custom IP Whitelist

Edit `data/whitelist.json`:
```json
{
  "trusted_ips": [
    "192.168.1.1",
    "10.0.0.1"
  ]
}
```

### WAF Integration

Generated WAF rules are in JSON format:
```json
{
  "rule_id": "secureflux-1706272000",
  "action": "RATE_LIMIT_IP",
  "scope": {"type": "SOURCE_IP", "value": "203.0.113.50"},
  "conditions": {"threshold": "50 req/sec", "duration_seconds": 600},
  "requires_admin_approval": true
}
```

### Performance Optimization

- **Reduce Max Alerts**: Lower `MAX_ALERTS` to reduce memory
- **Disable System Monitoring**: Comment out `host_monitor.start()` if not needed
- **Increase Log Trim**: Adjust `MAX_UI_LOGS` in templates to reduce UI lag

---

## Support & Troubleshooting

For issues:
1. Check Flask startup logs for errors
2. Review browser console (F12) for JavaScript errors
3. Check `data/logs_store.json` and `data/alerts_store.json` for data
4. Verify network interface name matches `INTERFACE` in app.py
5. Ensure admin privileges for packet capture
6. Check that all dependencies installed correctly: `pip show scapy pandas scikit-learn`

---
