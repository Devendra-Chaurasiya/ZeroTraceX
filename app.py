from flask import Flask, render_template, jsonify, request, send_file
import threading
import scapy.all as scapy
import time
import csv
import os
import json
import io
from datetime import datetime
from collections import defaultdict
import pandas as pd
import numpy as np

from predict import FlowPredictor
from flow_tracker import FlowTracker

from host_monitor import HostMonitor

app = Flask(__name__)

# Initialize Host Monitor
host_monitor = HostMonitor()

INTERFACE = "Wi-Fi"

LOGS_STORE_FILE = os.path.join("data", "logs_store.json")
ALERTS_STORE_FILE = os.path.join("data", "alerts_store.json")
MAX_ALERTS = 1000

captured_data = []
alerts_data = []
blocked_ips = {}

capture_running = False
lock = threading.Lock()
capture_thread_started = False

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

predictor = FlowPredictor()
flow_tracker = FlowTracker()

# =========================
# 🔥 ALERT CORRELATION (WAF)
# =========================
ALERT_WINDOW_SECONDS = 120
recent_alerts = defaultdict(list)


# =========================
# FRONTEND ROUTES (FIXED)
# =========================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/live")
def live_monitoring():
    return render_template("online.html")


@app.route("/system")
def system_monitoring():
    return render_template("system.html")


@app.route("/system_data")
def system_data_api():
    metrics = host_monitor.get_latest_metrics()
    
    safe_procs = _get_safe_processes()
                
    # Filter suspicious processes
    if "suspicious_processes" in metrics:
        metrics["suspicious_processes"] = [
            p for p in metrics["suspicious_processes"] 
            if p.get("name", "").lower() not in safe_procs
        ]

    # Run ML Prediction on latest snapshot + window features (PSCS02)
    # The 'metrics' dict now contains 'window_features'
    
    ml_result = predictor.predict_system_anomaly(metrics)
    metrics["anomaly_status"] = ml_result
    
    # 🔴 PERSIST SYSTEM ALERT IF ANOMALY OR HIGH RISK PROCESS
    # Check 1: ML Model Anomaly
    is_anomaly = ml_result.get("anomaly")
    
    # Check 2: Explicit High Risk Process (Risk Score >= 5)
    high_risk_procs = [p for p in metrics.get("suspicious_processes", []) if p.get("risk_score", 0) >= 5]
    if high_risk_procs:
        is_anomaly = True
        ml_result["reason"] = f"Critical Process Detected: {high_risk_procs[0]['name']} (Score: {high_risk_procs[0]['risk_score']})"
        ml_result["severity"] = "CRITICAL"

    if is_anomaly:
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "SYSTEM_VIOLATION", # PSCS02 Terminology
            "score": ml_result.get("score"),
            "severity": ml_result.get("severity"),
            "details": ml_result.get("reason", "Abnormal system behavior detected"),
            "indicators": ml_result.get("indicators", [])
        }
        _append_system_alert(alert_entry)

    return jsonify(metrics)


@app.route("/system_logs")
def system_logs_api():
    """Return recent lines from host_logs.json for the scrolling log UI."""
    log_file = host_monitor.log_file
    if not os.path.exists(log_file):
        return jsonify([])
    
    try:
        # Read last 100 lines efficiently
        with open(log_file, "r") as f:
            lines = f.readlines()[-100:] 
        return jsonify([json.loads(line) for line in lines])
    except Exception as e:
        print(f"[!] Error reading host logs: {e}")
        return jsonify([])


@app.route("/system_suspicious")
def system_suspicious_api():
    """Return recent suspicious processes from persisted host logs (not live memory)."""
    log_file = host_monitor.log_file
    if not os.path.exists(log_file):
        return jsonify([])

    try:
        # Tail read to avoid loading huge files
        with open(log_file, "r") as f:
            lines = f.readlines()[-500:]

        # Keep the most recent snapshot per PID that exceeds risk threshold
        latest_by_pid = {}
        for raw in reversed(lines):
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            for proc in entry.get("suspicious_processes", []):
                pid = proc.get("pid")
                risk = proc.get("risk_score", 0)
                if risk < 3:
                    continue
                if pid not in latest_by_pid:
                    proc_copy = dict(proc)
                    proc_copy["timestamp"] = entry.get("timestamp")
                    latest_by_pid[pid] = proc_copy
            # stop once we have a reasonable set
            if len(latest_by_pid) >= 50:
                break

        # Filter whitelisted
        safe_procs = _get_safe_processes()
        procs = [p for p in latest_by_pid.values() if p.get("name", "").lower() not in safe_procs]

        # Sort by risk desc, newest first (using timestamp if present)
        procs.sort(key=lambda x: (x.get("risk_score", 0), x.get("timestamp", "")), reverse=True)
        return jsonify(procs)
    except Exception as e:
        print(f"[!] Error reading suspicious processes: {e}")
        return jsonify([])


@app.route("/system_alerts")
def system_alerts_api():
    """Return persisted system warnings/alerts."""
    alerts_file = os.path.join("data", "system_alerts.json")
    if not os.path.exists(alerts_file):
        return jsonify([])
    
    try:
        with open(alerts_file, "r") as f:
            lines = f.readlines()
        # Parse and sort by timestamp desc (newest first)
        alerts = [json.loads(line) for line in lines]
        return jsonify(alerts[::-1]) 
    except Exception as e:
        return jsonify([])


@app.route("/add_whitelist", methods=["POST"])
def add_whitelist_api():
    """Add a process to the whitelist."""
    try:
        data = request.json
        process_name = data.get("process")
        
        if not process_name:
            return jsonify({"status": "error", "message": "No process name provided"}), 400

        whitelist_file = os.path.join("data", "whitelist.json")
        whitelist = {"processes": [], "ips": []}
        
        # Load existing
        if os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, 'r') as f:
                    whitelist = json.load(f)
            except:
                pass

        # Add unique
        if process_name not in whitelist["processes"]:
            whitelist["processes"].append(process_name)
            
            with open(whitelist_file, 'w') as f:
                json.dump(whitelist, f, indent=4)
                
            return jsonify({"status": "success", "message": f"Added {process_name} to whitelist"})
        else:
            return jsonify({"status": "info", "message": f"{process_name} already in whitelist"})

    except Exception as e:
        print(f"[!] Whitelist error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/get_whitelist")
def get_whitelist_api():
    """Return current whitelist."""
    whitelist_file = os.path.join("data", "whitelist.json")
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r') as f:
                return jsonify(json.load(f))
        except:
            pass
    return jsonify({"processes": [], "ips": []})


@app.route("/remove_whitelist", methods=["POST"])
def remove_whitelist_api():
    """Remove a process from the whitelist."""
    try:
        data = request.json
        process_name = data.get("process")
        
        if not process_name:
            return jsonify({"status": "error", "message": "No process name provided"}), 400

        whitelist_file = os.path.join("data", "whitelist.json")
        whitelist = {"processes": [], "ips": []}
        
        # Load existing
        if os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, 'r') as f:
                    whitelist = json.load(f)
            except:
                pass

        # Remove
        if process_name in whitelist["processes"]:
            whitelist["processes"].remove(process_name)
            
            with open(whitelist_file, 'w') as f:
                json.dump(whitelist, f, indent=4)
                
            return jsonify({"status": "success", "message": f"Removed {process_name} from whitelist"})
        else:
            return jsonify({"status": "error", "message": f"{process_name} not found in whitelist"}), 404

    except Exception as e:
        print(f"[!] Whitelist removal error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def _append_system_alert(alert):
    """Helper to append system alerts to disk."""
    alerts_file = os.path.join("data", "system_alerts.json")
    try:
        with open(alerts_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"[!] Failed to write system alert: {e}")


@app.route("/offline")
def offline_analysis():
    return render_template("offline.html")


# =========================
# HELPERS
# =========================

def _get_safe_processes():
    """Helper to load whitelisted processes."""
    whitelist_file = os.path.join("data", "whitelist.json")
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
                return set(p.lower() for p in whitelist.get("processes", []))
        except Exception as e:
            print(f"[!] Error loading whitelist: {e}")
    return set()
def get_protocol_name(proto):
    return PROTOCOLS.get(proto, f"OTHER({proto})")


def append_log_to_disk(log):
    try:
        clean = {k: v for k, v in log.items() if not k.startswith("_")}
        with open(LOGS_STORE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(clean) + "\n")
    except Exception as e:
        print("[!] Log disk error:", e)


def append_alert_to_disk(alert):
    try:
        clean = {k: v for k, v in alert.items() if not k.startswith("_")}
        # Convert any numpy / custom objects to native python types
        clean = json_safe(clean)
        print(f"[i] Appending alert to {os.path.abspath(ALERTS_STORE_FILE)}: {clean.get('src_ip')} -> {clean.get('dst_ip')} (severity={clean.get('severity')})")
        with open(ALERTS_STORE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(clean, ensure_ascii=False) + "\n")
    except Exception as e:
        import traceback
        print("[!] Alert disk error:", e)
        traceback.print_exc()


def load_alerts_from_disk():
    global alerts_data
    if not os.path.exists(ALERTS_STORE_FILE):
        print(f"[i] No alerts file found at {os.path.abspath(ALERTS_STORE_FILE)}")
        alerts_data = []
        return
    try:
        with open(ALERTS_STORE_FILE, "r", encoding="utf-8") as f:
            all_alerts = [json.loads(l) for l in f if l.strip()]
        
        # Keep only OPEN alerts and ensure they have status field
        alerts_data = []
        for a in all_alerts[-MAX_ALERTS:]:
            if not a.get('status'):
                a['status'] = 'OPEN'  # Default to OPEN if not set
            if a.get('status') == 'OPEN':
                alerts_data.append(a)
        
        print(f"[i] Loaded {len(alerts_data)} OPEN alerts from disk ({os.path.abspath(ALERTS_STORE_FILE)}) out of {len(all_alerts)} total")
    except Exception as e:
        print(f"[!] Error loading alerts from disk: {e}")
        alerts_data = []


def persist_alerts_to_disk():
    """Atomically write current alerts_data to disk as newline-delimited JSON."""
    try:
        tmp = ALERTS_STORE_FILE + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            for a in alerts_data:
                clean = {k: v for k, v in a.items() if not k.startswith("_")}
                clean = json_safe(clean)
                f.write(json.dumps(clean, ensure_ascii=False) + "\n")
        os.replace(tmp, ALERTS_STORE_FILE)
        print(f"[i] Persisted {len(alerts_data)} alerts to {os.path.abspath(ALERTS_STORE_FILE)}")
    except Exception as e:
        import traceback
        print("[!] Failed to persist alerts to disk:", e)
        traceback.print_exc()


def json_safe(obj):
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_safe(v) for v in obj]
    if hasattr(obj, "item"):
        return obj.item()
    return obj


# =========================
# PACKET CAPTURE
# =========================
def packet_callback(packet):
    if not capture_running or not packet.haslayer(scapy.IP):
        return

    ip = packet[scapy.IP]
    src_ip, dst_ip = ip.src, ip.dst
    proto = get_protocol_name(ip.proto)

    if packet.haslayer(scapy.ARP):
        return

    src_port = dst_port = None
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
    else:
        return

    completed = False
    if packet.haslayer(scapy.TCP):
        flags = int(packet[scapy.TCP].flags)
        completed = bool(flags & 0x01 or flags & 0x04)

    flow_info = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": len(packet),
    }

    flows = flow_tracker.update_flow(flow_info, completed)
    if not flows:
        return

    with lock:
        for f in flows:
            features = f.get("features")
            total_len = int(
                features.get("Total Length of Fwd Packet", 0)
                + features.get("Total Length of Bwd Packet", 0)
            )

            # 🚀 PERFORMANCE OPTIMIZATION: Pre-compute ML predictions once during capture
            result = predictor.predict_all(
                features,
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
            )
            status = predictor.get_live_baseline_status()

            log = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "protocol": f["protocol"],
                "src_port": f["src_port"],
                "dst_port": f["dst_port"],
                "length": total_len,
                "_features": features,
                # 🔥 Store pre-computed results to avoid re-computing on every page load
                "_prediction": result,
                "_live_baseline_status": status,
            }

            append_log_to_disk(log)
            captured_data.insert(0, log)
            # Reduced from 1000 to 200 for faster page loads
            if len(captured_data) > 200:
                captured_data[:] = captured_data[:200]
            
            # 🔴 ALERT PROCESSING: Handle alerts during capture, not on page load
            if result.get("final_decision") == "ALERT":
                alert = {**log, **result}
                alert["features"] = features
                alert["status"] = "OPEN"

                # Check for duplicates
                exists = any(
                    a["src_ip"] == alert["src_ip"]
                    and a["dst_ip"] == alert["dst_ip"]
                    and a["status"] == "OPEN"
                    for a in alerts_data
                )

                if not exists:
                    # Generate WAF rule recommendation
                    try:
                        pattern = detect_pattern(alert)
                        action = "MONITOR_ONLY"
                        scope = {"type": "SOURCE_IP", "value": alert.get("src_ip")}
                        conditions = {"duration_seconds": 180}

                        if pattern == "REPEATED_PAIR":
                            action = "RATE_LIMIT_PAIR"
                            scope = {"type": "SRC_DST_PAIR", "src_ip": alert.get("src_ip"), "dst_ip": alert.get("dst_ip")}
                            conditions = {"threshold": "10 req/sec", "duration_seconds": 300}
                        elif pattern == "SRC_SCAN":
                            action = "TEMP_BLOCK_IP"
                            conditions = {"duration_seconds": 600}
                        elif pattern == "BURST":
                            action = "RATE_LIMIT_IP"
                            conditions = {"threshold": "50 req/sec", "duration_seconds": 600}
                        elif pattern == "API_ABUSE":
                            action = "RATE_LIMIT_ENDPOINT"
                            scope = {"type": "ENDPOINT", "value": alert.get("endpoint", "unknown")}
                            conditions = {"threshold": "5 req/sec", "duration_seconds": 300}
                        elif pattern == "Anomalous Behavior":
                            action = "TEMP_BLOCK_PAIR"
                            scope = {"type": "SRC_DST_PAIR", "src_ip": alert.get("src_ip"), "dst_ip": alert.get("dst_ip")}
                            conditions = {"threshold": "", "duration_seconds": 1800}

                        alert["rule_recommendation"] = {
                            "action": action,
                            "scope": scope,
                            "conditions": conditions,
                            "pattern": pattern,
                            "severity": alert.get("severity"),
                            "reason": "Behavioural anomaly detected by ZeroTrace-X ML engine"
                        }
                    except Exception as e:
                        print(f"[!] Failed to generate WAF rule: {e}")

                    append_alert_to_disk(alert)
                    alerts_data.insert(0, alert)
                    alerts_data[:] = alerts_data[:MAX_ALERTS]
                    print(f"[!] ALERT: {alert['src_ip']} -> {alert['dst_ip']} ({alert.get('severity')})")


def capture_packets():
    scapy.sniff(iface=INTERFACE, prn=packet_callback, store=0)


def ensure_background_services():
    """Start packet capture and host monitor when the server boots (works with flask run)."""
    global capture_running, capture_thread_started

    if not capture_thread_started:
        capture_running = True
        threading.Thread(target=capture_packets, daemon=True).start()
        capture_thread_started = True
        print("[i] Packet capture thread started")

    if not host_monitor.running:
        host_monitor.start()


# =========================
# LIVE DATA API
# =========================
@app.route("/captured_data")
def captured_data_api():
    with lock:
        rows = list(captured_data[:100])  # 🚀 PERFORMANCE: Limit to 100 rows for display

    resp = []
    for row in rows:
        item = dict(row)
        features = item.pop("_features", None)
        
        # 🚀 PERFORMANCE: Use pre-computed prediction from capture time
        result = item.pop("_prediction", {})
        status = item.pop("_live_baseline_status", {})
        
        # Fallback: If old data doesn't have pre-computed results, compute now
        if not result:
            result = predictor.predict_all(
                features,
                src_ip=item["src_ip"],
                dst_ip=item["dst_ip"],
            )
            status = predictor.get_live_baseline_status()

        item.update(result)
        item["live_baseline_status"] = status

        # � PERFORMANCE: Alert processing moved to capture time - skip here
        resp.append(item)

    return jsonify(resp)


@app.route("/alerts_data")
def alerts_api():
    with lock:
        # If the in-memory list is empty (e.g., after a reload), hydrate from disk
        if not alerts_data and os.path.exists(ALERTS_STORE_FILE):
            try:
                load_alerts_from_disk()
            except Exception as e:
                print("[!] Failed to hydrate alerts from disk:", e)

        open_alerts = [a for a in alerts_data if a.get('status') == 'OPEN']
        return jsonify([json_safe(a) for a in open_alerts])


@app.route("/alerts_raw")
def alerts_raw():
    """Debug endpoint: return the entire persisted alerts file as a JSON array."""
    try:
        if not os.path.exists(ALERTS_STORE_FILE):
            return jsonify([])
        with open(ALERTS_STORE_FILE, 'r', encoding='utf-8') as f:
            lines = [l for l in f if l.strip()]
            arr = [json.loads(l) for l in lines]
        return jsonify(arr)
    except Exception as e:
        import traceback
        print("[!] Failed to read alerts_store.json:", e)
        traceback.print_exc()
        return jsonify({"error": "failed to read alerts_store.json"}), 500


# =========================
# OFFLINE CSV ANALYSIS
# =========================
@app.route("/download_csv_template")
def download_csv_template():
    """Generate a CSV template with required column headers from feature_order."""
    try:
        feature_order = predictor.models.get("home", {}).get("feature_order", [])
        if not feature_order:
            return jsonify({"error": "feature order not available"}), 500
        
        # Create CSV with just the header row
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(feature_order)
        buffer.seek(0)
        
        return send_file(
            io.BytesIO(buffer.getvalue().encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name="zerotrace_x_offline_template.csv"
        )
    except Exception as e:
        print(f"[!] Error generating CSV template: {e}")
        return jsonify({"error": f"failed to generate template: {str(e)}"}), 500


# Store offline analysis results temporarily
offline_analysis_cache = {}

@app.route("/analyze_csv", methods=["POST"])
def analyze_csv():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "no file uploaded"}), 400

    try:
        df = pd.read_csv(file)
    except Exception as e:
        return jsonify({"error": f"failed to read CSV: {e}"}), 400

    feature_order = predictor.models.get("home", {}).get("feature_order", [])
    missing = [c for c in feature_order if c not in df.columns]
    if missing:
        return jsonify({"error": f"missing required columns: {', '.join(missing)}"}), 400

    # Offline guardrails: enforce numeric inputs and scrub NaN/inf to prevent model errors
    df = df[feature_order].copy()
    df = df.apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    nan_count = int(df.isna().sum().sum())
    if nan_count > 0:
        print(f"[i] Offline analysis: filled {nan_count} NaN/inf values with 0.0")
        df = df.fillna(0.0)

    output_rows = []
    waf_rules = []
    anomaly_count = 0
    
    for idx, row in df.iterrows():
        feature_dict = {col: float(row[col]) for col in feature_order}
        result = predictor.predict_all_readonly(feature_dict)
        
        decision = result.get("final_decision")
        severity = result.get("severity")
        
        # Count anomalies
        if decision == "ALERT":
            anomaly_count += 1

        # Offline rule recommendation (no IP context available)
        action = "MONITOR_ONLY"
        duration = 180
        if severity == "CRITICAL":
            action = "TEMP_BLOCK_PAIR"
            duration = 1800
        elif severity == "HIGH":
            action = "RATE_LIMIT_IP"
            duration = 600
        elif severity == "MEDIUM":
            duration = 180
        
        rule = {
            "flow_index": idx + 1,
            "action": action,
            "scope": {"type": "OFFLINE_SAMPLE"},
            "conditions": {"duration_seconds": duration},
            "pattern": "OFFLINE_ALERT",
            "severity": severity,
            "decision": decision,
            "reason": "Offline analysis anomaly detected by ZeroTrace-X ML engine",
            "model_scores": {
                "home": result.get("scores", {}).get("home"),
                "industrial": result.get("scores", {}).get("industrial"),
                "live": result.get("scores", {}).get("live")
            },
            "model_votes": result.get("model_votes", {})
        }
        
        # Only add to WAF rules if it's an anomaly
        if decision == "ALERT":
            waf_rules.append(rule)

        output_rows.append({
            **feature_dict,
            "final_decision": decision,
            "severity": severity,
            "score_home": result.get("scores", {}).get("home"),
            "score_industrial": result.get("scores", {}).get("industrial"),
            "score_live": result.get("scores", {}).get("live"),
            "vote_home": result.get("model_votes", {}).get("home"),
            "vote_industrial": result.get("model_votes", {}).get("industrial"),
            "vote_live": result.get("model_votes", {}).get("live"),
            "rule_action": rule.get("action"),
            "rule_scope": json.dumps(rule.get("scope")),
            "rule_conditions": json.dumps(rule.get("conditions")),
            "rule_pattern": rule.get("pattern"),
            "rule_reason": rule.get("reason"),
        })

    output_df = pd.DataFrame(output_rows)
    
    # Store results in cache with timestamp as key
    cache_key = str(int(time.time() * 1000))
    offline_analysis_cache[cache_key] = {
        "df": output_df,
        "waf_rules": waf_rules,
        "filename": file.filename,
        "total_flows": len(output_rows),
        "anomaly_count": anomaly_count
    }
    
    # Return summary instead of file
    return jsonify({
        "status": "success",
        "cache_key": cache_key,
        "total_flows": len(output_rows),
        "anomaly_count": anomaly_count,
        "normal_count": len(output_rows) - anomaly_count,
        "filename": file.filename,
        "has_anomalies": anomaly_count > 0
    })


@app.route("/download_analyzed_csv/<cache_key>", methods=["GET"])
def download_analyzed_csv(cache_key):
    if cache_key not in offline_analysis_cache:
        return jsonify({"error": "Analysis results not found or expired"}), 404
    
    cached = offline_analysis_cache[cache_key]
    output_df = cached["df"]
    filename = cached["filename"]
    
    buffer = io.StringIO()
    output_df.to_csv(buffer, index=False)
    buffer.seek(0)

    return send_file(
        io.BytesIO(buffer.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"analyzed_{filename}"
    )


@app.route("/download_waf_rules/<cache_key>", methods=["GET"])
def download_waf_rules(cache_key):
    if cache_key not in offline_analysis_cache:
        return jsonify({"error": "Analysis results not found or expired"}), 404
    
    cached = offline_analysis_cache[cache_key]
    waf_rules = cached["waf_rules"]
    
    if not waf_rules:
        return jsonify({"error": "No anomalies detected, no WAF rules to download"}), 400
    
    # Structure the JSON with metadata
    waf_json = {
        "generated_at": datetime.now().isoformat(),
        "source_file": cached["filename"],
        "total_flows_analyzed": cached["total_flows"],
        "total_anomalies_detected": cached["anomaly_count"],
        "waf_rules": waf_rules,
        "summary": {
            "critical_severity": sum(1 for r in waf_rules if r["severity"] == "CRITICAL"),
            "high_severity": sum(1 for r in waf_rules if r["severity"] == "HIGH"),
            "medium_severity": sum(1 for r in waf_rules if r["severity"] == "MEDIUM"),
            "low_severity": sum(1 for r in waf_rules if r["severity"] == "LOW")
        }
    }
    
    json_str = json.dumps(waf_json, indent=2)
    
    return send_file(
        io.BytesIO(json_str.encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"waf_rules_{cached['filename'].replace('.csv', '')}.json"
    )


# =========================
# FALSE POSITIVE
# =========================
@app.route("/mark_false_positive", methods=["POST"])
def mark_false_positive():
    data = request.get_json()
    src, dst, ts = data.get("src_ip"), data.get("dst_ip"), data.get("timestamp")

    features = None
    removed = False

    with lock:
        # Find and remove the matching OPEN alert
        for i, a in enumerate(list(alerts_data)):
            if a.get("src_ip") == src and a.get("dst_ip") == dst and a.get("timestamp") == ts:
                features = a.get("features") or a.get("_features")
                # Remove the alert from in-memory list
                del alerts_data[i]
                removed = True
                print(f"[i] Removed alert as false positive: {src} -> {dst} @ {ts}")
                # Persist the updated alerts to disk
                persist_alerts_to_disk()
                break

        # Fallback: if alert didn't include features, search captured_data
        if not features:
            for l in captured_data:
                if l.get("src_ip") == src and l.get("dst_ip") == dst and l.get("timestamp") == ts:
                    features = l.get("_features")
                    break

    if features:
        try:
            predictor.accept_false_positive(features)
            print(f"[i] Accepted false positive into live baseline for {src} -> {dst}")
        except Exception as e:
            print("[!] Error accepting false positive into live baseline:", e)

    if removed:
        return jsonify({"status": "success", "removed": True})
    else:
        print(f"[!] mark_false_positive: alert not found for {src} -> {dst} @ {ts}")
        return jsonify({"status": "not_found"}), 404


# =========================
# 🔥 DYNAMIC WAF ENGINE
# =========================
def detect_pattern(alert):
    now = time.time()
    src = alert.get("src_ip")
    dst = alert.get("dst_ip")
    sev = alert.get("severity", "LOW")
    proto = alert.get("protocol", "")

    recent_alerts[src] = [
        a for a in recent_alerts[src]
        if now - a["time"] <= ALERT_WINDOW_SECONDS
    ]

    recent_alerts[src].append({
        "dst": dst,
        "severity": sev,
        "time": now
    })

    dsts = [a["dst"] for a in recent_alerts[src]]

    # 🔴 Same src → same dst repeatedly
    if dsts.count(dst) >= 3:
        return "REPEATED_PAIR"

    # 🔴 Scan / recon
    if len(set(dsts)) >= 5:
        return "SRC_SCAN"

    # 🔴 Burst anomaly
    if sev == "HIGH":
        return "BURST"

    # 🟠 Low & slow
    if sev == "MEDIUM" and len(dsts) >= 3:
        return "LOW_AND_SLOW"

    # 🟡 TLS behavioural anomaly
    if proto == "TCP" and sev == "MEDIUM":
        return "ENCRYPTED_ANOMALY"

    if sev == "CRITICAL":
        return "Anomalous Behavior"

    return "UNKNOWN"

@app.route("/generate_waf_rule", methods=["POST"])
def generate_waf_rule():
    alert = request.get_json()
    if not alert:
        return jsonify({"error": "invalid request"}), 400

    src = alert.get("src_ip")
    dst = alert.get("dst_ip")
    severity = alert.get("severity", "LOW")
    scores = alert.get("scores", {})
    explain = alert.get("explainability", {})

    pattern = detect_pattern(alert)

    # Defaults
    action = "MONITOR_ONLY"
    scope = {"type": "SOURCE_IP", "value": src}
    conditions = {"duration_seconds": 180}

    # 🔥 Behaviour → Enforcement
    if pattern == "REPEATED_PAIR":
        action = "RATE_LIMIT_PAIR"
        scope = {
            "type": "SRC_DST_PAIR",
            "src_ip": src,
            "dst_ip": dst
        }
        conditions = {"threshold": "10 req/sec", "duration_seconds": 300}

    elif pattern == "SRC_SCAN":
        action = "TEMP_BLOCK_IP"
        conditions = {"duration_seconds": 600}

    elif pattern == "BURST":
        action = "RATE_LIMIT_IP"
        conditions = {"threshold": "50 req/sec", "duration_seconds": 600}

    elif pattern == "API_ABUSE":
        action = "RATE_LIMIT_ENDPOINT"
        scope = {
            "type": "ENDPOINT",
            "value": alert.get("endpoint", "unknown")
        }
        conditions = {"threshold": "5 req/sec", "duration_seconds": 300}

    elif pattern == "Anomalous Behavior":
        action = "TEMP_BLOCK_PAIR"
        scope = {
            "type": "SRC_DST_PAIR",
            "src_ip": src,
            "dst_ip": dst
        }
        conditions = {"threshold": "", "duration_seconds": 1800}

    elif pattern == "FALSE_POSITIVE_PATTERN":
        action = "NO_ACTION"
        conditions = {}

    # 🧠 Human-readable reason
    reason = "Behavioural anomaly detected by ZeroTrace-X ML engine"
    if explain and explain.get("top_deviations"):
        reason += " | Deviations: " + ", ".join(explain["top_deviations"])

    rule = {
        "rule_id": f"zerotrace-x-{int(time.time())}",
        "generated_at": datetime.now().isoformat(),
        "source": "ZeroTrace-X-ML",
        "pattern": pattern,
        "severity": severity,
        "confidence": abs(scores.get("live", 0)),
        "requires_admin_approval": True,

        "action": action,
        "scope": scope,
        "conditions": conditions,
        "reason": reason
    }

    return jsonify({"status": "success", "rule": rule}), 200

# =========================
# STARTUP HOOKS
# =========================
# Register startup hook in a compatibility-safe way
try:
    @app.before_first_request
    def _startup_load_alerts():
        # Ensure persisted alerts are loaded when Flask starts (works with reloader)
        load_alerts_from_disk()
        ensure_background_services()
        print(f"[i] startup: in-memory alerts_count={len(alerts_data)}")
except Exception:
    # Some Flask builds/environments may not expose the decorator at import time
    # Fallback: load alerts immediately to avoid crashing and to ensure persistence is read
    load_alerts_from_disk()
    print("[!] Flask instance has no before_first_request; loaded alerts at import time instead")
    print(f"[i] startup: in-memory alerts_count={len(alerts_data)}")
    
    ensure_background_services()


# =========================
# START (when run directly)
# =========================
if __name__ == "__main__":
    # Also load alerts when executed as a script
    load_alerts_from_disk()
    ensure_background_services()

    app.run(debug=True)
