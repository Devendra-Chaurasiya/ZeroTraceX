import os
import json
import threading
import csv
import warnings
from typing import Dict, Any, List, Optional
from datetime import datetime

import numpy as np
import pandas as pd
from joblib import load as joblib_load, dump as joblib_dump
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Suppress sklearn feature name warnings
warnings.filterwarnings('ignore', category=UserWarning, message='.*does not have valid feature names.*')


class FlowPredictor:
    """
    Production-ready anomaly detector that loads and serves multiple pre-trained models.

    Models supported:
    - Home Network Model
    - Industrial Network Model
    - Live Baseline Model (disk-backed, restart-safe)

    Live baseline uses disk-backed buffering and batch training
    to prevent memory pressure and baseline poisoning.

    Startup behavior:
    - Loads scalers, IsolationForest models, thresholds, and feature orders once.
    - Attempts to load live_iforest.pkl if available.
    - No training or fitting performed at runtime until buffer threshold is met.

    Thread safety:
    - Inference guarded with an internal lock to safely run during background capture.
    """
    
    # Live baseline configuration
    LIVE_BUFFER_FILE = os.path.join("ml", "models", "live", "live_baseline_buffer.csv")
    LIVE_MODEL_FILE = os.path.join("ml", "models", "live", "live_iforest.pkl")
    LIVE_SCALER_FILE = os.path.join("ml", "models", "live", "live_scaler.pkl")
    LIVE_METADATA_FILE = os.path.join("ml", "models", "live", "live_metadata.json")
    BASELINE_BATCH_SIZE = 500  # Train new model after collecting this many verified normal flows

    def __init__(self):
        self._lock = threading.Lock()
        self.models: Dict[str, Dict[str, Any]] = {}
        self.active_model_name: str = "home"  # default selection; can be changed via setter
        
        # Live baseline state (memory-efficient: only counters, not data)
        # Live baseline learning is deferred and batch-based
        # to avoid memory overload and unsafe online learning.
        self.live_buffer_count = 0  # Current number of samples in buffer file
        self.live_model_loaded = False
        self.live_status = "UNTRAINED"  # UNTRAINED | COLLECTING | ACTIVE
        self.last_trained_time = None
        self.total_samples_trained = 0
        self.live_training_in_progress = False
        
        # System Baseline Configuration
        self.SYSTEM_BUFFER_FILE = os.path.join("ml", "models", "live", "system_baseline.csv")
        self.SYSTEM_MODEL_FILE = os.path.join("ml", "models", "live", "system_iforest.pkl")
        self.SYSTEM_SCALER_FILE = os.path.join("ml", "models", "live", "system_scaler.pkl")
        self.system_buffer_count = 0
        self.system_model_loaded = False
        
        # Define model file locations
        home_paths = {
            "scaler": os.path.join("ml", "models", "home", "home_scaler.pkl"),
            "model": os.path.join("ml", "models", "home", "home_iforest.pkl"),
            "threshold": os.path.join("ml", "models", "home", "home_threshold.json"),
            "feature_order": os.path.join("ml", "models", "home", "home_feature_order.txt"),
        }

        industrial_paths = {
            "scaler": os.path.join("ml", "models", "industrial", "scaler.pkl"),
            "model": os.path.join("ml", "models", "industrial", "isolation_forest.pkl"),
            "threshold": os.path.join("ml", "models", "industrial", "threshold.json"),
            "feature_order": os.path.join("ml", "models", "industrial", "feature_order.txt"),
        }

        # Load both model bundles at startup
        self.models["home"] = self._load_model_bundle(home_paths, metadata={"name": "home", "version": "v1.0", "last_trained_date": "2024-12-15"})
        self.models["industrial"] = self._load_model_bundle(industrial_paths, metadata={"name": "industrial", "version": "v1.0", "last_trained_date": "2024-12-10"})
        
        # Initialize live baseline system
        self._init_live_baseline()
        
        # Explicit initialization of system model key to safety
        self.models["system"] = {
            "model": None, # Will be loaded or trained
            "scaler": None,
            "threshold": -0.5,
            "feature_order": ["cpu", "memory", "proc_count", "net_sent", "net_recv"],
            "metadata": {"name": "system", "status": "UNINITIALIZED"}
        }
        self._init_system_baseline()

    def _init_system_baseline(self):
        """Initialize system-level anomaly detection model."""
        if os.path.exists(self.SYSTEM_BUFFER_FILE):
             with open(self.SYSTEM_BUFFER_FILE, 'r') as f:
                self.system_buffer_count = sum(1 for _ in f) - 1 # minus header

        if os.path.exists(self.SYSTEM_MODEL_FILE):
            try:
                self.models["system"] = {
                    "model": joblib_load(self.SYSTEM_MODEL_FILE),
                    "scaler": joblib_load(self.SYSTEM_SCALER_FILE),
                    "threshold": -0.5, # Less sensitive for system metrics
                    "feature_order": ["cpu", "memory", "proc_count", "net_sent", "net_recv"]
                }
                self.system_model_loaded = True
                print(f"[✓] System Baseline Loaded.")
            except Exception as e:
                print(f"[!] Failed to load system model: {e}")
    
    def train_system_baseline(self):
        """Train IsolationForest on collected system metrics."""
        self._train_generic_baseline(
            self.SYSTEM_BUFFER_FILE, 
            self.SYSTEM_MODEL_FILE, 
            self.SYSTEM_SCALER_FILE,
            "system",
            ["cpu", "memory", "proc_count", "net_sent", "net_recv"]
        )

    def _train_generic_baseline(self, buffer_file, model_file, scaler_file, model_name, feature_order):
        """Generic training helper for any CSV buffer."""
        try:
            if not os.path.exists(buffer_file): return
            
            df = pd.read_csv(buffer_file)
            if len(df) < 50: return # Minimum samples
            
            X = df[feature_order].values
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            model = IsolationForest(contamination=0.01, random_state=42)
            model.fit(X_scaled)
            
            joblib_dump(model, model_file)
            joblib_dump(scaler, scaler_file)
            
            self.models[model_name] = {
                "model": model,
                "scaler": scaler,
                "threshold": -0.5,
                "feature_order": feature_order
            }
            
            # Clean buffer
            os.remove(buffer_file)
            print(f"[✓] Trained new {model_name} baseline.")
            
        except Exception as e:
            print(f"[!] Training {model_name} failed: {e}")

    def collect_system_sample(self, metrics: Dict[str, float]):
        """Collect system metrics for training."""
        file_exists = os.path.exists(self.SYSTEM_BUFFER_FILE)
        HEADER = ["cpu", "memory", "proc_count", "net_sent", "net_recv"]
        
        try:
            with open(self.SYSTEM_BUFFER_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists: writer.writerow(HEADER)
                writer.writerow([metrics.get(k, 0) for k in HEADER])
            
            self.system_buffer_count += 1
            if self.system_buffer_count >= 100: # Train every 100 samples
                self.train_system_baseline()
                self.system_buffer_count = 0
        except Exception as e:
            print(f"[!] System sample collect error: {e}")
        
    def _init_live_baseline(self):
        """
        Initialize disk-based live baseline learning system.
        
        RESTART SAFETY:
        - Loads existing live_iforest.pkl if present
        - Counts existing buffer entries without loading into RAM
        - Waits for buffer to fill if model doesn't exist
        """
        # Count existing buffer entries (memory-efficient: don't load data)
        if os.path.exists(self.LIVE_BUFFER_FILE):
            with open(self.LIVE_BUFFER_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                self.live_buffer_count = sum(1 for _ in reader)
        else:
            self.live_buffer_count = 0
        
        # Load metadata if available
        if os.path.exists(self.LIVE_METADATA_FILE):
            try:
                with open(self.LIVE_METADATA_FILE, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                    self.last_trained_time = metadata.get("last_trained_time")
                    self.total_samples_trained = metadata.get("total_samples_trained", 0)
            except Exception as e:
                print(f"[!] Failed to load live metadata: {e}")
            
        # Attempt to load existing live model (restart safety)
        if os.path.exists(self.LIVE_MODEL_FILE):
            try:
                live_model = joblib_load(self.LIVE_MODEL_FILE)
                live_scaler = None
                if os.path.exists(self.LIVE_SCALER_FILE):
                    live_scaler = joblib_load(self.LIVE_SCALER_FILE)
                
                # Use home model's feature order as reference
                feature_order = self.models["home"]["feature_order"]
                
                self.models["live"] = {
                    "model": live_model,
                    "scaler": live_scaler,
                    "threshold": -0.2,  # Default threshold for live model
                    "feature_order": feature_order,
                    "baseline_means": {},
                    "metadata": {
                        "name": "live",
                        "version": "v1.0",
                        "last_trained_date": self.last_trained_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
                self.live_model_loaded = True
                self.live_status = "ACTIVE"
                print(f"[✓] Live baseline model loaded from disk ({self.live_buffer_count} samples in buffer)")
                print(f"[✓] Live Baseline: ACTIVE (trained on {self.total_samples_trained} flows)")
            except Exception as e:
                print(f"[!] Failed to load live model: {e}")
                self.live_model_loaded = False
                self.live_status = "UNTRAINED"
        else:
            self.live_status = "UNTRAINED"
            print(f"[i] Live baseline warming up - no model found yet")
            print(f"[i] Will train after collecting {self.BASELINE_BATCH_SIZE} verified normal flows.")
            print(f"[i] Current buffer: {self.live_buffer_count} samples")
            
    def collect_live_baseline_sample(self, feature_dict: Dict[str, Any], 
                                     home_result: Dict[str, Any],
                                     industrial_result: Dict[str, Any]) -> None:
        """
        Collect verified normal flow for live baseline training.
        
        SAFE COLLECTION RULE:
        Append to buffer ONLY IF:
        - Home prediction == NORMAL
        - Industrial prediction == NORMAL  
        - Both severity == LOW or NONE
        
        Never store MEDIUM or HIGH severity flows to prevent baseline poisoning.
        
        MEMORY RULE:
        - Appends directly to disk CSV
        - Never keeps full dataset in RAM
        - Only increments counter
        """
        # Safety check: both models must agree flow is normal
        if (not home_result.get("anomaly", True) and 
            not industrial_result.get("anomaly", True) and
            home_result.get("severity", "HIGH") == "LOW" and
            industrial_result.get("severity", "HIGH") == "LOW"):
            
            with self._lock:
                try:
                    # Get feature order from home model
                    feature_order = self.models["home"]["feature_order"]
                    features_array = self._prepare_features(feature_dict, feature_order)
                    
                    # Append to disk buffer (memory-efficient)
                    file_exists = os.path.exists(self.LIVE_BUFFER_FILE)
                    with open(self.LIVE_BUFFER_FILE, 'a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if not file_exists:
                            writer.writerow(feature_order)  # Write header
                        writer.writerow(features_array.tolist())
                    
                    self.live_buffer_count += 1
                    
                    # Update status to COLLECTING if we're building baseline
                    if self.live_status == "UNTRAINED" and self.live_buffer_count > 0:
                        self.live_status = "COLLECTING"
                        print(f"[i] Live baseline collecting samples... ({self.live_buffer_count}/{self.BASELINE_BATCH_SIZE})")
                    
                    # Check if we need to train
                    if self.live_buffer_count >= self.BASELINE_BATCH_SIZE:
                        self._train_live_baseline()
                        
                except Exception as e:
                    print(f"[!] Error collecting live baseline sample: {e}")
                    
    def _train_live_baseline(self):
        """
        Train new live baseline model from disk buffer.
        Protected by a training mutex to prevent parallel runs.
        """

    # 🔒 HARD STOP if training already running
        if self.live_training_in_progress:
            return

    # 🔐 Acquire training lock
        self.live_training_in_progress = True

        try:
            print(f"[→] Training live baseline model from {self.live_buffer_count} samples...")

            feature_order = self.models["home"]["feature_order"]
            X_data = []
            skipped_rows = 0

            # ✅ Safe file read (single trainer only)
            with open(self.LIVE_BUFFER_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header

                for row in reader:
                    try:
                        if len(row) != len(feature_order):
                            skipped_rows += 1
                            continue

                        values = []
                        for x in row:
                            x = x.strip()
                            values.append(float(x) if x and x.lower() != "nan" else 0.0)

                        X_data.append(values)
                    except Exception:
                        skipped_rows += 1

            if not X_data:
                print("[!] No valid samples for training")
                return

            X = np.array(X_data, dtype=float)

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                n_jobs=-1
            )
            model.fit(X_scaled)

            # 💾 Save model artifacts
            joblib_dump(model, self.LIVE_MODEL_FILE)
            joblib_dump(scaler, self.LIVE_SCALER_FILE)

            trained_samples = len(X)
            self.total_samples_trained += trained_samples
            self.last_trained_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.live_status = "ACTIVE"

            with open(self.LIVE_METADATA_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    "last_trained_time": self.last_trained_time,
                    "total_samples_trained": self.total_samples_trained,
                    "status": self.live_status
                }, f, indent=2)

            self.models["live"] = {
                "model": model,
                "scaler": scaler,
                "threshold": -0.2,
                "feature_order": feature_order,
                "baseline_means": {
                    name: float(scaler.mean_[i])
                    for i, name in enumerate(feature_order)
                },
                "metadata": {
                    "name": "live",
                    "version": "v1.0",
                    "last_trained_date": self.last_trained_time
                }
            }

            self.live_model_loaded = True

            # 🧹 Safe cleanup (ONLY ONE THREAD DOES THIS)
            if os.path.exists(self.LIVE_BUFFER_FILE):
                os.remove(self.LIVE_BUFFER_FILE)

            self.live_buffer_count = 0

            print(f"[✓] Live Baseline trained on {trained_samples} samples (skipped {skipped_rows})")
            print(f"[✓] Live Baseline ACTIVE (total trained: {self.total_samples_trained})")

        except Exception as e:
            print(f"[✗] Live baseline training failed: {e}")
            import traceback
            traceback.print_exc()

        finally:
            # 🔓 Release training lock
            self.live_training_in_progress = False
        
    def get_live_baseline_status(self) -> Dict[str, Any]:
        """Return comprehensive status of live baseline learning system for UI display."""
        status_message = ""
        if self.live_status == "ACTIVE":
            status_message = f"Live Baseline: ACTIVE (trained on {self.total_samples_trained} flows)"
        elif self.live_status == "COLLECTING":
            status_message = f"Live Baseline: COLLECTING ({self.live_buffer_count}/{self.BASELINE_BATCH_SIZE})"
        else:  # UNTRAINED
            status_message = "Live baseline warming up"
        
        return {
            "status": self.live_status,
            "model_loaded": self.live_model_loaded,
            "samples_collected": self.live_buffer_count,
            "samples_required": self.BASELINE_BATCH_SIZE,
            "total_samples_trained": self.total_samples_trained,
            "last_trained_time": self.last_trained_time,
            "progress_percent": min(100, int((self.live_buffer_count / self.BASELINE_BATCH_SIZE) * 100)),
            "status_message": status_message,
            "is_active": self.live_status == "ACTIVE"
        }

    def _load_model_bundle(self, paths: Dict[str, str], metadata: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Load scaler, model, threshold, and feature order from disk.

        Expected keys in `paths`: scaler, model, threshold, feature_order
        Returns a dict with keys: scaler, model, threshold, feature_order, metadata
        """
        missing = [k for k, p in paths.items() if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Missing model files: {missing} in paths {paths}")

        scaler = joblib_load(paths["scaler"])  # StandardScaler
        model = joblib_load(paths["model"])    # IsolationForest

        with open(paths["threshold"], "r", encoding="utf-8") as f:
            threshold_payload = json.load(f)

        # support multiple JSON structures: {"threshold": value}, {"anomaly_threshold": value}, or a raw number
        if isinstance(threshold_payload, dict):
            threshold = threshold_payload.get("threshold") or threshold_payload.get("anomaly_threshold")
            if threshold is None:
                # If neither key exists, try to get the first numeric value
                for v in threshold_payload.values():
                    if isinstance(v, (int, float)):
                        threshold = v
                        break
            if threshold is None:
                raise ValueError(f"Could not find threshold value in {paths['threshold']}. Content: {threshold_payload}")
            threshold = float(threshold)
        else:
            threshold = float(threshold_payload)

        with open(paths["feature_order"], "r", encoding="utf-8") as f:
            feature_order: List[str] = [line.strip() for line in f if line.strip()]

        # Compute baseline means from scaler (if available) for explainability
        baseline_means = {}
        if hasattr(scaler, 'mean_'):
            for i, feature_name in enumerate(feature_order):
                if i < len(scaler.mean_):
                    baseline_means[feature_name] = float(scaler.mean_[i])

        bundle = {
            "scaler": scaler,
            "model": model,
            "threshold": threshold,
            "feature_order": feature_order,
            "baseline_means": baseline_means,
            "metadata": metadata or {}
        }
        
        return bundle
    
    def accept_false_positive(self, feature_dict: Dict[str, Any]) -> None:
        """
        Admin-approved false positive.
        Force-add this flow to live baseline buffer as NORMAL traffic.
        """
        try:
            with self._lock:
                feature_order = self.models["home"]["feature_order"]
                features_array = self._prepare_features(feature_dict, feature_order)

                file_exists = os.path.exists(self.LIVE_BUFFER_FILE)
                with open(self.LIVE_BUFFER_FILE, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(feature_order)
                    writer.writerow(features_array.tolist())

                self.live_buffer_count += 1

                if self.live_status == "UNTRAINED":
                    self.live_status = "COLLECTING"

                print(f"[✓] False positive accepted into live baseline "
                    f"({self.live_buffer_count}/{self.BASELINE_BATCH_SIZE})")

                # 🚦 Train only once per batch
                if (
                    self.live_buffer_count >= self.BASELINE_BATCH_SIZE
                    and not getattr(self, "live_training_in_progress", False)
                ):
                    self._train_live_baseline()

        except Exception as e:
            print(f"[!] Failed to accept false positive: {e}")


    def set_active_model(self, name: str) -> None:
        """Set the active model for inference. Name must be 'home' or 'industrial'."""
        if name not in self.models:
            raise ValueError(f"Unknown model '{name}'. Available: {list(self.models.keys())}")
        self.active_model_name = name

    def get_loaded_models(self) -> List[str]:
        """Return the list of loaded model names."""
        return list(self.models.keys())

    def _prepare_features(self, feature_dict: Dict[str, Any], feature_order: List[str]) -> np.ndarray:
        """Arrange features strictly according to feature_order.

        Missing features are filled with 0.0; extra keys are ignored.
        """
        return np.array([float(feature_dict.get(name, 0.0)) for name in feature_order], dtype=float)

    def _generate_rule_recommendation(self, anomaly: bool, severity: str, src_ip: str, dst_ip: str) -> Optional[Dict[str, Any]]:
        """Generate a human-readable rule recommendation for anomalies.
        
        This is ONLY a suggestion, NOT enforcement.
        """
        if not anomaly:
            return None
        
        duration = 300  # default 5 minutes
        if severity == "CRITICAL":
            duration = 1800  # 30 minutes for critical severity
        elif severity == "HIGH":
            duration = 600  # 10 minutes for high severity
        elif severity == "MEDIUM":
            duration = 300
        else:
            duration = 180  # 3 minutes for low severity
        
        return {
            "action": "Rate-limit",
            "target": "Source IP",
            "value": src_ip,
            "duration_seconds": duration,
            "reason": "Abnormal deviation from baseline behaviour",
            "severity": severity
        }

    def _compute_explainability(self, feature_dict: Dict[str, Any], baseline_means: Dict[str, float], 
                                 feature_order: List[str]) -> Dict[str, List[str]]:
        """Compute top 3 features with highest absolute deviation from baseline.
        
        Returns explainability dict with top_deviations list.
        """
        deviations = []
        
        for feature_name in feature_order:
            current_value = feature_dict.get(feature_name, 0.0)
            baseline_value = baseline_means.get(feature_name, 0.0)
            
            if baseline_value == 0:
                baseline_value = 1e-6  # avoid division by zero
            
            # Compute relative deviation
            abs_deviation = abs(current_value - baseline_value)
            rel_deviation = abs_deviation / abs(baseline_value)
            
            direction = "↑" if current_value > baseline_value else "↓"
            deviations.append((feature_name, rel_deviation, direction))
        
        # Sort by deviation magnitude and take top 3
        deviations.sort(key=lambda x: x[1], reverse=True)
        top_deviations = [f"{name} {direction}" for name, _, direction in deviations[:3]]
        
        return {
            "top_deviations": top_deviations
        }

    def _compute_combined_explainability(self, feature_dict: Dict[str, Any],
                                         h_means: Dict[str, float], i_means: Dict[str, float],
                                         l_means: Optional[Dict[str, float]],
                                         feature_order: List[str]) -> Dict[str, List[str]]:
        """Prefer features where both a global model (H or I) AND Live model deviate.

        Combined score: max(dev_H, dev_I) * dev_L (fallback to max(H,I) if live not loaded).
        Returns top 3 feature names with direction arrows.
        """
        deviations = []
        for feature_name in feature_order:
            current_value = feature_dict.get(feature_name, 0.0)
            # Global deviations
            h_base = h_means.get(feature_name, 0.0) or 1e-6
            i_base = i_means.get(feature_name, 0.0) or 1e-6
            dev_h = abs(current_value - h_base) / abs(h_base)
            dev_i = abs(current_value - i_base) / abs(i_base)
            global_dev = max(dev_h, dev_i)

            # Live deviation (optional)
            if l_means:
                l_base = l_means.get(feature_name, 0.0) or 1e-6
                dev_l = abs(current_value - l_base) / abs(l_base)
                combined = global_dev * dev_l
            else:
                combined = global_dev

            direction = "↑" if current_value > (l_means.get(feature_name, h_base) if l_means else h_base) else "↓"
            deviations.append((feature_name, combined, direction))

        deviations.sort(key=lambda x: x[1], reverse=True)
        top_deviations = [f"{name} {direction}" for name, _, direction in deviations[:3]]
        return {"top_deviations": top_deviations}

    def _infer_model(self, name: str, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Infer a single model by name, returning score, anomaly, severity."""
        bundle = self.models[name]
        features = self._prepare_features(feature_dict, bundle["feature_order"])  # (n_features,)
        with self._lock:
            X = bundle["scaler"].transform([features])
            score = float(bundle["model"].decision_function(X)[0])
        threshold = float(bundle["threshold"])
        if score < threshold * 2.0:
            severity = "CRITICAL"
        elif score < threshold * 1.5:
            severity = "HIGH"
        elif score < threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        anomaly = score < threshold
        return {"score": round(score, 6), "anomaly": anomaly, "severity": severity}

    def _decision_engine(self, h_anom: bool, i_anom: bool, l_anom: bool) -> Dict[str, Any]:
        """Implements the exact decision table.

        Returns: {final_decision: 'ALLOW'|'ALERT', severity: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', train_live: bool}
        """
        # Map the table
        if not h_anom and not i_anom and not l_anom:
            return {"final_decision": "ALLOW", "severity": "LOW", "train_live": True}
        if not h_anom and i_anom and not l_anom:
            return {"final_decision": "ALLOW", "severity": "LOW", "train_live": True}
        if h_anom and not i_anom and not l_anom:
            return {"final_decision": "ALLOW", "severity": "LOW", "train_live": True}
        if h_anom and i_anom and not l_anom:
            return {"final_decision": "ALLOW", "severity": "LOW", "train_live": True}
        if not h_anom and not i_anom and l_anom:
            return {"final_decision": "ALERT", "severity": "MEDIUM", "train_live": False}
        if not h_anom and i_anom and l_anom:
            return {"final_decision": "ALERT", "severity": "HIGH", "train_live": False}
        if h_anom and not i_anom and l_anom:
            return {"final_decision": "ALERT", "severity": "HIGH", "train_live": False}
        # h_anom and i_anom and l_anom - All three models agree on anomaly
        return {"final_decision": "ALERT", "severity": "CRITICAL", "train_live": False}

    def predict_all(self, feature_dict: Dict[str, Any], src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> Dict[str, Any]:
        """Run H, I, and L models and apply decision engine. Also trigger live training only on LOW.

        Returns a dict matching the API spec with scores, model_votes, final_decision, severity,
        rule_recommendation, explainability, and model_metadata.
        """
        # Inference per model
        h = self._infer_model("home", feature_dict)
        i = self._infer_model("industrial", feature_dict)

        if "live" in self.models and self.models.get("live", {}).get("model") is not None:
            l = self._infer_model("live", feature_dict)
        else:
            # Treat live as NORMAL until trained
            l = {"score": 0.0, "anomaly": False, "severity": "LOW"}

        # Decision engine
        decision = self._decision_engine(h["anomaly"], i["anomaly"], l["anomaly"])

        # Live training trigger: only when final severity == LOW
        if decision["train_live"] and decision["severity"] == "LOW":
            try:
                feature_order = self.models["home"]["feature_order"]
                features_array = self._prepare_features(feature_dict, feature_order)
                file_exists = os.path.exists(self.LIVE_BUFFER_FILE)
                with open(self.LIVE_BUFFER_FILE, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(feature_order)
                    writer.writerow(features_array.tolist())
                self.live_buffer_count += 1
                if self.live_status == "UNTRAINED" and self.live_buffer_count > 0:
                    self.live_status = "COLLECTING"
                    print(f"[i] Live baseline collecting samples... ({self.live_buffer_count}/{self.BASELINE_BATCH_SIZE})")
                if self.live_buffer_count >= self.BASELINE_BATCH_SIZE:
                    self._train_live_baseline()
            except Exception as e:
                print(f"[!] Error appending live baseline sample: {e}")

        # Explainability: prefer features deviating in global and live
        h_means = self.models["home"]["baseline_means"]
        i_means = self.models["industrial"]["baseline_means"]
        l_means = self.models.get("live", {}).get("baseline_means") if self.live_model_loaded else None
        feature_order = self.models["home"]["feature_order"]
        explainability = self._compute_combined_explainability(feature_dict, h_means, i_means, l_means, feature_order)

        # Rule recommendation matches FINAL severity and only for ALERT
        rule_reco = None
        if decision["final_decision"] == "ALERT" and src_ip and dst_ip:
            rule_reco = self._generate_rule_recommendation(True, decision["severity"], src_ip, dst_ip)

        # Build response payload
        model_votes = {
            "home": "ANOMALY" if h["anomaly"] else "NORMAL",
            "industrial": "ANOMALY" if i["anomaly"] else "NORMAL",
            "live": "ANOMALY" if l["anomaly"] else "NORMAL"
        }
        scores = {"home": h["score"], "industrial": i["score"], "live": l["score"]}

        # Aggregate metadata
        metadata = {
            "home": self.models["home"].get("metadata", {}),
            "industrial": self.models["industrial"].get("metadata", {}),
            "live": self.models.get("live", {}).get("metadata", {"status": self.live_status})
        }

        return {
            "final_decision": decision["final_decision"],
            "severity": decision["severity"],
            "scores": scores,
            "model_votes": model_votes,
            "rule_recommendation": rule_reco,
            "explainability": explainability,
            "model_metadata": metadata
        }

    def predict_all_readonly(self, feature_dict: Dict[str, Any], src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Run H, I, and L models and apply decision engine WITHOUT training live model.
        
        This is a READ-ONLY version for offline analysis that:
        - Uses all three models for prediction
        - Applies the same decision engine logic
        - Does NOT add samples to live baseline buffer
        - Does NOT trigger live model training
        
        Returns the same structure as predict_all().
        """
        # Inference per model (exact same logic as predict_all)
        h = self._infer_model("home", feature_dict)
        i = self._infer_model("industrial", feature_dict)

        if "live" in self.models and self.models.get("live", {}).get("model") is not None:
            l = self._infer_model("live", feature_dict)
        else:
            # Treat live as NORMAL until trained
            l = {"score": 0.0, "anomaly": False, "severity": "LOW"}

        # Decision engine (same logic, no training)
        decision = self._decision_engine(h["anomaly"], i["anomaly"], l["anomaly"])

        # SKIP live training - this is the key difference for offline analysis

        # Explainability: prefer features deviating in global and live
        h_means = self.models["home"]["baseline_means"]
        i_means = self.models["industrial"]["baseline_means"]
        l_means = self.models.get("live", {}).get("baseline_means") if self.live_model_loaded else None
        feature_order = self.models["home"]["feature_order"]
        explainability = self._compute_combined_explainability(feature_dict, h_means, i_means, l_means, feature_order)

        # Rule recommendation matches FINAL severity and only for ALERT
        rule_reco = None
        if decision["final_decision"] == "ALERT" and src_ip and dst_ip:
            rule_reco = self._generate_rule_recommendation(True, decision["severity"], src_ip, dst_ip)

        # Build response payload (same as predict_all)
        model_votes = {
            "home": "ANOMALY" if h["anomaly"] else "NORMAL",
            "industrial": "ANOMALY" if i["anomaly"] else "NORMAL",
            "live": "ANOMALY" if l["anomaly"] else "NORMAL"
        }
        scores = {"home": h["score"], "industrial": i["score"], "live": l["score"]}

        # Get metadata
        metadata = {
            "home": self.models["home"].get("metadata", {}),
            "industrial": self.models["industrial"].get("metadata", {}),
            "live": self.models.get("live", {}).get("metadata", {"status": self.live_status})
        }

        return {
            "final_decision": decision["final_decision"],
            "severity": decision["severity"],
            "scores": scores,
            "model_votes": model_votes,
            "rule_recommendation": rule_reco,
            "explainability": explainability,
            "model_metadata": metadata
        }

    def get_model_metadata(self, network_type: Optional[str] = None) -> Dict[str, str]:
        """Return model metadata for the specified network type."""
        name = network_type or self.active_model_name
        if name not in self.models:
            raise ValueError(f"Model '{name}' is not loaded.")
        
        return self.models[name].get("metadata", {})

    def predict(self, feature_dict: Dict[str, Any], network_type: Optional[str] = None, 
                src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Run anomaly inference using the selected pre-trained model.

        - Arranges features per `feature_order`.
        - Scales with the loaded `StandardScaler`.
        - Computes IsolationForest decision_function score.
        - Flags anomaly if score < threshold.
        - Severity: HIGH if score < threshold*1.5, MEDIUM if score < threshold, LOW otherwise.
        - Adds rule recommendation and explainability for anomalies.

        Returns a dict with keys: anomaly, score, severity, rule_recommendation, explainability.
        """
        name = network_type or self.active_model_name
        if name not in self.models:
            raise ValueError(f"Model '{name}' is not loaded.")

        bundle = self.models[name]
        # Prepare feature vector in the exact required order
        features = self._prepare_features(feature_dict, bundle["feature_order"])  # shape: (n_features,)

        with self._lock:
            # Use plain numpy array - models were trained without feature names
            X = bundle["scaler"].transform([features])  # shape: (1, n_features)
            score = float(bundle["model"].decision_function(X)[0])

        threshold = float(bundle["threshold"])  # ensure numeric

        # Determine severity
        if score < threshold * 1.5:
            severity = "HIGH"
        elif score < threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        anomaly = score < threshold

        # Generate rule recommendation for anomalies
        rule_recommendation = None
        explainability = None
        
        if anomaly and src_ip and dst_ip:
            rule_recommendation = self._generate_rule_recommendation(anomaly, severity, src_ip, dst_ip)
            explainability = self._compute_explainability(
                feature_dict, 
                bundle["baseline_means"], 
                bundle["feature_order"]
            )

        return {
            "anomaly": anomaly,
            "score": round(score, 6),
            "severity": severity,
            "rule_recommendation": rule_recommendation,
            "explainability": explainability
        }

    def predict_system_anomaly(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run PSCS02 Anomaly Detection:
        Exploitation Pattern = System Deviation + (Persistence OR Coupling)
        """
        # Extract features
        current = metrics.get("current", {})
        window = metrics.get("window_features", {})
        
        # 1. Map to Feature Vector for Isolation Forest (using window stats + snapshot)
        # Vector: [cpu, memory, proc_count, cpu_var, mem_var, net_avg]
        snapshot_vector = {
            "cpu": current.get("cpu", 0),
            "memory": current.get("memory", 0),
            "proc_count": len(metrics.get("suspicious_processes", [])),
            "net_sent": current.get("net_sent", 0) if "net_sent" in current else 0, # fallbacks
            "net_recv": current.get("net_recv", 0) if "net_recv" in current else 0
        }
        
        # Background training on raw snapshot for simplicity of baseline
        self.collect_system_sample(snapshot_vector)
        
        if not self.system_model_loaded:
             return {"anomaly": False, "score": 0.0, "severity": "LOW", "status": "LEARNING"}

        try:
            bundle = self.models["system"]
            feature_order = bundle["feature_order"]
            
            # Prepare features (using current snapshot for now as per training)
            features = [float(snapshot_vector.get(k, 0)) for k in feature_order]
            
            with self._lock:
                X = bundle["scaler"].transform([features])
                score = float(bundle["model"].decision_function(X)[0])
                
            threshold = float(bundle["threshold"])
            
            # 1. System Deviation Check
            is_deviation = score < threshold
            
            # 2. Persistence Check (from window features)
            persistence_count = window.get("suspicious_persistence_count", 0)
            is_persistent = persistence_count > 0
            
            # 3. Network Coupling (Proxy: High network variance or load in either direction)
            # In a real PSCS02 build validation, we'd check 'net_map' correlation
            net_avg = max(window.get("net_sent_avg", 0), window.get("net_recv_avg", 0))
            start_coupling = net_avg > 10000 # 10KB/s avg threshold
            
            # --- PSCS02 EXPLOITATION LOGIC ---
            # "Exploitation Pattern (ALL must align)" -> But valid to alert if subset is strong
            # We strictly follow: System Deviation + (Persistence OR Network Coupling)
            
            # Default Status
            final_status = {"anomaly": False, "score": round(score, 4), "severity": "LOW", "status": "ACTIVE"}
            
            if is_deviation:
                indicators = ["System deviation detected"]
                severity = "MEDIUM"
                
                if is_persistent:
                    indicators.append("Process persistence across windows")
                    severity = "HIGH"
                
                if start_coupling:
                    indicators.append("Anomalous network coupling")
                    severity = "HIGH"
                    
                if is_persistent and start_coupling:
                    severity = "CRITICAL"
                    indicators.append("Full Exploitation Chain (System+Net+Persist)")

                # Only alert if we have corroboration (PSCS02 requirement for 'Exploitation Pattern')
                # Deviation alone = Anomaly (Low confidence)
                # Deviation + Persistence = Potential Exploitation
                
                if severity != "MEDIUM": # i.e. HIGH or CRITICAL
                    final_status = {
                         "anomaly": True,
                         "score": round(score, 4),
                         "severity": severity,
                         "reason": "Potential Exploitation Pattern",
                         "indicators": indicators,
                         "status": "THREAT"
                    }
                else:
                    # Deviation only -> Just warn, don't flag as full anomaly in UI
                    final_status["severity"] = "MEDIUM"
                    final_status["reason"] = "System Deviation (Transient)"
            
            return final_status
            
        except Exception as e:
            print(f"[!] System prediction error: {e}")
            return {"anomaly": False, "score": 0.0, "severity": "LOW", "status": "ERROR"}
