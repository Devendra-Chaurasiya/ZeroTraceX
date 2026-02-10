
import threading
import time
import psutil
import json
import os
from collections import deque
from datetime import datetime

class HostMonitor:
    def __init__(self, log_file="data/host_logs.json", history_size=60):
        self.log_file = log_file
        self.baseline_file = os.path.join("data", "process_baselines.json")
        self.history_size = history_size
        self.running = False
        self.lock = threading.Lock()
        
        # In-memory history for live graphs
        self.history = {
            "timestamps": deque(maxlen=history_size),
            "cpu": deque(maxlen=history_size),
            "memory": deque(maxlen=history_size),
            "net_sent": deque(maxlen=history_size),
            "net_recv": deque(maxlen=history_size)
        }
        
        # Track suspicious processes (simple behavioral heuristic)
        self.suspicious_processes = []
        self.persistence_tracker = {}
        
        # Previous network counters for rate calculation
        self._last_net_io = psutil.net_io_counters()
        self._last_time = time.time()

        # Create data directory if not exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        print("[*] Host Monitor started.")

    def stop(self):
        self.running = False
        print("[*] Host Monitor stopping...")

    def _monitor_loop(self):
        while self.running:
            try:
                self._collect_metrics()
            except Exception as e:
                print(f"[!] Host Monitor Error: {e}")
            time.sleep(1)

    def _collect_metrics(self):
        now = time.time()
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # System Metrics
        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        mem_pct = mem.percent
        
        # Network Rates (Bytes per second)
        net_io = psutil.net_io_counters()
        time_delta = now - self._last_time
        if time_delta < 0.1: time_delta = 0.1 # prevent div by zero
        
        sent_rate = (net_io.bytes_sent - self._last_net_io.bytes_sent) / time_delta
        recv_rate = (net_io.bytes_recv - self._last_net_io.bytes_recv) / time_delta
        
        self._last_net_io = net_io
        self._last_time = now
        
        # Load process baselines from disk (adaptive thresholds)
        self.process_baselines = self._load_baselines()

        # Process Analysis (Deep Hunter: Persistence & Adaptive Baselines)
        # 1. Map Network Sockets (PID -> Remote IP/Port)
        net_map = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.pid:
                    key = conn.pid
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Listening"
                    net_map[key] = remote
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # 2. Iterate Processes: Ancestry, Risk Scoring, Persistence
        suspicious = []

        # --- WHITELIST DEFINITION ---
        # Trusted system binaries and safe user applications
        WHITELIST_SYSTEM = {
            "svchost.exe": {"parent": "services.exe", "ports": "ANY"},
            "services.exe": {"parent": "wininit.exe", "ports": "NONE"},
            "System": {"parent": None, "ports": "ANY"},
            "Registry": {"parent": None, "ports": "NONE"},
            "smss.exe": {"parent": "System", "ports": "NONE"},
            "csrss.exe": {"parent": None, "ports": "NONE"},
            "wininit.exe": {"parent": "smss.exe", "ports": "NONE"},
            "lsass.exe": {"parent": "wininit.exe", "ports": "ANY"},
            "chrome.exe": {"parent": None, "ports": "ANY"},
            "Code.exe": {"parent": None, "ports": "ANY"},
        }

        # Adaptive Baseline: Track process averages (runtime memory)
        if not hasattr(self, 'process_baselines'): self.process_baselines = {}

        # Expanded fields for "View Detail"
        active_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'ppid', 'status', 'username', 'exe', 'cmdline']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = pinfo['name']
                active_pids.add(pid)

                # Sanitize None values for UI
                pinfo['username'] = pinfo.get('username') or "Unknown"
                pinfo['exe'] = pinfo.get('exe') or "Access Denied"
                pinfo['cmdline'] = " ".join(pinfo.get('cmdline', [])) if pinfo.get('cmdline') else ""

                # Ancestry
                try:
                    parent = psutil.Process(pinfo['ppid']) if pinfo['ppid'] else None
                    pinfo['parent_name'] = parent.name() if parent else "System"
                except:
                     pinfo['parent_name'] = "Unknown"

                # --- WHITELIST CHECK ---
                is_whitelisted = False
                if name in WHITELIST_SYSTEM:
                    rule = WHITELIST_SYSTEM[name]
                    # Check 1: Parent Verification (if strict rule exists)
                    parent_ok = True
                    if rule["parent"] and rule["parent"] != pinfo['parent_name']:
                        parent_ok = False
                    if parent_ok:
                        is_whitelisted = True

                # --- Adaptive Baseline Learning ---
                if name not in self.process_baselines:
                    self.process_baselines[name] = {'cpu': [], 'mem': []}

                # Add to baseline history (rolling window of 50)
                pb = self.process_baselines[name]
                pb['cpu'].append(pinfo['cpu_percent'])
                pb['mem'].append(pinfo['memory_percent'])
                if len(pb['cpu']) > 50:
                    pb['cpu'].pop(0)
                    pb['mem'].pop(0)

                # Calculate Adaptive Thresholds 
                avg_cpu = sum(pb['cpu']) / len(pb['cpu']) if pb['cpu'] else 0
                avg_mem = sum(pb['mem']) / len(pb['mem']) if pb['mem'] else 0

                # Dynamic Thresholds
                # If whitelisted, use MUCH looser thresholds (e.g. 80% CPU vs 50%)
                base_cpu = 85.0 if is_whitelisted else 50.0
                base_mem = 60.0 if is_whitelisted else 30.0

                cpu_thresh = max(base_cpu, avg_cpu * 3.0) 
                mem_thresh = max(base_mem, avg_mem * 2.5)

                # --- Risk Scoring ---
                risk_score = 0
                reasons = []

                # 1. Resource Spikes (Adaptive)
                if pinfo['cpu_percent'] > cpu_thresh:
                    # Penalty is lower for whitelisted apps
                    score_add = 1 if is_whitelisted else 3
                    risk_score += score_add
                    reasons.append(f"High CPU ({pinfo['cpu_percent']}%)")
                if pinfo['memory_percent'] > mem_thresh:
                    score_add = 1 if is_whitelisted else 2
                    risk_score += score_add
                    reasons.append("High Mem")

                # 2. Network Activity (Deep Hunter)
                if pid in net_map:
                    # If whitelisted for ANY ports, ignore network risk unless suspicious parent
                    if not (is_whitelisted and WHITELIST_SYSTEM.get(name, {}).get("ports") == "ANY"):
                        risk_score += 2
                        reasons.append(f"Net: {net_map[pid]}")

                # 3. Persistence / Frequency
                if pid not in self.persistence_tracker:
                     self.persistence_tracker[pid] = 0

                if risk_score > 0 or pinfo['cpu_percent'] > 10.0:
                     self.persistence_tracker[pid] += 1
                else:
                     if self.persistence_tracker[pid] > 0:
                          self.persistence_tracker[pid] -= 1

                if self.persistence_tracker[pid] > 60: 
                     # Only penalize persistence if NOT whitelisted
                     if not is_whitelisted:
                        risk_score += 1
                        reasons.append("High Persistence")

                # Final Report Threshold
                # Whitelisted apps need higher score to be flagged
                threshold = 4 if is_whitelisted else 3

                if risk_score >= threshold:
                     pinfo['risk_score'] = risk_score
                     pinfo['reasons'] = reasons
                     suspicious.append(pinfo)
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Cleanup persistence tracker to avoid leak
        for pid in list(self.persistence_tracker.keys()):
            if pid not in active_pids:
                self.persistence_tracker.pop(pid, None)
        
        # --- PSCS02 WINDOWED AGGREGATION ---
        # Instead of just sending raw snapshots, we aggregate features over time
        # This aligns with Requirement 2: "Aggregate everything into time windows"
        
        # 1. Update In-Memory History (Existing)
        with self.lock:
            self.history["timestamps"].append(timestamp)
            self.history["cpu"].append(cpu_pct)
            self.history["memory"].append(mem_pct)
            self.history["net_sent"].append(sent_rate)
            self.history["net_recv"].append(recv_rate)
            self.suspicious_processes = suspicious

        # 2. Log significant events (Existing)
        if suspicious or cpu_pct > 80:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "cpu": cpu_pct,
                "memory": mem_pct,
                "suspicious_processes": sorted(suspicious, key=lambda x: x['risk_score'], reverse=True)
            }
            self._write_log(log_entry)
            
        # Periodic Baseline Save (approx every 60s)
        if int(time.time()) % 60 == 0:
            self._save_baselines()

    def _load_baselines(self):
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load baselines: {e}")
        return {}

    def _save_baselines(self):
        try:
            with open(self.baseline_file, "w") as f:
                json.dump(self.process_baselines, f)
        except Exception as e:
            print(f"[!] Failed to save baselines: {e}")

    def _write_log(self, entry):
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[!] Failed to write host log: {e}")

    def get_latest_metrics(self):
        with self.lock:
            # PSCS02: Derived Behavioral Features
            # Calculate variance/entropy over the last 60s window (history_size is 60)
            
            def get_window_stats(sequence):
                if not sequence: return 0.0, 0.0
                avg = sum(sequence) / len(sequence)
                # Simple variance approximation
                var = sum((x - avg) ** 2 for x in sequence) / len(sequence)
                return avg, var

            cpu_avg, cpu_var = get_window_stats(list(self.history["cpu"]))
            mem_avg, mem_var = get_window_stats(list(self.history["memory"]))
            net_sent_avg, net_sent_var = get_window_stats(list(self.history["net_sent"]))
            net_recv_avg, net_recv_var = get_window_stats(list(self.history["net_recv"]))
            
            # Count distinct suspicious processes in window (Persistence Indicator)
            # This is a proxy for "Process reappears across windows"
            persistent_suspicion_count = len([pid for pid, count in self.persistence_tracker.items() if count > 5])

            return {
                "cpu": list(self.history["cpu"]),
                "memory": list(self.history["memory"]),
                "net_sent": list(self.history["net_sent"]),
                "net_recv": list(self.history["net_recv"]),
                "timestamps": list(self.history["timestamps"]),
                "suspicious_processes": self.suspicious_processes,
                "current": {
                    "cpu": self.history["cpu"][-1] if self.history["cpu"] else 0,
                    "memory": self.history["memory"][-1] if self.history["memory"] else 0,
                    "net_sent": self.history["net_sent"][-1] if self.history["net_sent"] else 0,
                    "net_recv": self.history["net_recv"][-1] if self.history["net_recv"] else 0
                },
                # PSCS02 Window Features for ML
                "window_features": {
                    "cpu_avg": float(cpu_avg),
                    "cpu_var": float(cpu_var),
                    "mem_avg": float(mem_avg),
                    "mem_var": float(mem_var),
                    "net_sent_avg": float(net_sent_avg),
                    "net_sent_var": float(net_sent_var),
                    "net_recv_avg": float(net_recv_avg),
                    "net_recv_var": float(net_recv_var),
                    "suspicious_persistence_count": persistent_suspicion_count
                }
            }
