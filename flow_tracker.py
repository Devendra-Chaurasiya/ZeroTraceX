import time
import numpy as np

# Emit a flow when idle for >= FLOW_TIMEOUT seconds
# Default lowered to 3s to ensure short-lived flows appear in logs
FLOW_TIMEOUT = 3  # seconds


class FlowTracker:
    def __init__(self):
        self.flows = {}

    def _flow_key(self, p):
        return (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], p["protocol"])

    def update_flow(self, packet, completed: bool = False):
        now = time.time()
        key = self._flow_key(packet)
        rev = (packet["dst_ip"], packet["src_ip"],
               packet["dst_port"], packet["src_port"], packet["protocol"])

        if key not in self.flows and rev not in self.flows:
            self.flows[key] = {
                "start": now,
                "last": now,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "sizes": [],
                "times": [],
                # retain meta for logging when flow is emitted
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "protocol": packet["protocol"],
            }

        flow = self.flows[key] if key in self.flows else self.flows[rev]
        direction = "fwd" if key in self.flows else "bwd"

        flow["last"] = now
        flow["sizes"].append(packet["length"])
        flow["times"].append(now)

        if direction == "fwd":
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet["length"]
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet["length"]

        emitted = []
        # If this flow is marked completed (e.g., TCP FIN/RST), emit immediately
        if completed:
            emitted_item = self._emit_flow_for_key(key if key in self.flows else rev)
            if emitted_item is not None:
                emitted.append(emitted_item)

        # Expire idle flows
        emitted.extend(self._expire_flows())

        # Filter out Nones
        return [e for e in emitted if e is not None]

    def _expire_flows(self):
        now = time.time()
        emitted = []
        expired_keys = []

        for k, f in self.flows.items():
            if now - f["last"] > FLOW_TIMEOUT:
                emitted.append({
                    "features": self._features(f),
                    "src_ip": f.get("src_ip"),
                    "dst_ip": f.get("dst_ip"),
                    "src_port": f.get("src_port"),
                    "dst_port": f.get("dst_port"),
                    "protocol": f.get("protocol"),
                })
                expired_keys.append(k)

        for k in expired_keys:
            del self.flows[k]

        return emitted

    def _emit_flow_for_key(self, key):
        if key not in self.flows:
            return None
        f = self.flows[key]
        emitted = {
            "features": self._features(f),
            "src_ip": f.get("src_ip"),
            "dst_ip": f.get("dst_ip"),
            "src_port": f.get("src_port"),
            "dst_port": f.get("dst_port"),
            "protocol": f.get("protocol"),
        }
        del self.flows[key]
        return emitted

    def _features(self, f):
        duration = max(f["last"] - f["start"], 1e-6)
        sizes = np.array(f["sizes"])
        iats = np.diff(f["times"]) if len(f["times"]) > 1 else np.array([0])

        return {
            "Flow Duration": duration * 1e6,
            "Flow Bytes/s": (f["fwd_bytes"] + f["bwd_bytes"]) / duration,
            "Flow Packets/s": (f["fwd_packets"] + f["bwd_packets"]) / duration,
            "Total Fwd Packet": f["fwd_packets"],
            "Total Bwd packets": f["bwd_packets"],
            "Total Length of Fwd Packet": f["fwd_bytes"],
            "Total Length of Bwd Packet": f["bwd_bytes"],
            "Packet Length Min": sizes.min() if len(sizes) else 0,
            "Packet Length Max": sizes.max() if len(sizes) else 0,
            "Packet Length Mean": sizes.mean() if len(sizes) else 0,
            "Packet Length Std": sizes.std() if len(sizes) else 0,
            "Packet Length Variance": sizes.var() if len(sizes) else 0,
            "Average Packet Size": sizes.mean() if len(sizes) else 0,
            "Fwd Packets/s": f["fwd_packets"] / duration,
            "Bwd Packets/s": f["bwd_packets"] / duration,
            "Flow IAT Mean": iats.mean(),
            "Flow IAT Std": iats.std(),
            "Flow IAT Max": iats.max(),
            "Flow IAT Min": iats.min(),
            "Down/Up Ratio": f["bwd_packets"] / f["fwd_packets"] if f["fwd_packets"] else 0,
            "Subflow Fwd Packets": f["fwd_packets"],
            "Subflow Fwd Bytes": f["fwd_bytes"],
            "Subflow Bwd Packets": f["bwd_packets"],
            "Subflow Bwd Bytes": f["bwd_bytes"]
        }
