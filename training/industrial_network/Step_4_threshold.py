import numpy as np
import pickle
import json

# =========================
# LOAD DATA
# =========================
scores = np.load("../../ml/models/industrial/anomaly_scores.npy")

# =========================
# THRESHOLD SELECTION
# =========================
THRESHOLD_PERCENTILE = 1
threshold = np.percentile(scores, THRESHOLD_PERCENTILE)

# =========================
# SAVE THRESHOLD
# =========================
config = {
    "threshold_percentile": THRESHOLD_PERCENTILE,
    "anomaly_score_threshold": float(threshold)
}

with open("../../ml/models/industrial/threshold.json", "w") as f:
    json.dump(config, f, indent=4)

print("🚀 STEP-4 COMPLETED")
print(f"🔻 Threshold percentile: {THRESHOLD_PERCENTILE}%")
print(f"📉 Anomaly score threshold: {threshold:.6f}")
print("💾 Saved: threshold.json")
