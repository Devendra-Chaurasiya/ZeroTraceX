import pandas as pd
import numpy as np
import pickle
import os
from sklearn.preprocessing import StandardScaler

# =========================
# CONFIG
# =========================
INPUT_FILE = r"../../ml/models/industrial/baseline_sample.csv"
OUTPUT_DIR = r"../../ml/models/industrial"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# LOAD DATA
# =========================
df = pd.read_csv(INPUT_FILE)

print("🚀 STEP-2: Preprocessing started")
print(f"📊 Input shape: {df.shape}")

# =========================
# SAFETY CLEANING
# =========================
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

# =========================
# FEATURE ORDER (LOCK THIS)
# =========================
FEATURE_ORDER = list(df.columns)

with open(os.path.join(OUTPUT_DIR, "feature_order.txt"), "w") as f:
    for col in FEATURE_ORDER:
        f.write(col + "\n")

# =========================
# SCALING
# =========================
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df.values)

# =========================
# SAVE OUTPUTS
# =========================
np.save(os.path.join(OUTPUT_DIR, "X_scaled.npy"), X_scaled)

with open(os.path.join(OUTPUT_DIR, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

print("✅ STEP-2 COMPLETED")
print(f"📦 Scaled matrix shape: {X_scaled.shape}")
print("💾 Saved: scaler.pkl, X_scaled.npy, feature_order.txt")
