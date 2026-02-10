import numpy as np
import pickle
from sklearn.ensemble import IsolationForest

# =========================
# LOAD DATA
# =========================
X = np.load("../../ml/models/industrial/X_scaled.npy")

print("🚀 STEP-3: Isolation Forest Training Started")
print(f"📊 Training data shape: {X.shape}")

# =========================
# MODEL CONFIGURATION
# =========================
model = IsolationForest(
    n_estimators=300,
    max_samples=0.8,
    contamination=0.01,   # conservative assumption
    random_state=42,
    n_jobs=-1
)

# =========================
# TRAIN MODEL
# =========================
model.fit(X)

# =========================
# SAVE MODEL
# =========================
with open("../../ml/models/industrial/isolation_forest.pkl", "wb") as f:
    pickle.dump(model, f)

# =========================
# STORE ANOMALY SCORES
# =========================
scores = model.decision_function(X)
np.save("../../ml/models/industrial/anomaly_scores.npy", scores)

print("✅ STEP-3 COMPLETED")
print(f"📉 Score range: min={scores.min():.4f}, max={scores.max():.4f}")
print("💾 Saved: isolation_forest.pkl, anomaly_scores.npy")
