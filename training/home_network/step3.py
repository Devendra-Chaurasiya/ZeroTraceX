import numpy as np
import pickle
from sklearn.ensemble import IsolationForest

X = np.load("../../ml/models/home/home_X_scaled.npy")

model = IsolationForest(
    n_estimators=300,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)

model.fit(X)

scores = model.decision_function(X)

with open("../../ml/models/home/home_iforest.pkl", "wb") as f:
    pickle.dump(model, f)

np.save("../../ml/models/home/home_scores.npy", scores)

print("✅ STEP-3 COMPLETED")
print("Score range:", scores.min(), scores.max())
print("Scores saved to ../../ml/models/home/home_scores.npy")
