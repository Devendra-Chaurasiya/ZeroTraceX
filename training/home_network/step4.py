import numpy as np
import json

scores = np.load("../../ml/models/home/home_scores.npy")

threshold = np.percentile(scores, 1)

with open("../../ml/models/home/home_threshold.json", "w") as f:
    json.dump({"threshold": float(threshold)}, f, indent=2)

print("✅ STEP-4 COMPLETED")
print("Threshold:", threshold)
print("Threshold saved to ../../ml/models/home/home_threshold.json")
