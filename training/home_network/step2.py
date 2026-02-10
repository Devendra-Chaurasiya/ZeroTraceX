import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import StandardScaler

INPUT_FILE = "../../ml/models/home/home_step1_clean.csv"

df = pd.read_csv(INPUT_FILE)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)

with open("../../ml/models/home/home_scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

np.save("../../ml/models/home/home_X_scaled.npy", X_scaled)

with open("../../ml/models/home/home_feature_order.txt", "w") as f:
    for col in df.columns:
        f.write(col + "\n")

print("✅ STEP-2 COMPLETED")
print("Scaled shape:", X_scaled.shape)
