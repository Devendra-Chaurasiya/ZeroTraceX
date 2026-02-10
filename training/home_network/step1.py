import pandas as pd
import numpy as np
import os

INPUT_FILE = "flow_features.csv"
OUTPUT_DIR = "../../ml/models/home"
OUTPUT_FILE = f"{OUTPUT_DIR}/home_step1_clean.csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

df = pd.read_csv(INPUT_FILE)

# Drop label column if exists
df = df.drop(columns=[c for c in df.columns if c.lower() == "label"], errors="ignore")

# Replace inf / nan
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Select numeric only
df = df.select_dtypes(include=[np.number])

df.to_csv(OUTPUT_FILE, index=False)

print("✅ STEP-1 COMPLETED")
print("Rows:", len(df))
print("Columns:", len(df.columns))
print("Saved:", OUTPUT_FILE)
