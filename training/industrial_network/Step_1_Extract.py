import pandas as pd
import numpy as np
import os

# =========================
# CONFIGURATION
# =========================
INPUT_FILE = r"Friday-23-02-2018.csv"
OUTPUT_FILE = r"../../ml/models/industrial/baseline_sample.csv"

CHUNK_SIZE = 500_000
TARGET_SAMPLES = 150_000
RANDOM_STATE = 42

# FINAL LOCKED FEATURE LIST
FEATURES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Down/Up Ratio",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes"
]

LABEL_COLUMN = "Label"

# =========================
# EXTRACTION LOGIC
# =========================
def extract_benign_sample():
    os.makedirs("output", exist_ok=True)
    sampled_chunks = []
    collected = 0

    print("🚀 Starting BENIGN extraction...")

    for chunk in pd.read_csv(INPUT_FILE, chunksize=CHUNK_SIZE, low_memory=False):
        chunk.columns = chunk.columns.str.strip()

        # Normalize labels
        labels = chunk[LABEL_COLUMN].astype(str).str.strip().str.lower()
        benign_chunk = chunk[labels == "benign"]

        if benign_chunk.empty:
            continue

        # Keep only required features
        benign_chunk = benign_chunk[FEATURES]

        # Replace inf / NaN
        benign_chunk = benign_chunk.replace([np.inf, -np.inf], np.nan).dropna()

        # Random sample from chunk
        remaining = TARGET_SAMPLES - collected
        if remaining <= 0:
            break

        sample_size = min(len(benign_chunk), remaining)
        sampled = benign_chunk.sample(
            n=sample_size,
            random_state=RANDOM_STATE
        )

        sampled_chunks.append(sampled)
        collected += sample_size

        print(f"✔ Collected {collected}/{TARGET_SAMPLES}")

    if collected < TARGET_SAMPLES:
        print(f"⚠ Warning: Only {collected} samples collected")

    final_df = pd.concat(sampled_chunks, ignore_index=True)
    final_df.to_csv(OUTPUT_FILE, index=False)

    print("✅ STEP-1 completed successfully")
    print(f"📁 Output saved to: {OUTPUT_FILE}")
    print(f"📊 Final sample size: {len(final_df)}")


if __name__ == "__main__":
    extract_benign_sample()
