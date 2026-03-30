import os
import joblib
import math
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------- PATHS ----------------
UPLOADS_DIR = "uploads"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_model.pkl")

# Ensure directories exist
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------- FEATURE EXTRACTION ----------------
def extract_features(file_path):
    """
    Extract 3 real features from a file:
    1. File size (bytes)
    2. Shannon entropy
    3. Max byte frequency ratio
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return None

        file_size = len(data)

        counter = Counter(data)
        probabilities = [c / file_size for c in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probabilities)

        max_byte_freq = max(counter.values()) / file_size

        return [file_size, entropy, max_byte_freq]

    except Exception as e:
        print(f"[ERROR] Feature extraction failed for {file_path}: {e}")
        return None

# ---------------- TRAIN MODEL ----------------
def train():
    print(f"[INFO] Reading files from '{UPLOADS_DIR}' for training...")

    X_train = []

    for filename in os.listdir(UPLOADS_DIR):
        file_path = os.path.join(UPLOADS_DIR, filename)

        if os.path.isfile(file_path):
            features = extract_features(file_path)
            if features:
                X_train.append(features)
                print(f"[OK] Features extracted: {filename}")

    if len(X_train) < 5:
        raise RuntimeError(
            "[ERROR] Not enough training files. "
            "Add at least 5 different files to the uploads folder."
        )

    # ---------------- SCALING ----------------
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # ---------------- MODEL ----------------
    print("[INFO] Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_scaled)

    # ---------------- SAVE MODEL + SCALER ----------------
    joblib.dump((model, scaler), MODEL_PATH)

    print("===================================")
    print("✅ Training completed successfully")
    print(f"📦 Model saved at: {MODEL_PATH}")
    print("📊 Features used: [file_size, entropy, max_byte_freq]")
    print("===================================")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    train()
