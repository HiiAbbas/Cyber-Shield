import os
import joblib
import math
import hashlib
import requests
import numpy as np
from collections import Counter

class ThreatDetector:
    def __init__(self, model_path, api_key=None):
        self.model_path = model_path
        self.api_key = api_key
        self.model = None
        self.scaler = None
        self.load_model()

    def load_model(self):
        """Loads AI model and scaler from models folder."""
        try:
            self.model, self.scaler = joblib.load(self.model_path)
            print(f"✅ AI Model & Scaler loaded from {self.model_path}")
        except Exception as e:
            print(f"⚠️ Could not load model. AI scan skipped. ({e})")

    def extract_features(self, file_path):
        """Extracts Size, Entropy, Max Byte Frequency as features."""
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

            return np.array([[file_size, entropy, max_byte_freq]])
        except Exception as e:
            print(f"[ERROR] Feature extraction failed: {e}")
            return None

    def check_virustotal(self, file_path):
        """Returns a consistent dict of VirusTotal stats."""
        if not self.api_key:
            return {"malicious": 0, "suspicious": 0}

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats
            else:
                return {"malicious": 0, "suspicious": 0}
        except Exception as e:
            print(f"[ERROR] VirusTotal API error: {e}")
            return {"malicious": 0, "suspicious": 0}

    def scan(self, file_path):
        """Main scan function used in app.py"""
        result = {
            "filename": os.path.basename(file_path),
            "status": "Safe",
            "details": "No threats detected.",
            "source": "Local Analysis"
        }

        # 1️⃣ VirusTotal Check
        vt_stats = self.check_virustotal(file_path)
        if vt_stats.get('malicious', 0) > 0:
            result["status"] = "Malicious"
            result["details"] = f"Flagged by {vt_stats['malicious']} AV vendors"
            result["source"] = "VirusTotal Cloud"
            return result
        elif vt_stats.get('suspicious', 0) > 0:
            result["status"] = "Suspicious"
            result["details"] = f"Marked suspicious by VirusTotal"
            result["source"] = "VirusTotal Cloud"

        # 2️⃣ AI Check
        if self.model and self.scaler:
            features = self.extract_features(file_path)
            if features is not None:
                features_scaled = self.scaler.transform(features)
                prediction = self.model.predict(features_scaled)[0]
                if prediction == -1:
                    result["status"] = "Suspicious"
                    result["details"] = "AI detected anomalous file structure"
                    result["source"] = "CyberShield AI"

        return result

    # ======================URL SCANNING ======================
    def check_virustotal_url(self, url):
        """
        Scans a URL using VirusTotal API.
        Returns a dict with malicious and suspicious counts.
        Note: ML is not used for URLs because the model is file-based.
        """

        if not self.api_key:
            return {"malicious": 0, "suspicious": 0}

        headers = {"x-apikey": self.api_key}

        try:
            # Step 1: Submit URL for analysis
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )

            if submit_response.status_code != 200:
                return {"malicious": 0, "suspicious": 0}

            # Step 2: Get analysis ID
            url_id = submit_response.json()["data"]["id"]

            # Step 3: Fetch analysis report
            report_response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )

            if report_response.status_code == 200:
                stats = report_response.json() \
                    .get("data", {}) \
                    .get("attributes", {}) \
                    .get("last_analysis_stats", {})

                return stats

            return {"malicious": 0, "suspicious": 0}

        except Exception as e:
            print(f"[ERROR] VirusTotal URL scan failed: {e}")
            return {"malicious": 0, "suspicious": 0}
