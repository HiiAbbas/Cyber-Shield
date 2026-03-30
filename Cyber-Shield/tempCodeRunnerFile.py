from flask import Flask, render_template, request
import mysql.connector
import hashlib
import os
import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

app = Flask(__name__)

# --- CONFIGURATION ---
file_uploads = "uploads"
VT_API_KEY = "a5f8b3484503f9c13af41180b94fa33061ac16721f0e65cf66c23ee00b3f07f5"

if not os.path.exists(file_uploads):
    os.makedirs(file_uploads)

app.config["FILE_UPLOADS"] = file_uploads

# --- MACHINE LEARNING SETUP (IsolationForest) ---
# [cite: 27] Loading the ML model for anomaly detection
# Note: In a real project, you train this on thousands of files. 
# For this demo, we initialize it with dummy data so it works.
clf = IsolationForest(contamination=0.1, random_state=42)
dummy_data = [[1024], [2048], [512], [4096]] # Dummy file sizes
clf.fit(dummy_data) 

# --- DATABASE CONNECTION ---
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Qwerty338939",
    database="CyberShield",
    port=3306
)
cursor = db.cursor()

# --- HELPER FUNCTIONS ---

def hash_file(filepath):
    # [cite: 19] Hashing is required to query VirusTotal
    with open(filepath, "rb") as f:
        data = f.read()
        md5hash = hashlib.md5(data).hexdigest()
    return md5hash

def check_virustotal(file_hash):
    """
     Queries VirusTotal API to see if the hash is malicious.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        if stats['malicious'] > 0:
            return "Infected", "High"
        else:
            return "Safe", "Low"
    elif response.status_code == 404:
        return "Unknown (Not in DB)", "Medium"
    else:
        return "API Error", "Low"

def check_anomaly_ml(filepath):
    """
     Uses IsolationForest to check file size anomaly.
    """
    filesize = os.path.getsize(filepath)
    # Reshaping for the model
    prediction = clf.predict([[filesize]])
    # -1 means anomaly, 1 means normal
    if prediction[0] == -1:
        return "Abnormal Pattern (ML Alert)"
    return "Normal Pattern"

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return "No file part"
    file = request.files["file"]
    if file.filename == "":
        return "No selected file"

    # 1. Save File
    filepath = os.path.join(app.config["FILE_UPLOADS"], file.filename)
    file.save(filepath)

    # 2. Get Attributes
    filename = file.filename
    filesize = os.path.getsize(filepath)
    filehash = hash_file(filepath)

    # 3. RUN SCANS (The missing logic)
    vt_status, severity = check_virustotal(filehash) # API Check
    ml_status = check_anomaly_ml(filepath)           # ML Check

    # If ML finds an anomaly in an unknown file, raise severity
    if vt_status == "Unknown (Not in DB)" and ml_status == "Abnormal Pattern (ML Alert)":
        vt_status = "Suspicious"
        severity = "Medium"

    scan_time = datetime.now()

    # 4. Save to Database [cite: 33]
    # Note: Ensure your DB table has 'status' and 'ml_result' columns if you want to store those too
    query = "INSERT INTO scanned_files (filename, filesize, filehash, severity, scan_time) VALUES (%s, %s, %s, %s, %s)"
    cursor.execute(query, (filename, filesize, filehash, severity, scan_time))
    db.commit()

    # 5. Show Results (Visualization) [cite: 31]
    # Instead of returning a string, we return a template with data
    return render_template("result.html", 
                           filename=filename,
                           status=vt_status,
                           severity=severity,
                           ml_status=ml_status)

if __name__ == "__main__":
    app.run(debug=True)