from flask import Flask, render_template, request
import mysql.connector
import os
import hashlib
from datetime import datetime
from scanner.logic import ThreatDetector
import matplotlib.pyplot as plt
import io
import base64

#configurations
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
VT_API_KEY = "a5f8b3484503f9c13af41180b94fa33061f5925f6b6362fb46e00ce75"
MODEL_PATH = "models/anomaly_model.pkl"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize Threat Detector
detector = ThreatDetector(model_path=MODEL_PATH, api_key=VT_API_KEY)

#database connectivity
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Qwerty338939",
        database="CyberShield"
    )

# ---------------- CHART ----------------
def generate_severity_chart():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("""
        SELECT severity, COUNT(*) 
        FROM scanned_files 
        GROUP BY severity
    """)
    data = cursor.fetchall()
    cursor.close()
    db.close()

    if not data:
        data = [('Low',0), ('Medium',0), ('High',0)]

    severities = [row[0] for row in data]
    counts = [row[1] for row in data]

    plt.figure(figsize=(6,4))
    plt.bar(severities, counts, color=['green','orange','red'])
    plt.xlabel("Severity")
    plt.ylabel("Number of Files")
    plt.title("Scan Severity Distribution")
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    chart = base64.b64encode(img.getvalue()).decode()
    plt.close()
    return chart

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    file = request.files.get("file")
    if not file or file.filename == "":
        return "No file selected"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    scan_result = detector.scan(filepath)
    filename = scan_result.get("filename", file.filename)
    ml_status = scan_result.get("details", "")

    vt_stats = detector.check_virustotal(filepath)
    if vt_stats:
        if vt_stats.get("malicious", 0) > 0:
            vt_status = "Malicious"
        elif vt_stats.get("suspicious", 0) > 0:
            vt_status = "Suspicious"
        else:
            vt_status = "Safe"
    else:
        vt_status = "Unknown"

    severity_map = {"Malicious": "High", "Suspicious": "Medium", "Safe": "Low", "Unknown": "Medium"}
    severity = severity_map.get(vt_status, "Low")

    try:
        db = get_db_connection()
        cursor = db.cursor()
        filesize = os.path.getsize(filepath)
        filehash = hashlib.md5(open(filepath,'rb').read()).hexdigest()
        cursor.execute("""
            INSERT INTO scanned_files (filename, filesize, filehash, severity, scan_time, vt_status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (filename, filesize, filehash, severity, datetime.now(), vt_status))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        return f"Database error: {e}"

    # --- Generate chart and pass to template ---
    chart = generate_severity_chart()

    return render_template("result.html",
                           filename=filename,
                           status=vt_status,
                           severity=severity,
                           ml_status=ml_status,
                           chart=chart)

if __name__ == "__main__":
    app.run(debug=True)
