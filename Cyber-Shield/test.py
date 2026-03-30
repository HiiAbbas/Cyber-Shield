import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, request
import mysql.connector
import numpy as np
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# Folder to save uploaded files
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["FILE_UPLOADS"] = UPLOAD_FOLDER

# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Qwerty338939",
    database="CyberShield",
    port=3306
)
cursor = db.cursor()

# Dummy scikit-learn model for anomaly detection
# In real scenario, train with real file features
model = IsolationForest(contamination=0.1)
# Dummy training with random feature (here we use file size as single feature)
dummy_train = np.random.randint(1000, 500000, size=(100,1))
model.fit(dummy_train)

# Function to calculate MD5 hash
def hash_file_md5(filepath):
    md5_hash = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Function to assign severity based on file type + anomaly
def assign_severity(file_ext, anomaly_score):
    # File type rules
    if file_ext in ["exe", "dll", "bat"]:
        base = "High"
    elif file_ext in ["zip", "rar"]:
        base = "Medium"
    else:
        base = "Low"
    
    # Increase severity if anomaly detected
    if anomaly_score == -1:  # IsolationForest returns -1 for anomalies
        if base == "Low":
            return "Medium"
        elif base == "Medium":
            return "High"
        else:
            return "High"
    return base

# Route to handle file scanning
@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return "No file part"
    
    file = request.files["file"]
    if file.filename == "":
        return "No selected file"
    
    # Save file to uploads folder
    filepath = os.path.join(app.config["FILE_UPLOADS"], file.filename)
    file.save(filepath)
    
    # Compute MD5 hash
    file_hash = hash_file_md5(filepath)
    
    # Get file size
    file_size = os.path.getsize(filepath)
    
    # Dummy anomaly detection using file size as feature
    anomaly_score = model.predict(np.array([[file_size]]))[0]
    
    # Assign severity based on file type and anomaly
    file_ext = file.filename.lower().split(".")[-1]
    severity = assign_severity(file_ext, anomaly_score)
    
    # Insert into database
    cursor.execute("""
        INSERT INTO files (FILE_NAME, FILE_SIZE, FILE_HASH, SEVERITY, TIME_STAMP)
        VALUES (%s, %s, %s, %s, %s)
    """, (file.filename, file_size, file_hash, severity, datetime.now()))
    db.commit()
    
    return f"""
    File scanned successfully!<br>
    Name: {file.filename}<br>
    Size: {file_size} bytes<br>
    MD5: {file_hash}<br>
    Severity: {severity}<br>
    """

if __name__ == "__main__":
    app.run(debug=True)
