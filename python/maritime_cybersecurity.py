import pandas as pd
import hashlib
import json
import os
from datetime import datetime

# -------------------------------
# 1. AIS Anomaly Detection
# -------------------------------
def detect_ais_anomalies():
    data = pd.read_csv("ais_sample.csv")

    # Duplicate ships
    duplicates = data[data.duplicated("Ship_ID", keep=False)]
    duplicates.to_csv("duplicate_ships.csv", index=False)

    # Suspicious speed
    suspicious_speed = data[data["Speed"] > 30]
    suspicious_speed.to_csv("suspicious_speed.csv", index=False)

    # Impossible jumps (>5 degrees in <5 mins for demo)
    data["Timestamp"] = pd.to_datetime(data["Timestamp"], format="%H:%M")
    data = data.sort_values(by=["Ship_ID", "Timestamp"])
    data["LatDiff"] = data.groupby("Ship_ID")["Latitude"].diff().abs()
    data["LonDiff"] = data.groupby("Ship_ID")["Longitude"].diff().abs()
    impossible_jumps = data[(data["LatDiff"] > 5) | (data["LonDiff"] > 5)]
    impossible_jumps.to_csv("impossible_jumps.csv", index=False)

    print("AIS anomalies detected and saved.")
    return ["duplicate_ships.csv", "suspicious_speed.csv", "impossible_jumps.csv"]

# -------------------------------
# 2. GPS Spoofing Detection
# -------------------------------
def detect_gps_spoofing():
    data = pd.read_csv("ais_sample.csv")

    # Assume safe range for demo: lat 10–14, lon 75–78
    spoofed = data[(data["Latitude"] < 10) | (data["Latitude"] > 14) |
                   (data["Longitude"] < 75) | (data["Longitude"] > 78)]
    spoofed.to_csv("gps_spoofed.csv", index=False)

    print("GPS spoofing detection done.")
    return ["gps_spoofed.csv"]

# -------------------------------
# 3. Suspicious Login Detection
# -------------------------------
def detect_suspicious_logins():
    # Sample log file: login_logs.csv
    # Columns: Ship_ID, Timestamp, Login_Status (Success/Fail)
    if not os.path.exists("login_logs.csv"):
        print("No login logs found, skipping.")
        return []

    logs = pd.read_csv("login_logs.csv")
    logs["FailCount"] = logs.groupby("Ship_ID")["Login_Status"].apply(
        lambda x: (x == "Fail").astype(int).cumsum()
    )
    suspicious = logs[logs["FailCount"] >= 3]
    suspicious.to_csv("suspicious_logs.csv", index=False)

    print("Suspicious login detection done.")
    return ["suspicious_logs.csv"]

# -------------------------------
# 4. Evidence Ledger
# -------------------------------
def record_to_ledger(files, ledger_file="evidence_ledger.json"):
    ledger = {}
    if os.path.exists(ledger_file):
        with open(ledger_file, "r") as f:
            ledger = json.load(f)

    for file in files:
        if os.path.exists(file):
            with open(file, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            timestamp = datetime.utcnow().isoformat() + "Z"
            ledger[file] = {"hash": file_hash, "timestamp": timestamp}
            print(f"[recorded] {file} -> {file_hash}")

    with open(ledger_file, "w") as f:
        json.dump(ledger, f, indent=4)

    print(f"Ledger updated: {ledger_file}")

# -------------------------------
# Main Orchestrator
# -------------------------------
if __name__ == "__main__":
    print("=== Maritime Cybersecurity Framework ===")

    # Run detections
    ais_files = detect_ais_anomalies()
    gps_files = detect_gps_spoofing()
    login_files = detect_suspicious_logins()

    # Combine all outputs
    all_files = ais_files + gps_files + login_files

    # Record evidence
    record_to_ledger(all_files)

    print("All anomaly detections complete ✅")
