import pandas as pd
import hashlib
import json
import os
from datetime import datetime, timezone

# ---------- CONFIG ----------
log_file = "login_logs.csv"
suspicious_file = "suspicious_logs.csv"
ledger_file = "evidence_ledger.json"

# ---------- STEP 1: Detect suspicious login attempts ----------
if not os.path.exists(log_file):
    print(f"❌ Log file not found: {log_file}")
    exit()

# Read the login logs
logs = pd.read_csv(log_file)

# Detect consecutive failed logins
def detect_failed_logins(group):
    group = group.copy()  # Avoid SettingWithCopyWarning
    group["Fail_Flag"] = (group["Login_Status"] == "Fail").astype(int)
    group["Consec_Fails"] = group["Fail_Flag"].groupby((group["Fail_Flag"] == 0).cumsum()).cumsum()
    return group

# Apply function per Ship_ID and Username
logs = logs.groupby(["Ship_ID", "Username"], group_keys=False).apply(detect_failed_logins)

# Remove duplicate columns added by groupby/apply
logs = logs.loc[:, ~logs.columns.duplicated()]

# Suspicious if 3 or more consecutive failures
suspicious = logs[logs["Consec_Fails"] >= 3]

if not suspicious.empty:
    print("⚠️ Suspicious login attempts detected:")
    print(suspicious)
    suspicious.to_csv(suspicious_file, index=False)
    print(f"✅ Suspicious logs saved to {suspicious_file}")
else:
    print("✅ No suspicious login attempts found.")
    suspicious = None

# ---------- STEP 2: Record suspicious file in ledger ----------
def file_hash(filename):
    """Compute SHA256 hash of a file"""
    with open(filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def update_ledger(file, ledger_file):
    """Update ledger with file hash & timestamp"""
    if not os.path.exists(file):
        print(f"[skip] not found: {file}")
        return

    # Use timezone-aware UTC
    timestamp = datetime.now(timezone.utc).isoformat()
    filehash = file_hash(file)

    # Load or create ledger
    ledger = {}
    if os.path.exists(ledger_file):
        with open(ledger_file, "r") as f:
            try:
                ledger = json.load(f)
                # Handle if ledger is a list instead of dict
                if isinstance(ledger, list):
                    ledger = {
                        item["file"]: {"hash": item["hash"], "timestamp": item["timestamp"]}
                        for item in ledger
                        if "file" in item and "hash" in item and "timestamp" in item
                    }
            except json.JSONDecodeError:
                print("[warn] Ledger file was empty or invalid. Recreating...")
                ledger = {}

    # Record new entry if not already present or hash changed
    if file not in ledger or ledger[file]["hash"] != filehash:
        ledger[file] = {"hash": filehash, "timestamp": timestamp}
        with open(ledger_file, "w") as f:
            json.dump(ledger, f, indent=4)
        print(f"[recorded] {file} -> {filehash}")
    else:
        print(f"[verified] {file} already in ledger, no change.")

# Record suspicious logs if they exist
if suspicious is not None and os.path.exists(suspicious_file):
    update_ledger(suspicious_file, ledger_file)
