# evidence_integrity.py
import hashlib
import json
import os
from datetime import datetime

# Config: folder with your CSV outputs
PROJECT_DIR = r"C:\Users\manas\python"
LEDGER_FILE = os.path.join(PROJECT_DIR, "evidence_ledger.json")

# Files to include in ledger (only those that exist)
files_to_record = [
    "duplicate_ships.csv",
    "suspicious_speed.csv",
    "gps_spoofed.csv",
    "impossible_jumps.csv",
    "suspicious_logs.csv"
]

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_ledger():
    if not os.path.exists(LEDGER_FILE):
        return []
    with open(LEDGER_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_ledger(ledger):
    with open(LEDGER_FILE, "w", encoding="utf-8") as f:
        json.dump(ledger, f, indent=2)

def latest_hash(ledger):
    if not ledger:
        return None
    return ledger[-1]["record_hash"]

def make_record(filename, filehash, prev_hash, description=""):
    timestamp = datetime.utcnow().isoformat() + "Z"
    payload = {
        "filename": filename,
        "filehash": filehash,
        "timestamp": timestamp,
        "prev_record_hash": prev_hash or "",
        "description": description,
    }
    # record hash — hash of payload JSON string (deterministic)
    record_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    record_hash = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
    payload["record_hash"] = record_hash
    return payload

def record_files():
    ledger = load_ledger()
    prev = latest_hash(ledger)
    any_recorded = False

    for fname in files_to_record:
        path = os.path.join(PROJECT_DIR, fname)
        if not os.path.exists(path):
            print(f"[skip] not found: {fname}")
            continue
        filehash = sha256_of_file(path)
        # Check if this file+hash already recorded last time
        already = next((r for r in ledger if r["filename"] == fname and r["filehash"] == filehash), None)
        if already:
            print(f"[ok] already recorded and unchanged: {fname}")
            prev = latest_hash(ledger)
            continue
        # create record
        description = f"Auto-recorded evidence file: {fname}"
        rec = make_record(fname, filehash, prev, description=description)
        ledger.append(rec)
        prev = rec["record_hash"]
        print(f"[recorded] {fname} -> {rec['record_hash']}")
        any_recorded = True

    if any_recorded:
        save_ledger(ledger)
        print(f"Ledger updated: {LEDGER_FILE}")
    else:
        print("No new files recorded.")

def verify_files():
    ledger = load_ledger()
    if not ledger:
        print("No ledger found (nothing to verify).")
        return
    # Build latest mapping of filename -> latest filehash recorded
    latest_for_file = {}
    for rec in ledger:
        latest_for_file[rec["filename"]] = rec["filehash"]

    tampered = []
    for fname, expected_hash in latest_for_file.items():
        path = os.path.join(PROJECT_DIR, fname)
        if not os.path.exists(path):
            tampered.append((fname, "MISSING"))
            continue
        current_hash = sha256_of_file(path)
        if current_hash != expected_hash:
            tampered.append((fname, "HASH_MISMATCH"))
    if not tampered:
        print("All recorded files verified OK (no tampering detected).")
    else:
        print("Tampering or missing files detected:")
        for t in tampered:
            print(" -", t[0], t[1])

if __name__ == "__main__":
    print("1) Recording current CSV outputs to ledger (if new) ...")
    record_files()
    print("\n2) Verifying recorded files against current filesystem ...")
    verify_files()
