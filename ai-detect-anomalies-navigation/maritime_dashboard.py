import pandas as pd
import hashlib
import json
import os
from datetime import datetime, timezone
import streamlit as st
import warnings
import random
import smtplib
from email.mime.text import MIMEText
import plotly.express as px
import folium
from streamlit_folium import folium_static
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

# ---------- SUPPRESS WARNINGS ----------
warnings.simplefilter(action='ignore', category=FutureWarning)

# ---------- CONFIG ----------
log_file = "login_logs.csv"
suspicious_file = "suspicious_logs.csv"
ledger_file = "evidence_ledger.json"
alert_history_file = "alert_history.csv"
files_to_monitor = ["config.txt", "system.log"]  # Critical files
email_sender = "your_email@gmail.com"           
email_password = "your_app_password"           
email_receiver = "security_officer@gmail.com"

# ---------- HELPER FUNCTIONS ----------
def file_hash(filename):
    with open(filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def update_ledger(file, ledger_file):
    timestamp = datetime.now(timezone.utc).isoformat()
    filehash = file_hash(file)
    ledger = {}
    if os.path.exists(ledger_file):
        try:
            with open(ledger_file, "r") as f:
                ledger = json.load(f)
                if isinstance(ledger, list):
                    ledger = {item["file"]: {"hash": item["hash"], "timestamp": item["timestamp"]} for item in ledger}
        except (json.JSONDecodeError, KeyError, TypeError):
            ledger = {}

    if file not in ledger or ledger[file]["hash"] != filehash:
        ledger[file] = {"hash": filehash, "timestamp": timestamp}
        with open(ledger_file, "w") as f:
            json.dump(ledger, f, indent=4)
    return ledger

def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = email_sender
        msg['To'] = email_receiver
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(email_sender, email_password)
            server.sendmail(email_sender, email_receiver, msg.as_string())
    except Exception as e:
        st.warning(f"⚠️ Email sending failed: {e}")

def log_alert(alert_msg):
    timestamp = datetime.now().isoformat()
    alert_entry = pd.DataFrame([{"Timestamp": timestamp, "Alert": alert_msg}])
    if os.path.exists(alert_history_file):
        alert_entry.to_csv(alert_history_file, mode='a', index=False, header=False)
    else:
        alert_entry.to_csv(alert_history_file, index=False)

def send_alert(message, email=True):
    st.error(f"🚨 ALERT: {message}")
    log_alert(message)
    if email:
        send_email_alert("Maritime Cybersecurity Alert", message)

# ---------- REAL-TIME LOG MONITOR ----------
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("login_logs.csv"):
            st.experimental_rerun()

observer = Observer()
observer.schedule(LogHandler(), path='.', recursive=False)
threading.Thread(target=observer.start, daemon=True).start()

# ---------- LOAD LOGS ----------
if not os.path.exists(log_file):
    st.error(f"❌ Log file not found: {log_file}")
    st.stop()

logs = pd.read_csv(log_file)
logs['Timestamp'] = pd.to_datetime(logs['Timestamp'])

# ---------- DETECT SUSPICIOUS LOGINS ----------
def detect_failed_logins(group):
    group = group.copy()
    group["Fail_Flag"] = (group["Login_Status"] == "Fail").astype(int)
    group["Consec_Fails"] = group["Fail_Flag"].groupby((group["Fail_Flag"] == 0).cumsum()).cumsum()
    return group

logs = logs.groupby(["Ship_ID", "Username"], group_keys=False).apply(detect_failed_logins)
logs = logs.loc[:, ~logs.columns.duplicated()]

suspicious = logs[logs["Consec_Fails"] >= 3]
if not suspicious.empty:
    suspicious.to_csv(suspicious_file, index=False)
    update_ledger(suspicious_file, ledger_file)

# ---------- UPDATE FILE INTEGRITY ----------
for f in files_to_monitor:
    if os.path.exists(f):
        update_ledger(f, ledger_file)

# ---------- DASHBOARD SETUP ----------
st.set_page_config(page_title="Maritime Cybersecurity Dashboard", layout="wide")
st.title("🛳️ Maritime Cybersecurity Monitoring Dashboard")

# ---------- ALL LOGIN LOGS ----------
st.subheader("All Login Logs")
st.dataframe(logs)

# ---------- SUSPICIOUS LOGINS ----------
st.subheader("⚠️ Suspicious Login Attempts")
if not suspicious.empty:
    st.dataframe(suspicious)
    for idx, row in suspicious.iterrows():
        send_alert(f"Ship {row['Ship_ID']} | User {row['Username']} had {row['Consec_Fails']} failed logins!", email=True)
else:
    st.success("No suspicious login attempts detected.")

# ---------- FILE INTEGRITY STATUS ----------
st.subheader("📄 File Integrity Status")
ledger = {}
if os.path.exists(ledger_file):
    try:
        with open(ledger_file, "r") as f:
            ledger = json.load(f)
            if isinstance(ledger, list):
                ledger = {item["file"]: {"hash": item["hash"], "timestamp": item["timestamp"]} for item in ledger}
    except:
        ledger = {}

if ledger:
    integrity_df = pd.DataFrame.from_dict(ledger, orient="index").reset_index().rename(columns={"index": "File"})
    st.dataframe(integrity_df)
else:
    st.info("No files tracked yet.")

# ---------- GPS SPOOFING DETECTION (SIMULATED) ----------
st.subheader("🗺️ Ship GPS Positions (Simulated)")
ships_positions = {
    101: (12.9716, 77.5946),
    102: (13.0827, 80.2707),
    103: (19.0760, 72.8777)
}

m = folium.Map(location=[15, 77], zoom_start=5)
gps_df = []

for ship_id, (lat_exp, lon_exp) in ships_positions.items():
    lat_act = lat_exp + random.uniform(-0.05, 0.05)
    lon_act = lon_exp + random.uniform(-0.05, 0.05)
    distance = ((lat_exp - lat_act)**2 + (lon_exp - lon_act)**2)**0.5
    if distance <= 0.03:
        status = "OK"
        color = "green"
    else:
        status = "GPS Spoofing Detected"
        color = "red"
        send_alert(f"Ship {ship_id} GPS anomaly detected!", email=True)
    gps_df.append({"Ship_ID": ship_id, "Expected_Lat": lat_exp, "Expected_Lon": lon_exp,
                   "Actual_Lat": round(lat_act,5), "Actual_Lon": round(lon_act,5), "Status": status})
    folium.Marker([lat_act, lon_act], popup=f"Ship {ship_id}: {status}", icon=folium.Icon(color=color)).add_to(m)

folium_static(m)
st.dataframe(pd.DataFrame(gps_df))

# ---------- DUPLICATE LOGIN DETECTION ----------
st.subheader("🔁 Duplicate Login Entries")
logs['Duplicate'] = logs.duplicated(subset=["Ship_ID","Username","Timestamp"], keep=False)
duplicates = logs[logs['Duplicate']]
if not duplicates.empty:
    st.dataframe(duplicates)
    send_alert("Duplicate login entries detected!", email=True)
else:
    st.success("No duplicate login entries found.")

# ---------- THREAT SCORING ----------
def threat_score(row):
    score = 0
    if row.get('Consec_Fails', 0) >= 3: score += 2
    if row.get('Status') == "GPS Spoofing Detected": score += 3
    if row.get('Duplicate', False): score += 1
    return score

gps_status = pd.DataFrame(gps_df)[['Ship_ID','Status']]
logs = logs.merge(gps_status, on='Ship_ID', how='left')
logs['Threat_Score'] = logs.apply(threat_score, axis=1)
logs['Threat_Level'] = logs['Threat_Score'].apply(lambda x: 'High' if x >= 4 else ('Medium' if x >= 2 else 'Low'))

st.subheader("🚨 Threat Scores per Ship/User")
st.dataframe(logs[['Ship_ID','Username','Consec_Fails','Status','Duplicate','Threat_Score','Threat_Level']])

# ---------- FAILED LOGIN CHART ----------
st.subheader("📊 Failed Logins per Ship")
failed_logins = logs[logs['Login_Status'] == 'Fail'].groupby("Ship_ID").size().reset_index(name='Failed_Logins')
if not failed_logins.empty:
    fig = px.bar(failed_logins, x='Ship_ID', y='Failed_Logins', color='Failed_Logins', title="Failed Logins per Ship")
    st.plotly_chart(fig)
else:
    st.info("No failed logins yet.")


# ---------- HISTORICAL TREND ----------
st.subheader("📈 Historical Failed Login Trend")
daily_failed = logs[logs['Login_Status']=='Fail'].groupby(logs['Timestamp'].dt.date).size().reset_index(name='Failed_Logins')
if not daily_failed.empty:
    fig_trend = px.line(daily_failed, x='Timestamp', y='Failed_Logins',
                        title="Daily Failed Logins Trend", markers=True)
    st.plotly_chart(fig_trend)
else:
    st.info("No historical failed login data available.")

# ---------- THREAT SEVERITY SUMMARY ----------
st.subheader("🚦 Threat Severity Summary")
threat_counts = logs['Threat_Level'].value_counts().reset_index()
threat_counts.columns = ['Threat_Level', 'Count']
if not threat_counts.empty:
    fig_severity = px.pie(threat_counts, names='Threat_Level', values='Count',
                          title="Threat Level Distribution", color='Threat_Level',
                          color_discrete_map={'High':'red','Medium':'yellow','Low':'green'})
    st.plotly_chart(fig_severity)
else:
    st.info("No threats detected yet.")

# ---------- ALERT HISTORY ----------
st.subheader("📜 Alert History")
if os.path.exists(alert_history_file):
    alert_history = pd.read_csv(alert_history_file)
    alert_history['Timestamp'] = pd.to_datetime(alert_history['Timestamp'])
    st.dataframe(alert_history.sort_values(by='Timestamp', ascending=False))
else:
    st.info("No alerts triggered yet.")

# ---------- OPTIONAL: EXPORT REPORT ----------
st.subheader("📄 Export Report")
if st.button("Export Threat Report to Excel"):
    report_file = "threat_report.xlsx"
    logs.to_excel(report_file, index=False)
    st.success(f"Report saved as {report_file}")
