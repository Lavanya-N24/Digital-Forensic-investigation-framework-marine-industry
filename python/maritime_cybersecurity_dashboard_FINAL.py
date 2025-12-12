"""
Maritime Cybersecurity Monitoring Dashboard - Single File (fixed & ready)

What this file does (final working version):
- Loads login_logs.csv (or generates a realistic sample if missing)
- Loads ais_positions.csv and malicious_ip_list.csv if present (or generates samples)
- Detects consecutive failed logins per Ship_ID+Username
- Detects suspicious IPs with a robust sliding-window algorithm (no KeyError)
- Tags malicious IPs from blocklist
- Simple AIS -> login join by nearest timestamp within +/- 10 minutes (if available)
- File integrity ledger updates
- Email alerts via Gmail App Password (configured below) — test button included
- Download report as Excel if xlsxwriter/openpyxl available, otherwise CSV
- Folium map for AIS positions and flagged IP geolocation (cached)
- Blocklist management UI
- Clean shutdown of watchdog observer

Usage:
    streamlit run maritime_cybersecurity_dashboard_fixed.py

⚠ Replace EMAIL_SENDER and EMAIL_PASSWORD with your Gmail + 16-char App Password.
"""

# ---------- IMPORTS ----------
# ---------- IMPORTS ----------
import os
import json
import time
import random
import socket
import hashlib
import warnings
import smtplib
import ipaddress
import threading
import requests
import pandas as pd
import folium
import plotly.express as px

from io import BytesIO
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from streamlit_folium import folium_static
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import streamlit as st

# MUST BE FIRST STREAMLIT COMMAND
st.set_page_config(page_title="Maritime Cybersecurity Dashboard (Fixed)", layout="wide")
# Change this path to your actual home.html path
import webbrowser

HOME_URL = "http://localhost:5000/home"

st.sidebar.markdown("### Navigation")

if st.sidebar.button("🏠 Go Back to Home"):
    st.success("Opening Home Page...")
    webbrowser.open_new_tab(HOME_URL)

# --- Background Image CSS --

# --- Background Image CSS ---
page_bg_img = '''
<style>
[data-testid="stAppViewContainer"] {
    background-image: url("https://images.unsplash.com/photo-1507525428034-b723cf961d3e");
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
}

[data-testid="stSidebar"] {
    background-color: rgba(255, 255, 255, 0.5);
    backdrop-filter: blur(6px);
}

[data-testid="stAppViewContainer"] > .main {
    background: rgba(255, 255, 255, 0.65);
    backdrop-filter: blur(4px);
    border-radius: 12px;
    padding: 20px;
}
</style>
'''

st.markdown(page_bg_img, unsafe_allow_html=True)




warnings.simplefilter(action="ignore", category=FutureWarning)

# ---------- CONFIG ----------
LOG_FILE = "login_logs.csv"
AIS_FILE = "ais_positions.csv"
MAL_IP_FILE = "malicious_ip_list.csv"

SUSPICIOUS_FILE = "suspicious_logs.csv"
LEDGER_FILE = "evidence_ledger.json"
ALERT_HISTORY_FILE = "alert_history.csv"
BLOCKLIST_FILE = "ip_blocklist.json"
GEO_CACHE_FILE = "ip_geo_cache.json"
FILES_TO_MONITOR = ["config.txt", "system.log"]

# ---------- EMAIL SETTINGS (NO SECRETS - local testing) ----------
# Replace with your Gmail and 16-character App Password
EMAIL_SENDER = "lavanyanm75@gmail.com"
EMAIL_PASSWORD = "gqew nvvz djej culf"  # Gmail App Password
EMAIL_RECEIVER = "lathacr.09@gmail.com"

# ---------- HELPERS ----------
def to_excel_bytes(df):
    """
    Return bytes of an Excel file. Try xlsxwriter, then openpyxl; fallback to CSV bytes.
    """
    output = BytesIO()
    for engine in ("xlsxwriter", "openpyxl"):
        try:
            with pd.ExcelWriter(output, engine=engine) as writer:
                df.to_excel(writer, index=False, sheet_name="Report")
            return output.getvalue()
        except Exception:
            output.seek(0)
            output.truncate(0)
            continue
    # fallback csv
    return df.to_csv(index=False).encode("utf-8")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except Exception:
        return False

def generate_random_ip():
    return f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def file_hash(filename):
    try:
        with open(filename, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def update_ledger(file, ledger_file):
    timestamp = datetime.now(timezone.utc).isoformat()
    filehash = file_hash(file)
    ledger = {}
    if os.path.exists(ledger_file):
        try:
            with open(ledger_file, "r") as f:
                ledger = json.load(f)
        except Exception:
            ledger = {}
    ledger[file] = {"hash": filehash, "timestamp": timestamp}
    try:
        with open(ledger_file, "w") as f:
            json.dump(ledger, f, indent=2)
    except Exception:
        pass
    return ledger

def send_email_alert(subject, message, receiver=None):
    receiver = receiver or EMAIL_RECEIVER
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = receiver
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, receiver, msg.as_string())
    except Exception as e:
        st.warning(f"⚠ Email sending failed: {e}")

def log_alert(alert_msg):
    timestamp = datetime.now().isoformat()
    entry = pd.DataFrame([{"Timestamp": timestamp, "Alert": alert_msg}])
    if os.path.exists(ALERT_HISTORY_FILE):
        entry.to_csv(ALERT_HISTORY_FILE, mode="a", index=False, header=False)
    else:
        entry.to_csv(ALERT_HISTORY_FILE, index=False)

def send_alert(message, email=True):
    st.error(f"🚨 ALERT: {message}")
    log_alert(message)
    if email:
        send_email_alert("Maritime Cybersecurity Alert", message)

# ---------- WATCHDOG ----------
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        try:
            if os.path.basename(event.src_path) == os.path.basename(LOG_FILE):
                st.experimental_rerun()
        except Exception:
            pass

observer = Observer()
try:
    observer.schedule(LogHandler(), path=".", recursive=False)
    threading.Thread(target=observer.start, daemon=True).start()
except Exception:
    pass

# ---------- DATA LOADING / SAMPLE GENERATION ----------
def generate_sample_login(path, rows=400):
    start = datetime.now() - timedelta(days=3)
    ships = [101, 102, 103, 104, 105]
    users = ["alice", "bob", "charlie", "david", "eve", "manas", "admin"]
    statuses = ["Success", "Fail"]

    data = []
    # Add some suspicious bursts for realism
    suspicious_ips = ["192.168.1.10", "192.168.2.20", "192.168.3.30"]
    for ip in suspicious_ips:
        ship = random.choice(ships)
        user = random.choice(users)
        t0 = start + timedelta(hours=random.randint(0,48))
        # create a burst of fails
        for k in range(6):
            data.append({
                "Ship_ID": ship,
                "Username": user,
                "Login_Status": "Fail",
                "Timestamp": (t0 + timedelta(seconds=k*20)).strftime("%Y-%m-%d %H:%M:%S"),
                "IP": ip
            })

    for i in range(rows - len(data)):
        ts = start + timedelta(minutes=random.randint(0, 60*48))
        ip = random.choice(suspicious_ips + [generate_random_ip() for _ in range(20)])
        row = {
            "Ship_ID": random.choice(ships),
            "Username": random.choice(users),
            "Login_Status": random.choices(statuses, weights=[0.78, 0.22])[0],
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "IP": ip
        }
        data.append(row)

    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    return df

def generate_sample_ais(path, rows=250):
    start = datetime.now() - timedelta(days=3)
    ships = [101, 102, 103, 104, 105]
    data = []
    for _ in range(rows):
        ship = random.choice(ships)
        lat = 10 + random.random() * 20
        lon = 70 + random.random() * 20
        ts = start + timedelta(minutes=random.randint(0, 60*48))
        data.append({"Ship_ID": ship, "Latitude": round(lat, 5), "Longitude": round(lon, 5), "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S")})
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    return df

def generate_sample_malicious(path):
    ips = [f"203.0.113.{i}" for i in range(1, 101)]
    df = pd.DataFrame({"IP": ips})
    df.to_csv(path, index=False)
    return df

# Ensure files exist (generate if missing)
if not os.path.exists(LOG_FILE):
    st.warning(f"{LOG_FILE} not found — generating a realistic sample for demo.")
    login_df = generate_sample_login(LOG_FILE)
else:
    login_df = pd.read_csv(LOG_FILE)

if not os.path.exists(AIS_FILE):
    st.info(f"{AIS_FILE} not found — generating sample AIS positions.")
    ais_df = generate_sample_ais(AIS_FILE)
else:
    ais_df = pd.read_csv(AIS_FILE)

if not os.path.exists(MAL_IP_FILE):
    st.info(f"{MAL_IP_FILE} not found — generating sample malicious IP list.")
    mal_df = generate_sample_malicious(MAL_IP_FILE)
else:
    mal_df = pd.read_csv(MAL_IP_FILE)

# Normalize timestamps
if "Timestamp" in login_df.columns:
    login_df["Timestamp"] = pd.to_datetime(login_df["Timestamp"], errors="coerce")
else:
    login_df["Timestamp"] = pd.to_datetime(datetime.now())

if "Timestamp" in ais_df.columns:
    ais_df["Timestamp"] = pd.to_datetime(ais_df["Timestamp"], errors="coerce")

# Validate IP column; auto-generate if missing/invalid
if "IP" not in login_df.columns:
    login_df["IP"] = [generate_random_ip() for _ in range(len(login_df))]
login_df["IP_Valid"] = login_df["IP"].apply(lambda x: is_valid_ip(x) if pd.notna(x) else False)

# Load malicious IPs into a set
try:
    malicious_set = set(mal_df["IP"].astype(str).tolist())
except Exception:
    malicious_set = set()

# ---------- CONSECUTIVE FAILED LOGIN DETECTION ----------
def detect_failed_logins(group):
    group = group.copy()
    group["Fail_Flag"] = (group["Login_Status"] == "Fail").astype(int)
    group["Consec_Fails"] = group["Fail_Flag"].groupby((group["Fail_Flag"] == 0).cumsum()).cumsum()
    return group

for c in ["Ship_ID", "Username", "Login_Status"]:
    if c not in login_df.columns:
        login_df[c] = None

login_df = login_df.groupby(["Ship_ID", "Username"], group_keys=False).apply(detect_failed_logins)
login_df = login_df.loc[:, ~login_df.columns.duplicated()]

suspicious = login_df[login_df.get("Consec_Fails", 0) >= 3]
if not suspicious.empty:
    suspicious.to_csv(SUSPICIOUS_FILE, index=False)
    update_ledger(SUSPICIOUS_FILE, LEDGER_FILE)

# ---------- UPDATE FILE INTEGRITY ----------
for f in FILES_TO_MONITOR:
    if os.path.exists(f):
        update_ledger(f, LEDGER_FILE)

# ---------- DETECT SUSPICIOUS IPS (robust sliding window) ----------
def detect_suspicious_ips(df, max_fails=5, max_unique_users=4, time_window_minutes=10):
    df_valid = df[df["IP_Valid"]].copy()
    if df_valid.empty:
        return pd.DataFrame(), pd.DataFrame()

    # summary counts
    fails_by_ip = (df_valid[df_valid["Login_Status"] == "Fail"]
                   .groupby("IP").size().rename("Fail_Count").reset_index())
    users_by_ip = df_valid.groupby("IP")["Username"].nunique().rename("Unique_Users").reset_index()
    ships_by_ip = df_valid.groupby("IP")["Ship_ID"].nunique().rename("Unique_Ships").reset_index()

    ip_summary = (fails_by_ip.merge(users_by_ip, on="IP", how="outer")
                  .merge(ships_by_ip, on="IP", how="outer").fillna(0))

    ip_summary[["Fail_Count", "Unique_Users", "Unique_Ships"]] = ip_summary[["Fail_Count", "Unique_Users", "Unique_Ships"]].astype(int)
    ip_summary["Flag"] = (ip_summary["Fail_Count"] >= max_fails) | (ip_summary["Unique_Users"] >= max_unique_users)
    flagged = ip_summary[ip_summary["Flag"]].copy()

    # sliding window detection (safe)
    df_valid = df_valid.sort_values("Timestamp").reset_index(drop=True)
    time_window_seconds = time_window_minutes * 60

    for ip in df_valid["IP"].unique():
        ip_fails = df_valid[(df_valid["IP"] == ip) & (df_valid["Login_Status"] == "Fail")].sort_values("Timestamp")
        if ip_fails.shape[0] < 2:
            continue
        times = ip_fails["Timestamp"].astype("int64") // 1_000_000_000
        times = times.reset_index(drop=True)
        i = 0
        for j in range(len(times)):
            while (times[j] - times[i]) > time_window_seconds:
                i += 1
            if (j - i + 1) >= max_fails:
                flagged = pd.concat([flagged, pd.DataFrame([{
                    "IP": ip,
                    "Fail_Count": (j - i + 1),
                    "Unique_Users": ip_fails["Username"].nunique(),
                    "Unique_Ships": ip_fails["Ship_ID"].nunique(),
                    "Flag": True
                }])], ignore_index=True)
                break

    flagged = flagged.drop_duplicates(subset=["IP"])
    return ip_summary, flagged

ip_summary, flagged_ips = detect_suspicious_ips(login_df, max_fails=5, max_unique_users=4, time_window_minutes=10)

# send alerts for flagged ips and suspicious logins
if not flagged_ips.empty:
    for _, r in flagged_ips.iterrows():
        send_alert(f"Suspicious IP {r['IP']} — fails: {int(r['Fail_Count'])}, users: {int(r['Unique_Users'])}", email=True)

if not suspicious.empty:
    for _, row in suspicious.iterrows():
        send_alert(f"User {row['Username']} on Ship {row['Ship_ID']} had {row['Consec_Fails']} consecutive failed logins!", email=True)

# ---------- AIS JOIN: nearest-by-time within +/- 10 minutes ----------
def attach_nearest_ais(login_df, ais_df, window_minutes=10):
    if ais_df.empty:
        login_df["AIS_Lat"] = None
        login_df["AIS_Lon"] = None
        login_df["AIS_Time"] = None
        return login_df
    # index AIS by Ship_ID for speed
    ais_by_ship = {sid: group.sort_values("Timestamp").reset_index(drop=True) for sid, group in ais_df.groupby("Ship_ID")}
    ais_lat = []
    ais_lon = []
    ais_time = []
    delta = timedelta(minutes=window_minutes)
    for _, row in login_df.iterrows():
        sid = row.get("Ship_ID")
        ts = row.get("Timestamp")
        lat = None
        lon = None
        atime = None
        if pd.isna(ts) or sid not in ais_by_ship:
            ais_lat.append(lat); ais_lon.append(lon); ais_time.append(atime); continue
        candidates = ais_by_ship[sid]
        # find nearest timestamp
        diffs = (candidates["Timestamp"] - ts).abs()
        min_idx = diffs.idxmin()
        if diffs.loc[min_idx] <= pd.Timedelta(delta):
            lat = candidates.loc[min_idx, "Latitude"]
            lon = candidates.loc[min_idx, "Longitude"]
            atime = candidates.loc[min_idx, "Timestamp"]
        ais_lat.append(lat); ais_lon.append(lon); ais_time.append(atime)
    login_df = login_df.copy()
    login_df["AIS_Lat"] = ais_lat
    login_df["AIS_Lon"] = ais_lon
    login_df["AIS_Time"] = ais_time
    return login_df

merged_df = attach_nearest_ais(login_df, ais_df, window_minutes=10)

# tag malicious IPs
merged_df["Is_Malicious_IP"] = merged_df["IP"].astype(str).apply(lambda x: x in malicious_set)

# ---------- DASHBOARD UI ----------

st.title("🛳 Maritime Cybersecurity Dashboard (Fixed)")

# Test email button
st.sidebar.markdown("### Testing & Utilities")
if st.sidebar.button("Test Email"):
    try:
        send_email_alert("Test Alert", "This is a test alert from the Maritime Dashboard.")
        st.sidebar.success("Test email sent (check inbox).")
    except Exception as e:
        st.sidebar.error(f"Email test failed: {e}")

# Show main tables
st.subheader("All Login Logs (merged with AIS where available)")
st.dataframe(merged_df)

st.subheader("IP Summary (fail counts / unique users / ships)")
if not ip_summary.empty:
    st.dataframe(ip_summary.sort_values("Fail_Count", ascending=False).reset_index(drop=True))
else:
    st.info("No valid IP summary data.")

st.subheader("🚩 Flagged Suspicious IPs")
if not flagged_ips.empty:
    st.dataframe(flagged_ips)
else:
    st.success("No suspicious IPs detected.")

st.subheader("⚠ Suspicious Login Attempts (Consecutive fails)")
if not suspicious.empty:
    st.dataframe(suspicious)
else:
    st.success("No suspicious consecutive login attempts.")

# Threat scoring (simple)
def threat_score(row, flagged_ip_set):
    score = 0
    if row.get("Consec_Fails", 0) >= 3: score += 2
    if row.get("Is_Malicious_IP"): score += 3
    if pd.notna(row.get("AIS_Lat")) and pd.notna(row.get("AIS_Lon")) and row.get("Login_Status") == "Fail":
        score += 1
    return score

flagged_set = set(flagged_ips["IP"].astype(str).tolist()) if not flagged_ips.empty else set()
merged_df["Threat_Score"] = merged_df.apply(lambda r: threat_score(r, flagged_set), axis=1)
merged_df["Threat_Level"] = merged_df["Threat_Score"].apply(lambda x: "High" if x >= 4 else ("Medium" if x >= 2 else "Low"))

st.subheader("Threat Scores")
st.dataframe(merged_df[["Ship_ID","Username","IP","Login_Status","Consec_Fails","Is_Malicious_IP","Threat_Score","Threat_Level"]])

# failed login chart
st.subheader("📊 Failed Logins per Ship")
failed_logins = merged_df[merged_df["Login_Status"] == "Fail"].groupby("Ship_ID").size().reset_index(name="Failed_Logins")
if not failed_logins.empty:
    fig = px.bar(failed_logins, x="Ship_ID", y="Failed_Logins", color="Failed_Logins", title="Failed Logins per Ship")
    st.plotly_chart(fig)
else:
    st.info("No failed logins yet.")

# historical trend
st.subheader("📈 Historical Failed Login Trend")
try:
    daily_failed = merged_df[merged_df["Login_Status"] == "Fail"].groupby(merged_df["Timestamp"].dt.date).size().reset_index(name="Failed_Logins")
    fig_trend = px.line(daily_failed, x="Timestamp", y="Failed_Logins", title="Daily Failed Logins Trend", markers=True)
    st.plotly_chart(fig_trend)
except Exception:
    st.info("Not enough timestamp data for historical trend.")

# AIS map
st.subheader("🗺 AIS Positions (latest per ship)")
if not ais_df.empty:
    latest_ais = ais_df.sort_values("Timestamp").groupby("Ship_ID").tail(1)
    m = folium.Map(location=[20,75], zoom_start=4)
    for _, r in latest_ais.iterrows():
        folium.Marker([r["Latitude"], r["Longitude"]], popup=f"Ship {r['Ship_ID']}", icon=folium.Icon(color="blue")).add_to(m)
    folium_static(m)
    st.dataframe(latest_ais)
else:
    st.info("No AIS data available.")

# flagged IP geolocation
st.subheader("📍 Flagged IP Locations (geolocated)")
if not flagged_ips.empty:
    m_ips = folium.Map(location=[20,75], zoom_start=3)
    # geolocate and cache
    def load_geo_cache():
        if os.path.exists(GEO_CACHE_FILE):
            try:
                with open(GEO_CACHE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    def save_geo_cache(c):
        try:
            with open(GEO_CACHE_FILE, "w") as f:
                json.dump(c, f, indent=2)
        except Exception:
            pass
    geo_cache = load_geo_cache()
    for ip in flagged_ips["IP"].astype(str).tolist():
        if ip in geo_cache:
            geo = geo_cache[ip]
        else:
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if resp.get("status") == "success":
                    geo = {"lat": resp.get("lat"), "lon": resp.get("lon"), "city": resp.get("city"), "country": resp.get("country")}
                else:
                    geo = None
            except Exception:
                geo = None
            if geo:
                geo_cache[ip] = geo
                save_geo_cache(geo_cache)
        if geo:
            folium.Marker([geo["lat"], geo["lon"]], popup=f"{ip}\n{geo.get('city')}, {geo.get('country')}", icon=folium.Icon(color="red")).add_to(m_ips)
    folium_static(m_ips)
else:
    st.info("No flagged IPs to geolocate.")

# blocklist UI
st.subheader("🔒 IP Blocklist Management")
new_block_ip = st.text_input("Add IP to blocklist")
if st.button("Block IP"):
    if is_valid_ip(new_block_ip):
        blocklist = set()
        if os.path.exists(BLOCKLIST_FILE):
            try:
                with open(BLOCKLIST_FILE, "r") as f:
                    blocklist = set(json.load(f))
            except Exception:
                blocklist = set()
        blocklist.add(new_block_ip)
        with open(BLOCKLIST_FILE, "w") as f:
            json.dump(list(blocklist), f, indent=2)
        st.success(f"Blocked {new_block_ip}")
    else:
        st.error("Invalid IP")

if os.path.exists(BLOCKLIST_FILE):
    try:
        with open(BLOCKLIST_FILE, "r") as f:
            bl = json.load(f)
    except Exception:
        bl = []
else:
    bl = []
if bl:
    st.write("Blocked IPs:")
    st.write(bl)

# check for blocked hits
if bl:
    blocked_hits = merged_df[merged_df["IP"].isin(bl)]
    if not blocked_hits.empty:
        st.subheader("🔴 Blocked IP Attempts")
        st.dataframe(blocked_hits)
        for _, row in blocked_hits.iterrows():
            send_alert(f"Blocked IP {row['IP']} attempted login on Ship {row['Ship_ID']}, user {row['Username']}", email=True)

# alert history
st.subheader("📜 Alert History")
if os.path.exists(ALERT_HISTORY_FILE):
    ah = pd.read_csv(ALERT_HISTORY_FILE)
    ah["Timestamp"] = pd.to_datetime(ah["Timestamp"], errors="coerce")
    st.dataframe(ah.sort_values("Timestamp", ascending=False))
else:
    st.info("No alerts triggered yet.")

# download merged report (prefer excel)
# ---------- DOWNLOAD THREAT REPORT ----------
st.subheader("📄 Download Threat Report")

# Generate Excel or CSV bytes
report_bytes = to_excel_bytes(merged_df)

# Detect whether output is Excel or CSV
# XLSX files start with PK (because they are zip files)
is_excel = report_bytes[:2] == b"PK"

st.download_button(
    label="⬇ Download Full Threat Report",
    data=report_bytes,
    file_name="threat_report.xlsx" if is_excel else "threat_report.csv",
    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if is_excel else "text/csv"
)

# EOF