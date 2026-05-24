import streamlit as st
import pandas as pd
import os
import time
import psutil
import plotly.graph_objects as go
import subprocess
import json
import pwd

LOG_DIR = "/var/log/remote_logs/"
CLEARED_USB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cleared_usb_events.json")

USB_KEYWORDS = ["usb", "USB", "new high-speed", "Mass Storage", "device descriptor", "connected"]

ATTACK_KEYWORDS = [
	"Failed password", "Invalid user", "authentication failure", "user NOT in sudoers",
	"Maximum authentication attempts exceeded", "Possible break-in attempt",
	"segfault", "buffer overflow"
]

st.set_page_config(layout="wide")
st.title("📊 **System Usage Overview**")

# ─── USB Clear Persistence ─────────────────────────────────────────────────────

def load_cleared_events():
	if os.path.exists(CLEARED_USB_FILE):
    	try:
        	with open(CLEARED_USB_FILE, "r") as f:
            	return set(json.load(f))
    	except Exception:
        	return set()
	return set()

def save_cleared_events(events: set):
	with open(CLEARED_USB_FILE, "w") as f:
    	json.dump(list(events), f)

# ─── System Stats ──────────────────────────────────────────────────────────────

def get_system_stats():
	return {
    	"CPU Usage (%)": psutil.cpu_percent(),
    	"RAM Usage (%)": psutil.virtual_memory().percent,
    	"Disk Usage (%)": psutil.disk_usage('/').percent,
    	"Free Disk Space (GB)": round(psutil.disk_usage('/').free / (1024**3), 2)
	}

system_stats = get_system_stats()

col1, col2, col3, col4 = st.columns(4)

with col1:
	st.markdown("💻 **CPU Usage**")
	fig_cpu = go.Figure(go.Pie(
    	labels=["Used", "Free"],
    	values=[system_stats["CPU Usage (%)"], 100 - system_stats["CPU Usage (%)"]],
    	hole=0.4,
    	marker=dict(colors=["blue", "lightgray"])
	))
	st.plotly_chart(fig_cpu, use_container_width=True)

with col2:
	st.markdown("🖥 **RAM Usage**")
	fig_ram = go.Figure(go.Pie(
    	labels=["Used", "Free"],
    	values=[system_stats["RAM Usage (%)"], 100 - system_stats["RAM Usage (%)"]],
    	hole=0.4,
    	marker=dict(colors=["red", "lightgray"])
	))
	st.plotly_chart(fig_ram, use_container_width=True)

with col3:
	st.markdown("🛠 **Disk Usage**")
	fig_disk = go.Figure(go.Pie(
    	labels=["Used", "Free"],
    	values=[system_stats["Disk Usage (%)"], 100 - system_stats["Disk Usage (%)"]],
    	hole=0.4,
    	marker=dict(colors=["green", "lightgray"])
	))
	st.plotly_chart(fig_disk, use_container_width=True)

with col4:
	st.markdown("📁 **Free Disk Space**")
	st.metric("Available", f"{system_stats['Free Disk Space (GB)']} GB")

st.title("🛡️ SIEM Dashboard - Network & Security Monitoring")

# ─── Log Helpers ───────────────────────────────────────────────────────────────

def get_hostnames():
	return [d for d in os.listdir(LOG_DIR) if os.path.isdir(os.path.join(LOG_DIR, d))]

def get_log_files(hostname):
	path = os.path.join(LOG_DIR, hostname)
	return [f for f in os.listdir(path) if f.endswith(".log")]

def get_logs(hostname, log_file, max_lines=50):
	try:
    	filename = os.path.join(LOG_DIR, hostname, log_file)
    	with open(filename, "r") as f:
        	logs = f.readlines()
        	return logs[-max_lines:]
	except Exception as e:
    	return [f"❌ Error reading log file: {str(e)}"]

def detect_usb_activity():
	usb_events = []
	for hostname in get_hostnames():
    	log_path = os.path.join(LOG_DIR, hostname, "kernel.log")
    	if os.path.exists(log_path):
        	try:
            	with open(log_path, "r") as f:
                	logs = f.readlines()
                	for log in logs[-50:]:
                    	if any(keyword in log for keyword in USB_KEYWORDS):
                        	usb_events.insert(0, f"🔌 {hostname}: {log.strip()}")
        	except Exception as e:
            	usb_events.insert(0, f"❌ Error reading kernel.log for {hostname}: {str(e)}")
	return usb_events

def detect_intrusions():
	attack_events = []
	for hostname in get_hostnames():
    	for log_file in ["auth.log", "secure.log", "kernel.log", "syslog", "sudo.log"]:
        	log_path = os.path.join(LOG_DIR, hostname, log_file)
        	if os.path.exists(log_path):
            	try:
                	with open(log_path, "r") as f:
                    	logs = f.readlines()
                    	for log in logs[-50:]:
                        	if any(keyword in log for keyword in ATTACK_KEYWORDS):
                            	attack_events.insert(0, f"🚨 {hostname}: {log.strip()}")
            	except Exception as e:
                	attack_events.insert(0, f"❌ Error reading {log_file} for {hostname}: {str(e)}")
	return attack_events

# ─── Host Selector ─────────────────────────────────────────────────────────────

hostnames = get_hostnames()
selected_host = st.selectbox("🔍 **Select a Hostname**", hostnames)

if selected_host:
	log_files = get_log_files(selected_host)
	selected_log = st.selectbox("📂 **Select a Log File**", log_files)

	log_placeholder = st.empty()
	all_logs = []

	# ─── Main Loop ─────────────────────────────────────────────────────────────

	while True:
    	usb_alerts = detect_usb_activity()
    	intrusion_alerts = detect_intrusions()

    	if intrusion_alerts:
        	st.error("🚨 **Intrusion Alert Detected!**")
        	for event in intrusion_alerts:
            	st.write(f"⚠️ {event}")

    	if selected_log:
        	logs = get_logs(selected_host, selected_log, 50)
        	logs.reverse()

        	if logs != all_logs[:len(logs)]:
            	all_logs = logs + all_logs
        	all_logs = all_logs[:50]

        	with log_placeholder.container():
            	st.subheader(f"📜 Logs from {selected_host} - {selected_log}")
            	df = pd.DataFrame(all_logs, columns=["Log Entry"])
            	st.dataframe(df, use_container_width=True)

    	# ─── Sidebar ───────────────────────────────────────────────────────────

    	with st.sidebar:
   	 
        	# Fix Permissions
        	st.subheader("🔧 Host Permissions")
        	if st.button("🔑 Fix Permissions"):
            	try:
                	current_user = pwd.getpwuid(os.getuid()).pw_name
                	subprocess.run(["sudo", "chown", "-R", "syslog:adm", LOG_DIR], check=True)
                	subprocess.run(["sudo", "chmod", "-R", "755", LOG_DIR], check=True)
                	st.success(f"✅ Permissions fixed on {LOG_DIR}")
            	except subprocess.CalledProcessError as e:
                	st.error(f"❌ Failed: {str(e)}")
            	except Exception as e:
                	st.error(f"❌ Error: {str(e)}")

        	# USB Activity
        	st.subheader("🔌 USB Activity")
        	cleared_events = load_cleared_events()
        	filtered_usb_alerts = [e for e in usb_alerts if e not in cleared_events]

        	if filtered_usb_alerts:
            	if st.button("🗑️ Clear USB Alerts"):
                	cleared_events.update(filtered_usb_alerts)
                	save_cleared_events(cleared_events)
                	st.rerun()
            	for event in filtered_usb_alerts:
                	st.warning(event)
        	else:
            	st.success("✅ No USB devices detected.")

        	st.divider()

        	# Restore cleared USB alerts
        	st.subheader("♻️ Restore Alerts")
        	if st.button("🔄 Restore All USB Alerts"):
            	save_cleared_events(set())
            	st.rerun()

        	st.divider()


    	time.sleep(1)
    	st.rerun()
