import streamlit as st
import pandas as pd
import os
import time
import psutil
import plotly.graph_objects as go

LOG_DIR = "/var/log/remote_logs/"  # Directory containing client log folders

# Keywords for detecting USB activity in kernel.log
USB_KEYWORDS = ["usb", "USB", "new high-speed", "Mass Storage", "device descriptor", "connected"]

# Keywords for detecting intrusion attempts
ATTACK_KEYWORDS = [
    "Failed password", "Invalid user", "authentication failure", "user NOT in sudoers",
    "Maximum authentication attempts exceeded", "Possible break-in attempt",
    "segfault", "buffer overflow"
]

st.set_page_config(layout="wide")
st.title("📊 **System Usage Overview**")

# Function to fetch system stats
def get_system_stats():
    return {
        "CPU Usage (%)": psutil.cpu_percent(),
        "RAM Usage (%)": psutil.virtual_memory().percent,
        "Disk Usage (%)": psutil.disk_usage('/').percent,
        "Free Disk Space (GB)": round(psutil.disk_usage('/').free / (1024**3), 2)
    }

# Fetch system stats
system_stats = get_system_stats()

# Create pie charts for system usage
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

# Function to get available hostnames (folders inside /var/log/remote_logs/)
def get_hostnames():
    return [d for d in os.listdir(LOG_DIR) if os.path.isdir(os.path.join(LOG_DIR, d))]

# Function to get log files for a specific hostname
def get_log_files(hostname):
    path = os.path.join(LOG_DIR, hostname)
    return [f for f in os.listdir(path) if f.endswith(".log")]

# Function to read the latest logs from a selected hostname and log file
def get_logs(hostname, log_file, max_lines=50):
    try:
        filename = os.path.join(LOG_DIR, hostname, log_file)
        with open(filename, "r") as f:
            logs = f.readlines()
            return logs[-max_lines:]  
    except Exception as e:
        return [f"❌ Error reading log file: {str(e)}"]

# Function to detect USB activity from kernel.log
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

# Function to detect intrusion attempts from security logs
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

# UI for selecting a hostname
hostnames = get_hostnames()
selected_host = st.selectbox("🔍 **Select a Hostname**", hostnames)

if selected_host:
    log_files = get_log_files(selected_host)
    selected_log = st.selectbox("📂 **Select a Log File**", log_files)

    log_placeholder = st.empty()
    all_logs = []

    while True:
        # Detect USB activity
        usb_alerts = detect_usb_activity()

        # Detect intrusion attempts
        intrusion_alerts = detect_intrusions()

        # Display intrusion alert on the main screen
        if intrusion_alerts:
            st.error("🚨 **Intrusion Alert Detected!**")
            for event in intrusion_alerts:
                st.write(f"⚠️ {event}")

        if selected_log:
            logs = get_logs(selected_host, selected_log, 50)  
            logs.reverse()  

            # Ensure only new lines are appended (avoid duplicate stacking)
            if logs != all_logs[:len(logs)]:  
                all_logs = logs + all_logs  
            all_logs = all_logs[:50]  

            # Display logs
            with log_placeholder.container():
                st.subheader(f"📜 Logs from {selected_host} - {selected_log}")
                df = pd.DataFrame(all_logs, columns=["Log Entry"])
                st.dataframe(df, use_container_width=True)

        # USB Alert Section (Sidebar)
        with st.sidebar:
            st.subheader("🔌 USB Activity")
            if usb_alerts:
                for event in usb_alerts:
                    st.warning(event)  
            else:
                st.success("✅ No USB devices detected.")

        time.sleep(1)  
        st.rerun()  
