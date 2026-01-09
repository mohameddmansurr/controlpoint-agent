import streamlit as st
import pandas as pd
import json
import os
import agent  # Import the agent logic

# Configuration
DATA_FILE = "cve_data.json"

st.set_page_config(page_title="ControlPoint Threat Intel", layout="wide")

# --- Sidebar ---
st.sidebar.image("https://img.icons8.com/color/96/industrial-control.png", width=50)
st.sidebar.title("ControlPoint")
st.sidebar.markdown("Automated OT Threat Intelligence")

if st.sidebar.button("Run Agent Scan Now"):
    with st.spinner("Agent is scanning global NVD database..."):
        agent.run_agent()
    st.success("Scan Complete!")
    st.rerun()

# --- Main Interface ---
st.title("🛡️ Live OT Threat Dashboard")

# Load Data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
else:
    data = []

if data:
    # Convert to DataFrame for easier handling
    df = pd.DataFrame(data)
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total OT Threats Detected", len(df))
    col2.metric("High Severity (>8.0)", len(df[pd.to_numeric(df['cvss'], errors='coerce') > 8.0]))
    col3.metric("Latest Update", df['timestamp'].max()[:16].replace('T', ' '))

    st.markdown("---")

# Display Threats
    st.subheader("⚠️ Critical Industrial Vulnerabilities")
    
    for index, row in df.iterrows():
        # Dynamic Severity Color
        score = float(row['cvss']) if row['cvss'] != 'N/A' else 0
        severity_color = "red" if score >= 9.0 else "orange" if score >= 7.0 else "green"
        
        # New: Confidence handling
        conf = row.get('confidence', 0) # Handle old data without confidence
        
        with st.expander(f"[{row['cve_id']}] CVSS: {row['cvss']} - {row['ai_insight']}"):
            col_a, col_b = st.columns([1, 3])
            
            with col_a:
                st.markdown(f"**Severity:** :{severity_color}[{row['cvss']}]")
                # Visual Confidence Bar
                st.write(f"**AI Confidence:** {conf}%")
                st.progress(int(conf))
                
            with col_b:
                st.markdown(f"**AI Analysis:** {row['ai_insight']}")
                st.markdown(f"**Full Description:** {row['description']}")
                st.caption(f"Detected at: {row['timestamp']}")
