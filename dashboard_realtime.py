"""Lightweight live dashboard for the upgraded CSPM.

Reads the existing JSON report and database where available. Run:
    streamlit run dashboard_realtime.py
"""
import json
import os
import time
import streamlit as st

BASE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(BASE, "output", "risk_report.json")
ALERTS = os.path.join(BASE, "output", "alerts.json")

st.set_page_config(page_title="CSPM Live Dashboard", layout="wide")
st.title("CSPM — Real-Time Security Posture")

refresh = st.sidebar.number_input("Refresh interval (seconds)", 1, 30, 3)

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

placeholder = st.empty()

while True:
    reports = load(REPORT)
    alerts = load(ALERTS)
    critical = sum(1 for r in reports if r.get("risk_assessment", {}).get("classification") == "Critical")
    high = sum(1 for r in reports if r.get("risk_assessment", {}).get("classification") == "High")
    medium = sum(1 for r in reports if r.get("risk_assessment", {}).get("classification") == "Medium")
    low = sum(1 for r in reports if r.get("risk_assessment", {}).get("classification") == "Low")

    with placeholder.container():
        a,b,c,d,e = st.columns(5)
        a.metric("Containers", len(reports))
        b.metric("Critical", critical)
        c.metric("High", high)
        d.metric("Medium", medium)
        e.metric("Low", low)

        rows = []
        for r in reports:
            c = r.get("container", {})
            a = r.get("risk_assessment", {})
            rows.append({
                "Container": c.get("container_id", ""),
                "Image": c.get("image", ""),
                "Risk": a.get("normalized_score", 0),
                "Class": a.get("classification", "Unknown"),
                "Vulnerability": a.get("vulnerability_score", 0),
                "Privilege": a.get("privilege_score", 0),
                "Exposure": a.get("exposure_score", 0),
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.subheader("Recent alerts")
        st.dataframe(alerts[-20:] if alerts else [], use_container_width=True, hide_index=True)
    time.sleep(refresh)
