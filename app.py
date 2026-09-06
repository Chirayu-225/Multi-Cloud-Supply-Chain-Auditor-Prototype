"""
Multi-Cloud AI Supply Chain Auditor — Dashboard

Hosted free on Render (no card required). Reads scan results directly
from Supabase's auto-generated REST API (PostgREST) using the public
anon key, which is safe to expose here since RLS only allows SELECT.
"""

import os
import requests
import streamlit as st

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")  # e.g. https://xxxx.supabase.co
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")  # safe to expose — read-only via RLS

st.set_page_config(page_title="AI Supply Chain Auditor", layout="wide")
st.title("Multi-Cloud AI Supply Chain Auditor")
st.caption("Scans models & datasets across cloud sources for tampering, dangerous serialization, and dependency risks.")

if st.button("Refresh results"):
    st.rerun()

try:
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/scan_results",
        headers={
            "apikey": SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        },
        params={"order": "scanned_at.desc", "limit": 50},
        timeout=10,
    )
    response.raise_for_status()
    results = response.json()
except Exception as e:
    st.error(f"Could not fetch results from Supabase: {e}")
    results = []

if not results:
    st.info("No scan results yet. Upload a file to your Supabase Storage bucket to trigger a scan.")
else:
    for row in results:
        findings = row.get("findings", [])
        risk = row.get("risk_score", 0)

        if risk >= 60:
            badge = "🔴 High risk"
        elif risk >= 25:
            badge = "🟡 Medium risk"
        else:
            badge = "🟢 Low risk"

        with st.expander(f"{badge} — {row['object_key']} (score: {risk})"):
            st.write(f"Scanned at: {row.get('scanned_at', 'unknown')}")
            if findings:
                for f in findings:
                    st.write(f"- **{f['check']}**: {f['detail']}")
            else:
                st.write("No findings.")
