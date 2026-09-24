"""
Multi-Cloud AI Supply Chain Auditor — Dashboard

Hosted free on Render (no card required). Reads scan results directly
from Supabase's auto-generated REST API (PostgREST) using the public
anon key, which is safe to expose here since RLS only allows SELECT.
"""

import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")  # e.g. https://xxxx.supabase.co
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")  # safe to expose — read-only via RLS

st.set_page_config(page_title="AI Supply Chain Auditor", layout="wide")
st.title("Multi-Cloud AI Supply Chain Auditor")
st.caption("Scans models & datasets across cloud sources for tampering, dangerous serialization, and dependency risks.")

# --- Upload widget: pushes the file straight into Supabase Storage, ---
# --- which then triggers the fully automated scan pipeline on its own ---
st.subheader("Upload a file to audit")
uploaded_file = st.file_uploader(
    "Choose a model, dataset, or requirements.txt file",
    type=None,  # accept any type; the scanners themselves decide what's relevant
)

if uploaded_file is not None:
    if st.button(f"Upload '{uploaded_file.name}' and scan"):
        with st.spinner("Uploading — the scan will run automatically once it lands..."):
            upload_url = f"{SUPABASE_URL}/storage/v1/object/supply-chain-artifacts/{uploaded_file.name}"
            try:
                response = requests.post(
                    upload_url,
                    headers={
                        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
                        "apikey": SUPABASE_ANON_KEY,
                        "Content-Type": uploaded_file.type or "application/octet-stream",
                    },
                    data=uploaded_file.getvalue(),
                    timeout=30,
                )
                if response.status_code in (200, 201):
                    st.success(
                        f"Uploaded '{uploaded_file.name}'. The scan runs automatically in the "
                        "background — click Refresh results below in about 10-20 seconds."
                    )
                elif response.status_code == 409:
                    st.error(
                        f"A file named '{uploaded_file.name}' already exists in the bucket. "
                        "Rename your file and try again — this avoids silently overwriting a "
                        "previous scan target."
                    )
                else:
                    st.error(f"Upload failed ({response.status_code}): {response.text}")
            except Exception as e:
                st.error(f"Upload error: {e}")

st.divider()

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
