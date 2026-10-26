"""
Multi-Cloud AI Supply Chain Auditor — Dashboard

Hosted free on Render (no card required). Reads scan results directly
from Supabase's auto-generated REST API (PostgREST) using the public
anon key, which is safe to expose here since RLS only allows SELECT.

Visual theme: dark "SOC console" — navy/amber/teal/violet — matching
the visual identity used across this portfolio's other AI Security
projects (llm-security-gateway, trust-gate).
"""

import html
import os
import re
import time
import uuid

import requests
import streamlit as st
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
BUCKET = "supply-chain-artifacts"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024        # matches the bucket's file_size_limit
UPLOADS_PER_WINDOW = 5                      # per browser session
UPLOAD_WINDOW_SECONDS = 600

HEADERS = {"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {SUPABASE_ANON_KEY}"}


def esc(value) -> str:
    """Everything shown via unsafe_allow_html comes from uploaders
    (file names, package names) — escape it, always."""
    return html.escape(str(value), quote=True)


def storage_key_for(filename: str) -> str:
    """Random prefix + sanitized name: no path tricks, no collisions,
    no overwriting someone else's upload."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename).strip("._") or "file"
    return f"{uuid.uuid4().hex[:12]}-{safe[:100]}"


def upload_allowed() -> bool:
    now = time.time()
    recent = [t for t in st.session_state.get("upload_times", []) if now - t < UPLOAD_WINDOW_SECONDS]
    st.session_state["upload_times"] = recent
    return len(recent) < UPLOADS_PER_WINDOW

st.set_page_config(
    page_title="Supply Chain Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# SOC console theme — dark navy base, amber/teal/violet accents
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --bg-primary: #0a0e17;
        --bg-secondary: #10151f;
        --bg-card: #131924;
        --border-subtle: #232b3a;
        --text-primary: #e8ecf3;
        --text-secondary: #8a94a6;
        --accent-teal: #2dd4bf;
        --accent-amber: #f5a623;
        --accent-violet: #8b5cf6;
        --accent-red: #f0525b;
        --accent-green: #3ddc84;
    }

    .stApp {
        background: linear-gradient(180deg, var(--bg-primary) 0%, #0c1119 100%);
        font-family: 'Inter', sans-serif;
    }

    /* Hide default Streamlit chrome for a cleaner product feel */
    #MainMenu, footer, header {visibility: hidden;}

    /* --- Header / masthead --- */
    .soc-masthead {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 4px 0 20px 0;
        border-bottom: 1px solid var(--border-subtle);
        margin-bottom: 28px;
    }
    .soc-brand {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .soc-brand-icon {
        width: 40px;
        height: 40px;
        border-radius: 10px;
        background: linear-gradient(135deg, var(--accent-teal), var(--accent-violet));
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
    }
    .soc-brand-title {
        font-size: 20px;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.02em;
        margin: 0;
    }
    .soc-brand-subtitle {
        font-size: 12.5px;
        color: var(--text-secondary);
        margin: 0;
    }
    .soc-status-pill {
        display: flex;
        align-items: center;
        gap: 6px;
        background: rgba(61, 220, 132, 0.1);
        border: 1px solid rgba(61, 220, 132, 0.25);
        color: var(--accent-green);
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .soc-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--accent-green);
        box-shadow: 0 0 8px var(--accent-green);
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
    }

    /* --- KPI cards --- */
    .kpi-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin-bottom: 28px;
    }
    .kpi-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
    }
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
    }
    .kpi-card.total::before { background: var(--accent-teal); }
    .kpi-card.high::before { background: var(--accent-red); }
    .kpi-card.medium::before { background: var(--accent-amber); }
    .kpi-card.low::before { background: var(--accent-green); }
    .kpi-label {
        font-size: 11.5px;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 600;
        margin-bottom: 8px;
    }
    .kpi-value {
        font-size: 30px;
        font-weight: 800;
        color: var(--text-primary);
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
    }

    /* --- Section headers --- */
    .soc-section-title {
        font-size: 14px;
        font-weight: 700;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin: 8px 0 14px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .soc-section-title::before {
        content: '';
        width: 3px;
        height: 14px;
        background: var(--accent-teal);
        border-radius: 2px;
    }

    /* --- Upload area --- */
    [data-testid="stFileUploader"] {
        background: var(--bg-card);
        border: 1px dashed var(--border-subtle);
        border-radius: 12px;
        padding: 8px;
    }

    /* --- Result cards --- */
    .result-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-left: 3px solid transparent;
        border-radius: 10px;
        padding: 16px 18px;
        margin-bottom: 10px;
    }
    .result-card.risk-high { border-left-color: var(--accent-red); }
    .result-card.risk-medium { border-left-color: var(--accent-amber); }
    .result-card.risk-low { border-left-color: var(--accent-green); }

    .result-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .result-filename {
        font-family: 'JetBrains Mono', monospace;
        font-size: 13.5px;
        color: var(--text-primary);
        font-weight: 500;
    }
    .risk-pill {
        font-size: 11px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 20px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        font-family: 'JetBrains Mono', monospace;
    }
    .risk-pill.high { background: rgba(240, 82, 91, 0.15); color: var(--accent-red); }
    .risk-pill.medium { background: rgba(245, 166, 35, 0.15); color: var(--accent-amber); }
    .risk-pill.low { background: rgba(61, 220, 132, 0.15); color: var(--accent-green); }

    .result-meta {
        font-size: 11.5px;
        color: var(--text-secondary);
        font-family: 'JetBrains Mono', monospace;
        margin-top: 4px;
    }
    .finding-line {
        font-size: 13px;
        color: var(--text-primary);
        padding: 8px 12px;
        background: var(--bg-secondary);
        border-radius: 6px;
        margin-top: 8px;
        border: 1px solid var(--border-subtle);
    }
    .finding-check {
        color: var(--accent-violet);
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11.5px;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }

    /* Buttons */
    .stButton button {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        color: var(--text-primary);
        border-radius: 8px;
        font-weight: 500;
    }
    .stButton button:hover {
        border-color: var(--accent-teal);
        color: var(--accent-teal);
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Masthead
# ---------------------------------------------------------------------------
st.markdown("""
<div class="soc-masthead">
    <div class="soc-brand">
        <div class="soc-brand-icon">🛡️</div>
        <div>
            <p class="soc-brand-title">Supply Chain Auditor</p>
            <p class="soc-brand-subtitle">Multi-cloud AI model &amp; dependency risk scanning</p>
        </div>
    </div>
    <div class="soc-status-pill"><span class="soc-dot"></span> LIVE</div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Fetch results (used for both KPIs and the list below)
# ---------------------------------------------------------------------------
try:
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/scan_results",
        headers=HEADERS,
        params={"order": "scanned_at.desc", "limit": 50},
        timeout=10,
    )
    response.raise_for_status()
    results = response.json()
    fetch_error = None
except Exception as e:
    results = []
    fetch_error = str(e)

try:
    jobs_response = requests.get(
        f"{SUPABASE_URL}/rest/v1/scan_jobs",
        headers=HEADERS,
        params={"status": "in.(pending,running,failed)", "order": "created_at.desc", "limit": 20},
        timeout=10,
    )
    jobs_response.raise_for_status()
    open_jobs = jobs_response.json()
except Exception:
    open_jobs = []


def classify(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


total = len(results)
high_count = sum(1 for r in results if classify(r.get("risk_score", 0)) == "high")
medium_count = sum(1 for r in results if classify(r.get("risk_score", 0)) == "medium")
low_count = total - high_count - medium_count

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
st.markdown(f"""
<div class="kpi-row">
    <div class="kpi-card total">
        <div class="kpi-label">Total Scans</div>
        <div class="kpi-value">{total}</div>
    </div>
    <div class="kpi-card high">
        <div class="kpi-label">High Risk</div>
        <div class="kpi-value" style="color: var(--accent-red);">{high_count}</div>
    </div>
    <div class="kpi-card medium">
        <div class="kpi-label">Medium Risk</div>
        <div class="kpi-value" style="color: var(--accent-amber);">{medium_count}</div>
    </div>
    <div class="kpi-card low">
        <div class="kpi-label">Clean</div>
        <div class="kpi-value" style="color: var(--accent-green);">{low_count}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
st.markdown('<div class="soc-section-title">Submit for Audit</div>', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Drop a model, dataset, or requirements.txt file",
    type=None,
    label_visibility="collapsed",
)

if uploaded_file is not None:
    col1, col2 = st.columns([1, 4])
    with col1:
        scan_clicked = st.button(f"Scan '{uploaded_file.name}'", type="primary")
    if scan_clicked:
        if uploaded_file.size > MAX_UPLOAD_BYTES:
            st.error(f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        elif not upload_allowed():
            st.error("Upload limit reached — try again in a few minutes.")
        else:
            key = storage_key_for(uploaded_file.name)
            with st.spinner("Uploading — the automated scan pipeline runs in the background..."):
                try:
                    upload_response = requests.post(
                        f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{key}",
                        headers={**HEADERS, "Content-Type": "application/octet-stream"},
                        data=uploaded_file.getvalue(),
                        timeout=60,
                    )
                    if upload_response.status_code in (200, 201):
                        st.session_state["upload_times"].append(time.time())
                        st.success(f"Uploaded as '{key}' — the scan is queued. Refresh in ~15 seconds.")
                    else:
                        st.error(f"Upload failed ({upload_response.status_code}).")
                except Exception as e:
                    st.error(f"Upload error: {e}")

st.write("")

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
header_col, button_col = st.columns([5, 1])
with header_col:
    st.markdown('<div class="soc-section-title">Recent Scans</div>', unsafe_allow_html=True)
with button_col:
    if st.button("↻ Refresh"):
        st.rerun()

if open_jobs:
    st.markdown('<div class="soc-section-title">Queue</div>', unsafe_allow_html=True)
    for job in open_jobs:
        note = f" — {esc(job['last_error'])}" if job.get("last_error") else ""
        st.markdown(
            f'<div class="finding-line"><span class="finding-check">{esc(job.get("status"))}</span> '
            f'{esc(job.get("object_key"))} · attempt {esc(job.get("attempts", 0))}{note}</div>',
            unsafe_allow_html=True,
        )
    st.write("")

if fetch_error:
    st.error(f"Could not fetch results: {fetch_error}")
elif not results:
    st.info("No scans yet — upload a file above to run your first audit.")
else:
    for row in results:
        findings = row.get("findings", [])
        risk = int(row.get("risk_score") or 0)
        level = classify(risk)
        object_key = row.get("object_key", "unknown")
        scanned_at = row.get("scanned_at", "")

        try:
            dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
            time_str = dt.strftime("%b %d, %Y · %H:%M UTC")
        except Exception:
            time_str = scanned_at

        findings_html = ""
        if findings:
            for f in findings:
                findings_html += (
                    f'<div class="finding-line">'
                    f'<span class="finding-check">{esc(f.get("check", "check"))}</span><br/>'
                    f'{esc(f.get("detail", ""))}'
                    f'</div>'
                )
        else:
            findings_html = '<div class="finding-line" style="color: var(--text-secondary);">No findings — file passed all checks.</div>'

        st.markdown(f"""
        <div class="result-card risk-{level}">
            <div class="result-header">
                <span class="result-filename">{esc(object_key)}</span>
                <span class="risk-pill {level}">{level} · {esc(risk)}</span>
            </div>
            <div class="result-meta">{esc(time_str)}</div>
            {findings_html}
        </div>
        """, unsafe_allow_html=True)
