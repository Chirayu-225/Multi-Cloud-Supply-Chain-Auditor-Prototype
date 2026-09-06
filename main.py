"""
Multi-Cloud AI Supply Chain Auditor — Backend scanning service.

Deployed on Render or Fly.io (free tier, no card required, no expiry).
This is where all the CPU-heavy work happens: file hashing, model
deserialization checks, dependency typosquat detection, and the
cross-cloud tamper diff. The Cloudflare Worker only forwards jobs here.
"""

import os
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

load_dotenv()  # reads variables from a local .env file into os.environ

from scanners.serialization_check import check_serialization_format
from scanners.dangerous_code_scan import scan_for_dangerous_code
from scanners.typosquat_check import check_dependency_typosquat
from scanners.cross_cloud_diff import cross_cloud_hash_diff

app = FastAPI(title="AI Supply Chain Auditor — Backend")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")  # e.g. https://xxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
# service_role key bypasses Row Level Security so the backend can write
# results; never expose this key to the dashboard/frontend — it stays
# server-side only.


class ScanJob(BaseModel):
    bucket: str
    object_key: str
    size: int
    source: str  # "r2", "huggingface", etc.


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan")
async def receive_scan_job(job: ScanJob, background_tasks: BackgroundTasks):
    """
    Called by the Cloudflare Worker. Immediately acknowledges and runs the
    actual scan in the background so the Worker's request doesn't hang.
    """
    background_tasks.add_task(run_full_scan, job)
    return {"status": "accepted", "object_key": job.object_key}


async def run_full_scan(job: ScanJob):
    findings = []
    risk_score = 0

    # 1. Serialization format check (pickle/safetensors/etc.)
    serialization_result = check_serialization_format(job.bucket, job.object_key)
    if serialization_result["risky"]:
        findings.append(serialization_result)
        risk_score += serialization_result["weight"]

    # 2. Dangerous code scan (e.g. unpickling arbitrary code execution)
    code_scan_result = scan_for_dangerous_code(job.bucket, job.object_key)
    if code_scan_result["risky"]:
        findings.append(code_scan_result)
        risk_score += code_scan_result["weight"]

    # 3. Dependency typosquat detection (if the object is a requirements
    #    file or references packages, e.g. model card metadata)
    typosquat_result = check_dependency_typosquat(job.bucket, job.object_key)
    if typosquat_result["risky"]:
        findings.append(typosquat_result)
        risk_score += typosquat_result["weight"]

    # 4. Cross-cloud tamper check — compares this file's hash against the
    #    "same" file if it exists in other configured sources
    diff_result = cross_cloud_hash_diff(job.object_key)
    if diff_result["risky"]:
        findings.append(diff_result)
        risk_score += diff_result["weight"]

    await post_results(job.object_key, risk_score, findings)


async def post_results(object_key: str, risk_score: int, findings: list):
    """Write the completed result directly into Supabase Postgres via its
    auto-generated REST API (PostgREST), using the service_role key so
    Row Level Security doesn't block the insert."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        print(f"[WARN] Supabase env vars not set — result not persisted: {object_key}")
        return

    async with httpx.AsyncClient() as client:
        await client.post(
            f"{SUPABASE_URL}/rest/v1/scan_results",
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            json={
                "object_key": object_key,
                "risk_score": risk_score,
                "findings": findings,
            },
            timeout=10.0,
        )
