"""
Durable job queue backed by the scan_jobs table (see schema.sql).

A database trigger inserts a 'pending' row whenever a file lands in the
bucket, so a job exists even if the backend is asleep or crashes. The
backend claims jobs through Postgres functions that use
FOR UPDATE SKIP LOCKED, so two workers never grab the same job and a
job stuck in 'running' (worker died mid-scan) is retried later.
"""

from dataclasses import dataclass

import httpx

from .config import Settings


@dataclass
class Job:
    id: int
    bucket: str
    object_key: str
    attempts: int


class JobQueue:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._http = httpx.Client(
            base_url=f"{settings.supabase_url}/rest/v1",
            headers={
                "apikey": settings.supabase_service_role_key,
                "Authorization": f"Bearer {settings.supabase_service_role_key}",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )

    def _rpc(self, function: str, payload: dict):
        response = self._http.post(f"/rpc/{function}", json=payload)
        response.raise_for_status()  # never fail silently
        return response.json() if response.content else None

    def claim(self) -> Job | None:
        rows = self._rpc("claim_scan_job", {"max_attempts": self._settings.max_attempts})
        if not rows:
            return None
        row = rows[0]
        return Job(id=row["id"], bucket=row["bucket"], object_key=row["object_key"], attempts=row["attempts"])

    def complete(self, job: Job, sha256: str | None, risk_score: int, findings: list[dict]) -> None:
        self._rpc("complete_scan_job", {
            "p_job_id": job.id,
            "p_sha256": sha256,
            "p_risk_score": risk_score,
            "p_findings": findings,
        })

    def fail(self, job: Job, error: str) -> None:
        self._rpc("fail_scan_job", {
            "p_job_id": job.id,
            "p_error": error[:500],
            "p_max_attempts": self._settings.max_attempts,
        })
