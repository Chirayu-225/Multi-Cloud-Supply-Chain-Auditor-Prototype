"""
Central configuration. Every environment variable the backend reads is
declared here once, so missing settings fail loudly at startup instead
of halfway through a scan.
"""

import os
from dataclasses import dataclass
from functools import lru_cache


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_service_role_key: str
    s3_endpoint: str
    s3_access_key_id: str
    s3_secret_access_key: str
    s3_region: str
    storage_bucket: str
    # Shared secret between the Supabase Edge Function and this backend.
    # Requests to /jobs/notify must carry an HMAC made with it.
    webhook_secret: str
    max_artifact_bytes: int
    poll_interval_seconds: float
    max_attempts: int

    @property
    def allowed_buckets(self) -> frozenset[str]:
        return frozenset({self.storage_bucket})


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        supabase_url=_required("SUPABASE_URL").rstrip("/"),
        supabase_service_role_key=_required("SUPABASE_SERVICE_ROLE_KEY"),
        s3_endpoint=_required("SUPABASE_S3_ENDPOINT"),
        s3_access_key_id=_required("SUPABASE_S3_ACCESS_KEY_ID"),
        s3_secret_access_key=_required("SUPABASE_S3_SECRET_ACCESS_KEY"),
        s3_region=os.environ.get("SUPABASE_S3_REGION", "ap-south-1"),
        storage_bucket=_required("SUPABASE_STORAGE_BUCKET"),
        webhook_secret=_required("SCAN_WEBHOOK_SECRET"),
        max_artifact_bytes=int(os.environ.get("MAX_ARTIFACT_BYTES", str(100 * 1024 * 1024))),
        poll_interval_seconds=float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "30")),
        max_attempts=int(os.environ.get("JOB_MAX_ATTEMPTS", "3")),
    )
