"""
Cross-source tamper check: if a file with the same name/purpose exists
in more than one source (R2 bucket vs. its origin on Hugging Face Hub),
compare hashes. A mismatch is a strong tamper signal — someone modified
the copy in one location without updating the other, which is exactly
the pattern seen in real supply-chain attacks (e.g. a compromised mirror
serving a backdoored checkpoint while the "official" source looks clean).

This uses the Hugging Face Hub API's built-in file hashes (via
huggingface_hub.HfApi) rather than re-downloading multi-GB files twice.
"""

import hashlib
import os
import boto3
from botocore.config import Config
from huggingface_hub import HfApi

SUPPLY_CHAIN_MAP = {
    # Configure this mapping for whichever models/datasets you're auditing.
    # Format: "storage_object_key": ("hf_repo_id", "hf_filename")
    "hf_reference_test/model.safetensors": ("hf-internal-testing/tiny-random-bert-safetensors", "model.safetensors"),
}


def _get_storage_client():
    return boto3.client(
        "s3",  # Supabase Storage exposes an S3-compatible API
        endpoint_url=os.environ["SUPABASE_S3_ENDPOINT"],
        aws_access_key_id=os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("SUPABASE_S3_REGION", "ap-south-1"),
        config=Config(s3={"addressing_style": "path"}),  # Supabase requires path-style, not virtual-hosted-style
    )


def _hash_storage_object(bucket: str, object_key: str) -> str:
    client = _get_storage_client()
    obj = client.get_object(Bucket=bucket, Key=object_key)
    hasher = hashlib.sha256()
    for chunk in iter(lambda: obj["Body"].read(8192), b""):
        hasher.update(chunk)
    return hasher.hexdigest()


def _extract_reference_sha256(sibling) -> str | None:
    """
    Hugging Face only exposes a directly-comparable content SHA-256 for
    LFS-tracked files (the git-lfs pointer's `oid sha256:...`, which is
    the plain hash of the raw file content). Small files committed
    straight into git instead have a `blob_id`, which is a *Git blob
    SHA-1* — a different hash of a different thing (the blob object,
    not the raw content) — so it can never be compared against a plain
    SHA-256 of the downloaded file. We only trust the LFS path.
    """
    lfs_info = getattr(sibling, "lfs", None)
    if not lfs_info:
        return None
    # huggingface_hub represents this as a dict-like BlobLfsInfo
    if isinstance(lfs_info, dict):
        return lfs_info.get("sha256")
    return getattr(lfs_info, "sha256", None)


def cross_cloud_hash_diff(object_key: str) -> dict:
    mapping = SUPPLY_CHAIN_MAP.get(object_key)
    if not mapping:
        return {"risky": False, "check": "cross_cloud_diff", "detail": "No cross-source mapping configured for this file, skipped", "weight": 0}

    hf_repo_id, hf_filename = mapping
    api = HfApi()

    try:
        hf_file_info = api.model_info(hf_repo_id, files_metadata=True)
        hf_sibling = next((s for s in hf_file_info.siblings if s.rfilename == hf_filename), None)
        hf_sha256 = _extract_reference_sha256(hf_sibling) if hf_sibling else None
        print(f"[cross_cloud_diff] sibling found: {hf_sibling is not None}, hf_sha256: {hf_sha256}")
    except Exception as e:
        print(f"[cross_cloud_diff] EXCEPTION fetching HF metadata: {e}")
        return {
            "risky": True,
            "check": "cross_cloud_diff",
            "detail": f"Could not fetch Hugging Face reference hash: {e}",
            "weight": 15,
        }

    if not hf_sha256:
        print(f"[cross_cloud_diff] No hf_sha256 available — skipping comparison entirely")
        return {
            "risky": False,
            "check": "cross_cloud_diff",
            "detail": f"No comparable SHA-256 available from Hugging Face for {hf_repo_id}/{hf_filename} (not LFS-tracked) — skipped, not a tamper signal",
            "weight": 0,
        }

    storage_sha256 = _hash_storage_object(os.environ.get("SUPABASE_STORAGE_BUCKET", ""), object_key)
    print(f"[cross_cloud_diff] hf_sha256:      {hf_sha256}")
    print(f"[cross_cloud_diff] storage_sha256: {storage_sha256}")
    print(f"[cross_cloud_diff] match: {hf_sha256 == storage_sha256}")

    if hf_sha256 != storage_sha256:
        return {
            "risky": True,
            "check": "cross_cloud_diff",
            "detail": f"Hash mismatch between Supabase Storage copy and Hugging Face source ({hf_repo_id}/{hf_filename}) — possible tampering",
            "weight": 70,
        }

    return {"risky": False, "check": "cross_cloud_diff", "detail": "Hashes match across sources — file is verified unmodified", "weight": 0}
