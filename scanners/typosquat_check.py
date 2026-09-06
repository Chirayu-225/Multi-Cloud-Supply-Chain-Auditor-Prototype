"""
Checks requirements.txt / model card dependency lists for typosquatted
package names — e.g. "tensrflow" instead of "tensorflow", or
"reqeusts" instead of "requests". Uses Levenshtein distance against a
curated list of popular ML/data packages.
"""

import os
import boto3
from botocore.config import Config

POPULAR_ML_PACKAGES = [
    "torch", "tensorflow", "numpy", "pandas", "scikit-learn", "transformers",
    "huggingface-hub", "requests", "scipy", "matplotlib", "pillow", "opencv-python",
    "boto3", "flask", "fastapi", "pydantic", "safetensors", "onnx", "accelerate",
]


def _get_storage_client():
    return boto3.client(
        "s3",  # Supabase Storage exposes an S3-compatible API
        endpoint_url=os.environ["SUPABASE_S3_ENDPOINT"],
        aws_access_key_id=os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("SUPABASE_S3_REGION", "ap-south-1"),
        config=Config(s3={"addressing_style": "path"}),  # Supabase requires path-style, not virtual-hosted-style
    )


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_dependency_typosquat(bucket: str, object_key: str) -> dict:
    if not object_key.endswith(("requirements.txt", ".txt")):
        return {"risky": False, "check": "typosquat_check", "detail": "Not a dependency file, skipped", "weight": 0}

    client = _get_storage_client()
    obj = client.get_object(Bucket=bucket, Key=object_key)
    content = obj["Body"].read().decode("utf-8", errors="ignore")

    suspicious = []
    for line in content.splitlines():
        pkg = line.strip().split("==")[0].split(">=")[0].strip().lower()
        if not pkg or pkg in POPULAR_ML_PACKAGES:
            continue
        for legit in POPULAR_ML_PACKAGES:
            dist = _levenshtein(pkg, legit)
            # distance 1-2 on a name that isn't an exact match is a classic
            # typosquat signature (e.g. "tensrflow" vs "tensorflow")
            if 0 < dist <= 2 and abs(len(pkg) - len(legit)) <= 2:
                suspicious.append(f"'{pkg}' looks like a typosquat of '{legit}'")

    if suspicious:
        return {
            "risky": True,
            "check": "typosquat_check",
            "detail": "; ".join(suspicious),
            "weight": 30,
        }

    return {"risky": False, "check": "typosquat_check", "detail": "No typosquat patterns found", "weight": 0}
