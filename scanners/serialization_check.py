"""
Checks the serialization format of a model/dataset file.

Why this matters: formats like Python's `pickle` (and by extension
old-style PyTorch `.pt`/`.bin` checkpoints saved with torch.save) can
execute arbitrary code on load via __reduce__. Safer formats like
`safetensors` or `ONNX` don't have this problem because they only
store tensor data, not executable objects.
"""

import io
import boto3
from botocore.config import Config

RISKY_EXTENSIONS = {".pkl", ".pickle", ".pt", ".bin", ".ckpt"}
SAFE_EXTENSIONS = {".safetensors", ".onnx", ".json", ".txt", ".csv"}

PICKLE_MAGIC_BYTES = [
    b"\x80\x02",  # pickle protocol 2
    b"\x80\x03",  # pickle protocol 3
    b"\x80\x04",  # pickle protocol 4
    b"\x80\x05",  # pickle protocol 5
]


def _get_storage_client():
    import os
    return boto3.client(
        "s3",  # Supabase Storage exposes an S3-compatible API
        endpoint_url=os.environ["SUPABASE_S3_ENDPOINT"],  # https://<project>.supabase.co/storage/v1/s3
        aws_access_key_id=os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("SUPABASE_S3_REGION", "ap-south-1"),
        config=Config(s3={"addressing_style": "path"}),  # Supabase requires path-style, not virtual-hosted-style
    )


def check_serialization_format(bucket: str, object_key: str) -> dict:
    ext = "." + object_key.rsplit(".", 1)[-1].lower() if "." in object_key else ""

    if ext in SAFE_EXTENSIONS:
        return {"risky": False, "check": "serialization_format", "detail": f"Safe format ({ext})", "weight": 0}

    if ext not in RISKY_EXTENSIONS:
        return {"risky": False, "check": "serialization_format", "detail": "Unrecognized extension, skipped", "weight": 0}

    # Read just the first few bytes — no need to pull the whole file
    # (this keeps the backend fast even for multi-GB checkpoints)
    client = _get_storage_client()
    response = client.get_object(Bucket=bucket, Key=object_key, Range="bytes=0-15")
    header = response["Body"].read()

    is_pickle = any(header.startswith(magic) for magic in PICKLE_MAGIC_BYTES)

    if is_pickle:
        return {
            "risky": True,
            "check": "serialization_format",
            "detail": f"File uses pickle-based serialization ({ext}) — can execute arbitrary code on load. Recommend converting to safetensors.",
            "weight": 40,
        }

    return {"risky": False, "check": "serialization_format", "detail": "No pickle signature detected", "weight": 0}
