"""
Scans pickle-based files for dangerous opcodes WITHOUT ever unpickling
(i.e. never executing) the file. This is critical — the whole point is
to detect malicious payloads without triggering them.

Uses Python's pickletools.genops to statically walk the opcode stream
and flag GLOBAL/STACK_GLOBAL references to known-dangerous callables
(os.system, subprocess, eval, exec, etc.) — the same technique used by
tools like Hugging Face's picklescan and fickling.
"""

import pickletools
import io
import boto3
import os
from botocore.config import Config

DANGEROUS_CALLABLES = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("posix", "system"),
    ("nt", "system"),
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


STRING_PUSH_OPCODES = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
    "SHORT_BINSTRING", "BINSTRING", "UNICODE", "STRING",
}


def scan_for_dangerous_code(bucket: str, object_key: str) -> dict:
    ext = "." + object_key.rsplit(".", 1)[-1].lower() if "." in object_key else ""
    if ext not in {".pkl", ".pickle", ".pt", ".bin", ".ckpt"}:
        return {"risky": False, "check": "dangerous_code_scan", "detail": "Not a pickle-based format, skipped", "weight": 0}

    client = _get_storage_client()

    # Cap how much we read — most malicious payloads sit in the opcode
    # stream near the start/end, and we don't want to pull a full multi-GB
    # checkpoint just to statically inspect its structure.
    obj = client.get_object(Bucket=bucket, Key=object_key)
    data = obj["Body"].read(50 * 1024 * 1024)  # first 50MB is enough for opcode scanning

    found = []
    try:
        # Track the last two pushed strings — STACK_GLOBAL (pickle protocol
        # 4+) pops (module, name) off the stack rather than carrying them
        # as a single argument the way the older GLOBAL opcode does. We
        # don't need a full pickle VM — just enough to catch this pattern.
        recent_strings = []
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            if opcode.name in STRING_PUSH_OPCODES and arg is not None:
                recent_strings.append(str(arg))
                if len(recent_strings) > 2:
                    recent_strings.pop(0)

            if opcode.name == "GLOBAL" and arg:
                # Old-style: arg is "module name" as one string
                parts = tuple(str(arg).split(" ")) if " " in str(arg) else (str(arg),)
                if len(parts) == 2 and parts in DANGEROUS_CALLABLES:
                    found.append(f"{parts[0]}.{parts[1]}")

            elif opcode.name == "STACK_GLOBAL":
                # New-style: module and name were the last two strings
                # pushed onto the stack before this opcode
                if len(recent_strings) == 2:
                    parts = (recent_strings[0], recent_strings[1])
                    if parts in DANGEROUS_CALLABLES:
                        found.append(f"{parts[0]}.{parts[1]}")
    except Exception:
        # Malformed/truncated pickle stream — flag as suspicious rather than crash
        return {
            "risky": True,
            "check": "dangerous_code_scan",
            "detail": "Pickle stream could not be statically parsed — treat as suspicious",
            "weight": 20,
        }

    if found:
        return {
            "risky": True,
            "check": "dangerous_code_scan",
            "detail": f"Dangerous callables referenced in pickle stream: {', '.join(set(found))}",
            "weight": 60,
        }

    return {"risky": False, "check": "dangerous_code_scan", "detail": "No dangerous callables found", "weight": 0}
