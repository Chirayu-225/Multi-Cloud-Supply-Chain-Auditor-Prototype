"""
Request signing between the Supabase Edge Function and the backend.

The edge function sends:
    X-Auditor-Timestamp: <unix seconds>
    X-Auditor-Signature: hex(HMAC-SHA256(secret, "<timestamp>.<raw body>"))

Including the timestamp in the signed message and rejecting old ones
stops a captured request from being replayed later.
"""

import hashlib
import hmac
import time

MAX_CLOCK_SKEW_SECONDS = 300


def sign(secret: str, timestamp: str, body: bytes) -> str:
    message = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str | None, signature: str | None, body: bytes, now: float | None = None) -> bool:
    if not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > MAX_CLOCK_SKEW_SECONDS:
        return False
    expected = sign(secret, timestamp, body)
    return hmac.compare_digest(expected, signature)
