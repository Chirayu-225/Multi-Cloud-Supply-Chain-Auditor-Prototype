"""
One place that talks to Supabase Storage (through its S3-compatible
API). Scanners never touch storage directly — they receive an Artifact
that has already been downloaded once.
"""

import hashlib
import os
import tempfile
from dataclasses import dataclass

import boto3
from botocore.config import Config

from .config import Settings

CHUNK_SIZE = 1024 * 1024


class ArtifactTooLarge(Exception):
    def __init__(self, size: int, limit: int):
        super().__init__(f"Object is {size} bytes, limit is {limit} bytes")
        self.size = size
        self.limit = limit


@dataclass
class Download:
    path: str
    size: int
    sha256: str


class StorageClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            region_name=settings.s3_region,
            config=Config(s3={"addressing_style": "path"}),  # Supabase requires path-style
        )

    def download(self, bucket: str, key: str, max_bytes: int) -> Download:
        """Stream an object to a temp file, hashing as it goes.

        Refuses objects over max_bytes, checked both up front (HEAD) and
        while streaming, since Content-Length can't be fully trusted.
        """
        if bucket not in self._settings.allowed_buckets:
            raise PermissionError(f"Bucket '{bucket}' is not allowed")

        head = self._client.head_object(Bucket=bucket, Key=key)
        if head["ContentLength"] > max_bytes:
            raise ArtifactTooLarge(head["ContentLength"], max_bytes)

        body = self._client.get_object(Bucket=bucket, Key=key)["Body"]
        hasher = hashlib.sha256()
        size = 0
        tmp = tempfile.NamedTemporaryFile(prefix="artifact-", delete=False)
        try:
            with tmp:
                for chunk in iter(lambda: body.read(CHUNK_SIZE), b""):
                    size += len(chunk)
                    if size > max_bytes:
                        raise ArtifactTooLarge(size, max_bytes)
                    hasher.update(chunk)
                    tmp.write(chunk)
        except BaseException:
            os.unlink(tmp.name)
            raise
        return Download(path=tmp.name, size=size, sha256=hasher.hexdigest())
