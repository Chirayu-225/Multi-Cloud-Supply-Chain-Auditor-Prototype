"""
One scan, start to finish: download once, run every applicable scanner,
aggregate the score. Pure function of (storage, scanners, bucket, key),
so it can be tested without the queue or the web server.
"""

import logging

from .artifact import Artifact
from .risk import aggregate
from .scanners import Finding, Scanner
from .storage import ArtifactTooLarge, StorageClient

log = logging.getLogger(__name__)


def scan_object(storage: StorageClient, scanners: list[Scanner], bucket: str, key: str, max_bytes: int) -> tuple[str | None, int, list[Finding]]:
    try:
        download = storage.download(bucket, key, max_bytes)
    except ArtifactTooLarge as e:
        finding = Finding("size_limit", True, 30, f"Not scanned: {e}")
        return None, aggregate([finding]), [finding]

    artifact = Artifact.from_file(bucket, key, download.path, download.size, download.sha256)
    try:
        return artifact.sha256, *run_scanners(scanners, artifact)
    finally:
        artifact.cleanup()


def run_scanners(scanners: list[Scanner], artifact: Artifact) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    for scanner in scanners:
        if not scanner.applies(artifact):
            continue
        try:
            findings.append(scanner.scan(artifact))
        except Exception as e:
            log.exception("Scanner %s crashed on %s", scanner.name, artifact.key)
            findings.append(Finding(scanner.name, True, 20, f"Scanner error: {str(e)[:150]}"))
    return aggregate(findings), findings
