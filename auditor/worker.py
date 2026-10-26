"""
Background worker thread. Drains the job queue, then sleeps until either
the poll interval passes or /jobs/notify wakes it up.

Running scans in a plain thread (not an async task) matters: boto3 and
the scanners are blocking, and running them inside FastAPI's event loop
froze every other request while a scan ran.
"""

import logging
import threading

from .config import Settings
from .jobs import JobQueue
from .pipeline import scan_object
from .scanners import Scanner
from .storage import StorageClient

log = logging.getLogger(__name__)


class Worker:
    def __init__(self, settings: Settings, queue: JobQueue, storage: StorageClient, scanners: list[Scanner]):
        self._settings = settings
        self._queue = queue
        self._storage = storage
        self._scanners = scanners
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="scan-worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=10)

    def notify(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.drain()
            except Exception:
                log.exception("Worker loop error")
            self._wake.wait(self._settings.poll_interval_seconds)
            self._wake.clear()

    def drain(self) -> int:
        processed = 0
        while not self._stop.is_set():
            job = self._queue.claim()
            if job is None:
                return processed
            self._process(job)
            processed += 1
        return processed

    def _process(self, job) -> None:
        log.info("Scanning job %s: %s/%s (attempt %s)", job.id, job.bucket, job.object_key, job.attempts)
        try:
            if job.bucket not in self._settings.allowed_buckets:
                raise PermissionError(f"Bucket '{job.bucket}' is not allowed")
            sha256, score, findings = scan_object(
                self._storage, self._scanners, job.bucket, job.object_key, self._settings.max_artifact_bytes
            )
            self._queue.complete(job, sha256, score, [f.to_dict() for f in findings])
        except Exception as e:
            log.exception("Job %s failed", job.id)
            self._queue.fail(job, f"{type(e).__name__}: {e}")
