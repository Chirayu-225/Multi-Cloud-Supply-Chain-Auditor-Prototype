"""
Multi-Cloud AI Supply Chain Auditor — backend.

The backend no longer accepts "scan this bucket/key" from the network.
Jobs are created by a Postgres trigger when a file lands in storage
(see schema.sql); the only public write endpoint is a signed "wake up,
there's work" ping from the Supabase Edge Function, which carries no
instructions about what to scan.
"""

import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request

load_dotenv()

from auditor.config import get_settings  # noqa: E402
from auditor.jobs import JobQueue  # noqa: E402
from auditor.scanners import default_scanners  # noqa: E402
from auditor.security import verify  # noqa: E402
from auditor.storage import StorageClient  # noqa: E402
from auditor.worker import Worker  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    worker = Worker(settings, JobQueue(settings), StorageClient(settings), default_scanners())
    worker.start()  # drains anything that queued up while we were asleep
    app.state.settings = settings
    app.state.worker = worker
    yield
    worker.stop()


app = FastAPI(title="AI Supply Chain Auditor — Backend", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/jobs/notify", status_code=202)
async def notify(request: Request):
    body = await request.body()
    ok = verify(
        request.app.state.settings.webhook_secret,
        request.headers.get("x-auditor-timestamp"),
        request.headers.get("x-auditor-signature"),
        body,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid signature")
    request.app.state.worker.notify()
    return {"status": "accepted"}
