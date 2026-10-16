"""Single-process authenticated job API; persistent statuses and bounded queue."""
import hmac
import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import __version__
from .acquire import Settings, validate_inputs
from .evaluation import compare, validate_reference
from .pipeline import ARTIFACTS, OPTIONAL_ARTIFACTS, analyze, write_json

LOGGER = logging.getLogger('uvicorn.error')


def log_event(event, **fields):
    LOGGER.info(json.dumps({'event': event, **fields}, ensure_ascii=True))


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str | None = Field(default=None, max_length=2048)
    commit: str | None = Field(default=None, pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    image: str = Field(max_length=2048)
    run_mode: Literal['production', 'verification'] = 'production'
    reference_sbom: dict | None = None
    reference_scope: Literal['runtime', 'build', 'unknown'] = 'unknown'

    @model_validator(mode='after')
    def reference_contract(self):
        if (self.repository_url is None) != (self.commit is None):
            raise ValueError('Repository URL and commit must be supplied together')
        if self.run_mode == 'production' and self.reference_sbom is not None:
            raise ValueError('Production mode does not accept a reference')
        if self.run_mode == 'verification':
            if self.reference_sbom is None:
                raise ValueError('Verification requires reference_sbom')
            validate_reference(self.reference_sbom)
        return self


def api_token():
    path = os.getenv("SBOM_API_TOKEN_FILE")
    try:
        if path:
            with Path(path).open("rb") as stream:
                raw = stream.read(8193)
            if len(raw) > 8192:
                return ""
            token = raw.decode("utf-8").strip()
        else:
            token = os.getenv("SBOM_API_TOKEN", "")
    except (OSError, UnicodeError):
        return ""
    return token if len(token) <= 8192 and not any(ord(c) < 32 for c in token) else ""


def create_app(workspace=None, runner=analyze, settings=None):
    root = Path(workspace or os.getenv("SBOM_WORKSPACE", "workspace")).resolve()
    jobs = root / "jobs"
    executor = ThreadPoolExecutor(max_workers=max(1, min(4, int(os.getenv("SBOM_WORKERS", "1")))))
    capacity = threading.BoundedSemaphore(16)
    status_lock = threading.Lock()

    def save_status(path, data):
        with status_lock:
            write_json(path, data)

    def read_status(path):
        with status_lock:
            return json.loads(path.read_text("utf-8"))

    @asynccontextmanager
    async def lifespan(app):
        jobs.mkdir(parents=True, exist_ok=True)
        for status_file in jobs.glob("*/status.json"):
            data = json.loads(status_file.read_text("utf-8"))
            if data["status"] in {"queued", "running"}:
                data.update(status="failed", error="interrupted_by_restart")
                write_json(status_file, data)
        yield
        executor.shutdown(wait=True, cancel_futures=False)

    app = FastAPI(title="SBOM Creator", version=__version__, lifespan=lifespan)

    def auth(authorization: str | None = Header(default=None)):
        token = api_token()
        if not token:
            raise HTTPException(503, "SBOM API token is not configured")
        if authorization is None or not hmac.compare_digest(authorization.encode("utf-8"),
                                                             ("Bearer " + token).encode("utf-8")):
            raise HTTPException(401, "Invalid credentials")

    def job_dir(job_id):
        try:
            if str(uuid.UUID(job_id)) != job_id:
                raise ValueError()
        except ValueError:
            raise HTTPException(404, "Job not found") from None
        directory = jobs / job_id
        if not (directory / "status.json").is_file():
            raise HTTPException(404, "Job not found")
        return directory

    @app.get("/health")
    def health():
        return {"status": "ok", "dependency_readiness": "not_checked"}

    def execute(directory, request, job_id, configured):
        started = time.monotonic()
        stage = 'analysis'
        try:
            log_event('analysis.started', job_id=job_id, run_mode=request.run_mode)
            save_status(directory / "status.json", {"id": job_id, "status": "running"})
            result = runner(request.repository_url, request.commit, request.image,
                            directory / "result", settings=configured, mode="rules")
            artifacts = list(ARTIFACTS)
            artifacts.extend(name for name in OPTIONAL_ARTIFACTS if (directory/'result'/name).is_file())
            if request.run_mode == 'verification':
                stage = 'verification'
                log_event('verification.started', job_id=job_id)
                evaluation = compare(directory / 'result', request.reference_sbom, request.reference_scope)
                write_json(directory / 'result/evaluation.json', evaluation)
                result = dict(result, evaluation=evaluation)
                artifacts.append('evaluation.json')
                log_event('verification.completed', job_id=job_id, status=evaluation['status'])
            save_status(directory / "status.json",
                       {"id": job_id, "status": "succeeded", "result": result,
                        "artifacts": artifacts})
            log_event('analysis.completed', job_id=job_id, elapsed_seconds=round(time.monotonic() - started, 3),
                      artifact_count=len(artifacts), partial=bool(result.get('partial')))
        except Exception as error:  # noqa: BLE001 -- job boundary must persist every failure
            log_event('analysis.failed', job_id=job_id, stage=getattr(error, 'stage', stage),
                      error_type=getattr(error, 'error_type', type(error).__name__),
                      elapsed_seconds=round(time.monotonic() - started, 3))
            # External command/model errors may contain credentials; never serialize raw errors.
            save_status(directory / "status.json", {"id": job_id, "status": "failed",
                       "error": getattr(error, "error_type", type(error).__name__),
                       "stage": getattr(error, "stage", "acquisition_or_configuration"),
                       "message": "Analysis failed; output blocked"})
        finally:
            capacity.release()

    @app.post("/v1/analyses", status_code=202, dependencies=[Depends(auth)])
    def submit(request: Request):
        job_id = str(uuid.uuid4())
        log_event('analysis.received', job_id=job_id, run_mode=request.run_mode)
        configured = settings or Settings.from_env()
        if configured.image_archive:
            log_event('analysis.rejected', job_id=job_id, reason='remote_archive_configuration')
            raise HTTPException(503, "Remote API requires registry image acquisition")
        try:
            validate_inputs(request.repository_url, request.commit, request.image, configured)
        except ValueError:
            log_event('analysis.rejected', job_id=job_id, reason='invalid_or_unauthorized_inputs')
            raise HTTPException(422, "Invalid or unauthorized repository/commit/image") from None
        if not capacity.acquire(blocking=False):
            log_event('analysis.rejected', job_id=job_id, reason='queue_full')
            raise HTTPException(429, "Job queue is full")
        if os.getenv('SBOM_DEBUG_LOGGING', '').lower() in ('1', 'true', 'yes'):
            reference = request.reference_sbom
            log_event('analysis.inputs', job_id=job_id, commit=request.commit,
                      repository_host=urlsplit(request.repository_url).hostname if request.repository_url else None,
                      image=request.image, reference_scope=request.reference_scope,
                      reference_bytes=len(json.dumps(reference).encode()) if reference is not None else 0,
                      reference_components=len(reference.get('components', [])) if reference is not None else 0,
                      platform=configured.image_platform)
        directory = jobs / job_id
        try:
            directory.mkdir(parents=True)
            save_status(directory / "status.json", {"id": job_id, "status": "queued"})
            log_event('analysis.queued', job_id=job_id)
            executor.submit(execute, directory, request, job_id, configured)
        except Exception:
            capacity.release()
            raise
        return {"id": job_id, "status": "queued", "status_url": f"/v1/analyses/{job_id}"}

    @app.get("/v1/analyses/{job_id}", dependencies=[Depends(auth)])
    def status(job_id: str):
        return read_status(job_dir(job_id) / "status.json")

    @app.get("/v1/analyses/{job_id}/artifacts/{name}", dependencies=[Depends(auth)])
    def artifact(job_id: str, name: str):
        directory = job_dir(job_id)
        state = read_status(directory / "status.json")
        if state["status"] != "succeeded":
            raise HTTPException(409, "Job has no published results")
        if name not in state.get('artifacts', []) or not (directory / "result" / name).is_file():
            raise HTTPException(404, "Artifact not found")
        return FileResponse(directory / "result" / name, media_type="application/json", filename=name)

    return app


def main():
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("SBOM_PORT", "8080")))
