"""Single-process authenticated job API; persistent statuses and bounded queue."""
import hmac
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from .acquire import Settings, validate_inputs
from .pipeline import ARTIFACTS, analyze, write_json


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str = Field(max_length=2048)
    commit: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    image: str = Field(max_length=2048)


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

    app = FastAPI(title="SBOM Creator", version="0.5.0", lifespan=lifespan)

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
        try:
            save_status(directory / "status.json", {"id": job_id, "status": "running"})
            result = runner(request.repository_url, request.commit, request.image,
                            directory / "result", settings=configured, mode="rules")
            save_status(directory / "status.json",
                       {"id": job_id, "status": "succeeded", "result": result,
                        "artifacts": list(ARTIFACTS)})
        except Exception as error:  # noqa: BLE001 -- job boundary must persist every failure
            # External command/model errors may contain credentials; never serialize raw errors.
            save_status(directory / "status.json", {"id": job_id, "status": "failed",
                       "error": getattr(error, "error_type", type(error).__name__),
                       "stage": getattr(error, "stage", "acquisition_or_configuration"),
                       "message": "Analysis failed; output blocked"})
        finally:
            capacity.release()

    @app.post("/v1/analyses", status_code=202, dependencies=[Depends(auth)])
    def submit(request: Request):
        configured = settings or Settings.from_env()
        if configured.image_archive:
            raise HTTPException(503, "Remote API requires registry image acquisition")
        try:
            validate_inputs(request.repository_url, request.commit, request.image, configured)
        except ValueError:
            raise HTTPException(422, "Invalid or unauthorized repository/commit/image") from None
        if not capacity.acquire(blocking=False):
            raise HTTPException(429, "Job queue is full")
        job_id = str(uuid.uuid4())
        directory = jobs / job_id
        try:
            directory.mkdir(parents=True)
            save_status(directory / "status.json", {"id": job_id, "status": "queued"})
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
        if name not in ARTIFACTS or not (directory / "result" / name).is_file():
            raise HTTPException(404, "Artifact not found")
        return FileResponse(directory / "result" / name, media_type="application/json", filename=name)

    return app


def main():
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("SBOM_PORT", "8080")))
