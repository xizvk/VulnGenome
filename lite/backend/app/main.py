from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
import re
import shutil
import sys
import uuid
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response

from .config import BACKEND_ROOT, LITE_ROOT, get_settings
from .elf import ELFValidationError, validate_elf64_amd64_shared_object
from .services.intelligence import build_explanation
from .services.reporting import json_report, render_html
from .store import JobStore


class WorkerSupervisor:
    def __init__(self, store: JobStore, data_dir: Path, timeout: int):
        self.store = store
        self.data_dir = data_dir
        self.timeout = timeout
        self.tasks: dict[str, asyncio.Task[None]] = {}

    def submit(self, job_id: str) -> None:
        if job_id not in self.tasks or self.tasks[job_id].done():
            self.tasks[job_id] = asyncio.create_task(self._run(job_id))

    async def _run(self, job_id: str) -> None:
        env = os.environ.copy()
        command = [sys.executable, "-m", "app.worker", "--job-id", job_id,
                   "--data-dir", str(self.data_dir)]
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command, cwd=str(BACKEND_ROOT), env=env,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.wait(), timeout=self.timeout)
            current = self.store.get(job_id)
            if process.returncode != 0 and current and current["status"] == "running":
                self.store.update(job_id, status="failed", stage="FAILED",
                                  error=f"Worker exited with code {process.returncode} before recording a result.")
        except asyncio.TimeoutError:
            await self._stop(process)
            with suppress(KeyError):
                self.store.update(job_id, status="failed", stage="FAILED",
                                  error=f"Analysis exceeded the {self.timeout}-second worker limit.")
        except Exception as exc:
            await self._stop(process)
            with suppress(Exception):
                self.store.update(job_id, status="failed", stage="FAILED",
                                  error=f"{type(exc).__name__}: worker could not be started.")
        finally:
            self.tasks.pop(job_id, None)

    @staticmethod
    async def _stop(process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=4)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


def create_app(data_dir: str | Path | None = None, worker_timeout_seconds: int | None = None) -> FastAPI:
    settings = get_settings(data_dir)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
    store = JobStore(settings.database_path)
    supervisor = WorkerSupervisor(store, settings.data_dir,
                                  worker_timeout_seconds or settings.worker_timeout_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.mark_interrupted()
        yield
        pending = list(supervisor.tasks.values())
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    app = FastAPI(title="VulnGenome Lite", version="0.1.0", lifespan=lifespan,
                  description="Static analysis for controlled Linux AMD64 ELF shared-object pairs.")
    app.state.store = store
    app.state.settings = settings
    app.state.supervisor = supervisor

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        try:
            import importlib.util
            angr_available = importlib.util.find_spec("angr") is not None
        except (ImportError, ValueError):
            angr_available = False
        return {"status": "ok", "service": "VulnGenome Lite", "profile": "controlled-linux-amd64-shared-object-v1",
                "static_only": True, "angr_available": angr_available}

    @app.post("/api/v1/analyses", status_code=202)
    async def create_analysis(
        vulnerable: list[UploadFile] = File(...),
        patched: list[UploadFile] = File(...),
    ) -> dict[str, Any]:
        if len(vulnerable) != 1 or len(patched) != 1:
            raise HTTPException(422, "Upload exactly one vulnerable and one patched binary.")
        job_id = uuid.uuid4().hex
        job_dir = settings.quarantine_dir / job_id
        job_dir.mkdir(mode=0o700)
        try:
            old_path, old_name, old_info = await _persist_upload(
                vulnerable[0], job_dir / "vulnerable.elf", settings.max_upload_bytes, "vulnerable"
            )
            new_path, new_name, new_info = await _persist_upload(
                patched[0], job_dir / "patched.elf", settings.max_upload_bytes, "patched"
            )
            if (old_info.architecture, old_info.endianness, old_info.object_type) != (
                new_info.architecture, new_info.endianness, new_info.object_type
            ):
                raise HTTPException(422, "Vulnerable and patched uploads must match the supported ELF profile.")
            record = {
                "id": job_id,
                "vulnerable_name": old_name,
                "patched_name": new_name,
                "vulnerable_sha256": old_info.sha256,
                "patched_sha256": new_info.sha256,
                "vulnerable_size": old_info.size_bytes,
                "patched_size": new_info.size_bytes,
            }
            store.create(record)
            supervisor.submit(job_id)
            return {"id": job_id, "status": "running", "stage": "VALIDATING",
                    "profile": "controlled-linux-amd64-shared-object-v1",
                    "artifacts": {"vulnerable": {"filename": old_name, "sha256": old_info.sha256,
                                                   "size_bytes": old_info.size_bytes, "elf": old_info.to_dict()},
                                  "patched": {"filename": new_name, "sha256": new_info.sha256,
                                              "size_bytes": new_info.size_bytes, "elf": new_info.to_dict()}}}
        except HTTPException:
            _remove_created_job_dir(job_dir, settings.quarantine_dir)
            raise
        except (ELFValidationError, OSError) as exc:
            _remove_created_job_dir(job_dir, settings.quarantine_dir)
            raise HTTPException(422, str(exc)) from exc
        except Exception:
            _remove_created_job_dir(job_dir, settings.quarantine_dir)
            raise
        finally:
            await vulnerable[0].close()
            await patched[0].close()

    @app.get("/api/v1/analyses")
    async def list_analyses(limit: int = Query(50, ge=1, le=100)) -> dict[str, Any]:
        return {"items": [_public_job(item, include_result=False) for item in store.list(limit)]}

    @app.get("/api/v1/analyses/{job_id}")
    async def get_analysis(job_id: str) -> dict[str, Any]:
        return _require_job(store, job_id)

    @app.get("/api/v1/analyses/{job_id}/evidence")
    async def get_evidence(job_id: str) -> dict[str, Any]:
        job = _require_completed_job(store, job_id)
        result = job["result"]
        return {"job_id": job_id, "items": result.get("evidence", []),
                "artifacts": {side: result["artifacts"][side]["sha256"] for side in ("vulnerable", "patched")}}

    @app.get("/api/v1/analyses/{job_id}/verification")
    async def get_verification(job_id: str) -> dict[str, Any]:
        job = _require_completed_job(store, job_id)
        return {"job_id": job_id, "result": job["result"].get("verification"),
                "inference": job["result"].get("inference"),
                "abstentions": job["result"].get("abstentions", [])}

    @app.get("/api/v1/analyses/{job_id}/diff")
    async def get_diff(job_id: str) -> dict[str, Any]:
        job = _require_completed_job(store, job_id)
        return {"job_id": job_id, "result": job["result"].get("comparison")}

    @app.get("/api/v1/analyses/{job_id}/intelligence")
    async def get_intelligence(job_id: str) -> dict[str, Any]:
        job = _require_completed_job(store, job_id)
        result = job["result"]
        if not result.get("intelligence"):
            result["intelligence"] = build_explanation(result)
            store.update(job_id, result_json=result)
        return {"job_id": job_id, **result["intelligence"]}

    @app.get("/api/v1/analyses/{job_id}/report")
    async def get_report(job_id: str, format: str = Query("json", pattern="^(json|html)$")) -> Response:
        job = _require_completed_job(store, job_id)
        intelligence = job["result"].get("intelligence") or build_explanation(job["result"])
        if not job["result"].get("intelligence"):
            job["result"]["intelligence"] = intelligence
            store.update(job_id, result_json=job["result"])
        if format == "html":
            return HTMLResponse(render_html(job, intelligence), headers={
                "Content-Disposition": f'attachment; filename="vulngenome-{job_id}.html"'
            })
        return Response(json_report(job, intelligence), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="vulngenome-{job_id}.json"'})

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> FileResponse:
        return FileResponse(LITE_ROOT / "frontend" / "index.html")

    return app


def _sanitize_filename(filename: str | None, role: str) -> str:
    candidate = (filename or f"{role}.elf").replace("\\", "/").replace("\x00", "")
    return PurePosixPath(candidate).name[:160] or f"{role}.elf"


async def _persist_upload(
    upload: UploadFile, target: Path, max_bytes: int, role: str
) -> tuple[Path, str, Any]:
    import hashlib
    digest = hashlib.sha256()
    size = 0
    chunks: list[bytes] = []
    with target.open("xb") as output:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(413, f"{role.title()} upload exceeds the {max_bytes // (1024 * 1024)} MiB limit.")
            digest.update(chunk)
            chunks.append(chunk)
            output.write(chunk)
    data = b"".join(chunks)
    info = validate_elf64_amd64_shared_object(data)
    if digest.hexdigest() != info.sha256:
        raise RuntimeError("server-side upload hash mismatch")
    return target, _sanitize_filename(upload.filename, role), info


def _remove_created_job_dir(path: Path, quarantine: Path) -> None:
    resolved, parent = path.resolve(), quarantine.resolve()
    if resolved.parent == parent and resolved.name and resolved.exists():
        shutil.rmtree(resolved, ignore_errors=True)


def _public_job(job: dict[str, Any], include_result: bool) -> dict[str, Any]:
    keys = {"id", "status", "stage", "created_at", "updated_at", "vulnerable_name", "patched_name",
            "vulnerable_sha256", "patched_sha256", "vulnerable_size", "patched_size", "error"}
    result = {key: job[key] for key in keys if key in job}
    if include_result:
        result["result"] = job.get("result")
    return result


def _require_job(store: JobStore, job_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise HTTPException(404, "Analysis not found")
    job = store.get(job_id)
    if not job:
        raise HTTPException(404, "Analysis not found")
    return _public_job(job, include_result=True)


def _require_completed_job(store: JobStore, job_id: str) -> dict[str, Any]:
    job = _require_job(store, job_id)
    if job["status"] not in {"completed", "inconclusive"} or not job.get("result"):
        raise HTTPException(409, f"Analysis is not ready (stage {job['stage']}).")
    return job


app = create_app()
