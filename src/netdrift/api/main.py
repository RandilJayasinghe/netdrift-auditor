"""FastAPI service. Run: uvicorn netdrift.api.main:app --reload

Environment (see README): NETDRIFT_DATABASE_URL, NETDRIFT_API_KEY / NETDRIFT_API_KEYS / NETDRIFT_JWT_SECRET,
NETDRIFT_RATE_LIMIT(_HEAVY), NETDRIFT_MAX_UPLOAD_BYTES, NETDRIFT_MAX_JSON_BYTES, NETDRIFT_ASYNC_WORKERS.
"""
from __future__ import annotations

import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..engine import run_audit
from ..errors import NetDriftError, ProfileError, SecretLeakError
from ..graph.cytoscape import to_cytoscape
from ..models import Severity
from ..parsers import parse_config
from ..reports.markdown import render_markdown
from ..reports.pdf import render_pdf
from ..sanitizer import install_log_redaction, sanitize_for_storage
from ..schemas import AuditProfile, AuditResult, Finding
from .jobs import make_runner
from .security import BodyLimitMiddleware, Limiters, Principal, RateLimiter, auth_config, guard
from .settings import Settings
from .store import Store

log = logging.getLogger("netdrift")
STATIC_DIR = Path(__file__).parent / "static"


class UploadResponse(BaseModel):
    config_id: str
    vendor: str
    hostname: str
    rules: int
    zones: list[str]
    address_objects: int
    redactions: int = 0
    warnings: list[str]


class AnalyzeRequest(BaseModel):
    config_id: str
    profile: AuditProfile
    baseline_config_id: Optional[str] = None
    baseline_id: Optional[str] = Field(None, description="A saved baseline snapshot (alternative to baseline_config_id)")


class BaselineRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    config_id: str


class JobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "succeeded", "failed"]
    config_id: str
    audit_id: Optional[str] = None
    error: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    poll_url: str = ""
    result_url: Optional[str] = None


def _job_view(d: dict) -> JobStatus:
    js = JobStatus(**d, poll_url=f"/api/v1/audit/jobs/{d['job_id']}")
    if js.audit_id:
        js.result_url = f"/api/v1/reports/summary?audit_id={js.audit_id}&format=json"
    return js


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.require_auth and not auth_config().enabled:
        raise RuntimeError("NETDRIFT_REQUIRE_AUTH is set but no NETDRIFT_API_KEY(S) / NETDRIFT_JWT_SECRET is configured")
    install_log_redaction("netdrift")
    store = Store(settings.database_url)
    runner = make_runner(store, settings.async_workers)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        n = store.fail_stale_jobs()
        if n:
            log.warning("marked %d interrupted job(s) as failed", n)
        if not auth_config().enabled:
            log.warning("authentication is DISABLED (no API keys / JWT secret configured); every caller is admin")
        yield
        runner.shutdown()
        store.close()

    app = FastAPI(title="NetDrift-Auditor", version=__version__, lifespan=lifespan)
    app.state.store = store
    app.state.settings = settings
    app.state.limiters = Limiters(RateLimiter(settings.rate_limit), RateLimiter(settings.rate_limit_heavy),
                                  RateLimiter(settings.auth_fail_limit))
    app.add_middleware(BodyLimitMiddleware, upload_limit=settings.max_upload_bytes, json_limit=settings.max_json_bytes)

    router = APIRouter(prefix="/api/v1")
    viewer, analyst, admin = guard("viewer"), guard("analyst"), guard("admin")
    analyst_heavy = guard("analyst", heavy=True)

    def _ingest(raw: bytes, vendor: Optional[str], tenant: str) -> UploadResponse:
        if b"\x00" in raw[:8192]:
            raise HTTPException(415, "binary data: upload a text/JSON configuration export")
        san = sanitize_for_storage(raw.decode("utf-8", errors="replace"))  # secrets are stripped before anything else
        try:
            cfg = parse_config(san.text, vendor)
            cid = store.put_config(tenant, cfg, san)
        except SecretLeakError as exc:
            log.error("upload rejected by secret-leak guard: %s", exc)
            raise HTTPException(422, "configuration contains credentials that could not be sanitized") from exc
        except NetDriftError as exc:
            raise HTTPException(422, str(exc)) from exc
        log.info("config %s parsed: tenant=%s vendor=%s rules=%d redactions=%d", cid, tenant, cfg.vendor, len(cfg.rules), san.redactions)
        return UploadResponse(config_id=cid, vendor=cfg.vendor, hostname=cfg.hostname, rules=len(cfg.rules), zones=sorted(cfg.zones),
                              address_objects=len(cfg.address_objects), redactions=san.redactions, warnings=cfg.warnings)

    @router.post("/audit/upload", response_model=UploadResponse, status_code=201)
    async def upload(file: UploadFile = File(...), vendor: Optional[str] = Form(None),
                     p: Principal = Depends(analyst_heavy)) -> UploadResponse:
        limit = settings.max_upload_bytes
        data = await file.read(limit + 1)
        if len(data) > limit:
            raise HTTPException(413, f"file exceeds {limit} bytes")
        if not data.strip():
            raise HTTPException(422, "empty file")
        return await run_in_threadpool(_ingest, data, vendor, p.tenant)

    @router.get("/configs")
    def configs(p: Principal = Depends(viewer)) -> list[dict]:
        return store.list_configs(p.tenant)

    @router.delete("/configs/{config_id}", status_code=204)
    def delete_config(config_id: str, p: Principal = Depends(admin)) -> Response:
        if not store.delete_config(p.tenant, config_id):
            raise HTTPException(404, "unknown config_id")
        return Response(status_code=204)

    @router.post("/baselines", status_code=201)
    def create_baseline(req: BaselineRequest, p: Principal = Depends(analyst)) -> dict:
        out = store.create_baseline(p.tenant, req.name, req.config_id)
        if out is None:
            raise HTTPException(404, "unknown config_id")
        return out

    @router.get("/baselines")
    def baselines(p: Principal = Depends(viewer)) -> list[dict]:
        return store.list_baselines(p.tenant)

    def _resolve(req: AnalyzeRequest, tenant: str):
        cfg = store.get_config(tenant, req.config_id)
        if cfg is None:
            raise HTTPException(404, "unknown config_id")
        base_cid = req.baseline_config_id
        if req.baseline_id:
            base_cid = store.baseline_config_id(tenant, req.baseline_id)
            if base_cid is None:
                raise HTTPException(404, "unknown baseline_id")
        base = None
        if base_cid:
            base = store.get_config(tenant, base_cid)
            if base is None:
                raise HTTPException(404, "unknown baseline_config_id")
        return cfg, base, base_cid

    @router.post("/audit/analyze", response_model=AuditResult)
    def analyze(req: AnalyzeRequest, p: Principal = Depends(analyst_heavy)) -> AuditResult:
        """Synchronous audit (sync `def`: FastAPI runs it in a worker thread). For large rulebases use /audit/jobs."""
        cfg, base, base_cid = _resolve(req, p.tenant)
        try:
            run = run_audit(cfg, req.profile, baseline=base, config_id=req.config_id)
        except ProfileError as exc:
            raise HTTPException(422, str(exc)) from exc
        store.save_audit(p.tenant, run, req.profile, base_cid)
        return run.result

    @router.post("/audit/jobs", response_model=JobStatus, status_code=202)
    def submit_job(req: AnalyzeRequest, response: Response, wait: bool = Query(False, description="Block until done (synchronous fallback)"),
                   p: Principal = Depends(analyst_heavy)) -> JobStatus:
        """Queue an audit and poll `GET /audit/jobs/{job_id}`. With `?wait=true` (or when the service runs with
        NETDRIFT_ASYNC_WORKERS=0) the job is executed before the response is returned."""
        _, _, base_cid = _resolve(req, p.tenant)
        jid = store.create_job(p.tenant, req.config_id, base_cid, req.profile)
        runner.submit(jid)
        if wait and settings.async_workers > 0:
            import time
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                job = store.get_job(p.tenant, jid)
                if job and job["status"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)
        job = store.get_job(p.tenant, jid)
        if job and job["status"] in ("succeeded", "failed"):
            response.status_code = 200
        return _job_view(job)

    @router.get("/audit/jobs/{job_id}", response_model=JobStatus)
    def job_status(job_id: str, p: Principal = Depends(viewer)) -> JobStatus:
        job = store.get_job(p.tenant, job_id)
        if job is None:
            raise HTTPException(404, "unknown job_id")
        return _job_view(job)

    @router.get("/audit/{audit_id}/findings", response_model=list[Finding])
    def findings(audit_id: str, severity: Optional[Severity] = None, category: Optional[str] = None,
                 p: Principal = Depends(viewer)) -> list[Finding]:
        out = store.list_findings(p.tenant, audit_id, severity.value if severity else None, category)
        if out is None:
            raise HTTPException(404, "unknown audit_id")
        return out

    def _run(audit_id: str, tenant: str):
        run = store.get_run(tenant, audit_id)
        if run is None:
            raise HTTPException(404, "unknown audit_id")
        return run

    @router.get("/reports/attack-paths")
    def attack_paths(audit_id: str, min_severity: Severity = Severity.INFO,
                     format: Literal["cytoscape", "json"] = "cytoscape", p: Principal = Depends(viewer)) -> dict:
        run = _run(audit_id, p.tenant)
        paths = [x for x in run.result.attack_paths if x.severity.rank <= min_severity.rank]
        if format == "json":
            return {"audit_id": audit_id, "paths": [x.model_dump(mode="json") for x in paths]}
        return to_cytoscape(run.graph, paths, run.result.hostname)

    @router.get("/reports/summary")
    def summary(audit_id: str, format: Literal["markdown", "pdf", "json"] = Query("markdown"), p: Principal = Depends(viewer)):
        if format == "json":
            res = store.get_result(p.tenant, audit_id)
            if res is None:
                raise HTTPException(404, "unknown audit_id")
            return res
        run = _run(audit_id, p.tenant)
        if format == "pdf":
            return Response(render_pdf(run.result), media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="netdrift-{audit_id}.pdf"'})
        return Response(render_markdown(run.result), media_type="text/markdown")

    app.include_router(router)

    # Dashboard: deliberately outside the guarded API router so the page itself always loads; every
    # data call it makes goes to /api/v1 and is authenticated there (the UI has a credentials field).
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
