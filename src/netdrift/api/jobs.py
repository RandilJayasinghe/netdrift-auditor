"""Asynchronous audit execution.

`JobRunner` is the seam: `submit(job_id)` must eventually call `execute_job(store, job_id)` in some
worker. `ThreadJobRunner` (default) runs jobs on an in-process thread pool and `InlineJobRunner`
(`NETDRIFT_ASYNC_WORKERS=0`) runs them before returning - the synchronous fallback. To scale out,
implement `JobRunner.submit` as `celery_task.delay(job_id)` / `rq_queue.enqueue(execute_job, store, job_id)`:
all job state lives in the database, so any worker process that shares it can pick the job up.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from ..engine import run_audit
from ..errors import NetDriftError
from .store import Store

log = logging.getLogger("netdrift.jobs")


class JobRunner(Protocol):
    def submit(self, job_id: str) -> None: ...
    def shutdown(self) -> None: ...


def execute_job(store: Store, job_id: str) -> None:
    """Run one queued job to completion; never raises (failures are recorded on the job row)."""
    payload = store.job_payload(job_id)
    if payload is None:
        log.error("job %s vanished before execution", job_id)
        return
    tenant, config_id, baseline_id, profile = payload
    store.mark_job(job_id, "running")
    try:
        cfg = store.get_config(tenant, config_id)
        if cfg is None:
            raise NetDriftError("configuration no longer exists")
        base = store.get_config(tenant, baseline_id) if baseline_id else None
        if baseline_id and base is None:
            raise NetDriftError("baseline configuration no longer exists")
        run = run_audit(cfg, profile, baseline=base, config_id=config_id)
        store.save_audit(tenant, run, profile, baseline_id)
        store.mark_job(job_id, "succeeded", audit_id=run.result.audit_id)
        log.info("job %s succeeded: audit %s", job_id, run.result.audit_id)
    except NetDriftError as exc:
        store.mark_job(job_id, "failed", error=str(exc))
        log.warning("job %s failed: %s", job_id, exc)
    except Exception as exc:  # noqa: BLE001 - a worker must survive any single job
        store.mark_job(job_id, "failed", error=f"internal error: {type(exc).__name__}")
        log.exception("job %s crashed", job_id)


class InlineJobRunner:
    def __init__(self, store: Store) -> None:
        self.store = store

    def submit(self, job_id: str) -> None:
        execute_job(self.store, job_id)

    def shutdown(self) -> None:
        pass


class ThreadJobRunner:
    def __init__(self, store: Store, workers: int = 2) -> None:
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netdrift-job")

    def submit(self, job_id: str) -> None:
        self._pool.submit(execute_job, self.store, job_id)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def make_runner(store: Store, workers: int) -> JobRunner:
    return InlineJobRunner(store) if workers <= 0 else ThreadJobRunner(store, workers)
