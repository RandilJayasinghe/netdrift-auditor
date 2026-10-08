"""Persistent repository over the SQLAlchemy schema (replaces the old in-memory LRU store).

Rules enforced here, in one place:
* every query is scoped by `tenant_id` (a foreign tenant's id is indistinguishable from a missing one);
* configs are only accepted together with a `SanitizedConfig`, re-verified with `verify_sanitized`
  immediately before the INSERT, and the canonical JSON is scanned for residual secrets as well;
* audit results and findings are written in one transaction.
"""
from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, sessionmaker

from ..engine import AuditRun, rebuild_graph
from ..models import FirewallConfig
from ..sanitizer import SanitizedConfig, find_residual_secrets, sanitize_config, verify_sanitized
from ..errors import SecretLeakError
from ..schemas import AuditProfile, AuditResult, Finding
from . import db
from .db import AuditRow, BaselineRow, ConfigRow, FindingRow, JobRow, utcnow


def _utc(d: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; everything we store is UTC."""
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def new_id() -> str:
    return uuid.uuid4().hex[:12]


class Store:
    def __init__(self, url: str = "sqlite:///netdrift.db") -> None:
        self.url = url
        self.engine = db.make_engine(url)
        db.create_schema(self.engine)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as s:
            try:
                yield s
                s.commit()
            except Exception:
                s.rollback()
                raise

    def close(self) -> None:
        self.engine.dispose()

    # ---- configs ------------------------------------------------------------------------------
    def put_config(self, tenant: str, cfg: FirewallConfig, sanitized: SanitizedConfig) -> str:
        if not isinstance(sanitized, SanitizedConfig):
            raise SecretLeakError("put_config requires a SanitizedConfig")
        verify_sanitized(sanitized.text)
        cfg_json = cfg.model_dump_json()
        leaks = find_residual_secrets(cfg_json)
        if leaks:
            raise SecretLeakError("parsed configuration contains secret material: " + ", ".join(leaks))
        cid = new_id()
        with self.session() as s:
            s.add(ConfigRow(id=cid, tenant_id=tenant, hostname=cfg.hostname, vendor=cfg.vendor, sha256=sanitized.sha256,
                            redactions=sanitized.redactions, sanitized_text=sanitized.text, config_json=cfg_json))
        return cid

    def get_config(self, tenant: str, config_id: str) -> Optional[FirewallConfig]:
        with self.session() as s:
            row = s.scalar(select(ConfigRow).where(ConfigRow.id == config_id, ConfigRow.tenant_id == tenant))
            return FirewallConfig.model_validate_json(row.config_json) if row else None

    def list_configs(self, tenant: str, limit: int = 100) -> list[dict]:
        with self.session() as s:
            rows = s.scalars(select(ConfigRow).where(ConfigRow.tenant_id == tenant).order_by(ConfigRow.created_at.desc()).limit(limit))
            return [{"config_id": r.id, "hostname": r.hostname, "vendor": r.vendor, "sha256": r.sha256,
                     "redactions": r.redactions, "created_at": _utc(r.created_at)} for r in rows]

    def delete_config(self, tenant: str, config_id: str) -> bool:
        with self.session() as s:
            if s.scalar(select(ConfigRow.id).where(ConfigRow.id == config_id, ConfigRow.tenant_id == tenant)) is None:
                return False
            audit_ids = list(s.scalars(select(AuditRow.id).where(AuditRow.config_id == config_id)))
            if audit_ids:
                s.execute(delete(FindingRow).where(FindingRow.audit_id.in_(audit_ids)))
                s.execute(delete(AuditRow).where(AuditRow.id.in_(audit_ids)))
            s.execute(delete(BaselineRow).where(BaselineRow.config_id == config_id))
            s.execute(delete(JobRow).where(JobRow.config_id == config_id))
            s.execute(delete(ConfigRow).where(ConfigRow.id == config_id))
            return True

    # ---- baselines ----------------------------------------------------------------------------
    def create_baseline(self, tenant: str, name: str, config_id: str) -> Optional[dict]:
        with self.session() as s:
            if s.scalar(select(ConfigRow.id).where(ConfigRow.id == config_id, ConfigRow.tenant_id == tenant)) is None:
                return None
            row = BaselineRow(id=new_id(), tenant_id=tenant, name=name, config_id=config_id)
            s.add(row)
            return {"baseline_id": row.id, "name": name, "config_id": config_id}

    def list_baselines(self, tenant: str) -> list[dict]:
        with self.session() as s:
            rows = s.scalars(select(BaselineRow).where(BaselineRow.tenant_id == tenant).order_by(BaselineRow.created_at.desc()))
            return [{"baseline_id": r.id, "name": r.name, "config_id": r.config_id, "created_at": _utc(r.created_at)} for r in rows]

    def baseline_config_id(self, tenant: str, baseline_id: str) -> Optional[str]:
        with self.session() as s:
            return s.scalar(select(BaselineRow.config_id).where(BaselineRow.id == baseline_id, BaselineRow.tenant_id == tenant))

    # ---- audit runs ---------------------------------------------------------------------------
    def save_audit(self, tenant: str, run: AuditRun, profile: AuditProfile, baseline_config_id: str | None = None) -> str:
        r = run.result
        with self.session() as s:
            s.add(AuditRow(id=r.audit_id, tenant_id=tenant, config_id=r.config_id, baseline_config_id=baseline_config_id,
                           hostname=r.hostname, vendor=r.vendor, score=r.score.score, grade=r.score.grade,
                           profile_json=profile.model_dump_json(), result_json=r.model_dump_json()))
            s.flush()
            for f in r.findings:
                s.add(FindingRow(audit_id=r.audit_id, tenant_id=tenant, ref=f.id, category=f.category, severity=f.severity.value,
                                 title=f.title, body_json=f.model_dump_json()))
        return r.audit_id

    def get_result(self, tenant: str, audit_id: str) -> Optional[AuditResult]:
        with self.session() as s:
            row = s.scalar(select(AuditRow).where(AuditRow.id == audit_id, AuditRow.tenant_id == tenant))
            return AuditResult.model_validate_json(row.result_json) if row else None

    def get_run(self, tenant: str, audit_id: str) -> Optional[AuditRun]:
        """Result plus a rebuilt policy graph (needed by the attack-path / cytoscape reports)."""
        with self.session() as s:
            row = s.scalar(select(AuditRow).where(AuditRow.id == audit_id, AuditRow.tenant_id == tenant))
            if row is None:
                return None
            result = AuditResult.model_validate_json(row.result_json)
            profile = AuditProfile.model_validate_json(row.profile_json)
            cfg_json = s.scalar(select(ConfigRow.config_json).where(ConfigRow.id == row.config_id))
        return AuditRun(result, rebuild_graph(FirewallConfig.model_validate_json(cfg_json), profile))

    def list_findings(self, tenant: str, audit_id: str, severity: str | None = None, category: str | None = None) -> Optional[list[Finding]]:
        with self.session() as s:
            if s.scalar(select(AuditRow.id).where(AuditRow.id == audit_id, AuditRow.tenant_id == tenant)) is None:
                return None
            q = select(FindingRow.body_json).where(FindingRow.audit_id == audit_id, FindingRow.tenant_id == tenant).order_by(FindingRow.pk)
            if severity:
                q = q.where(FindingRow.severity == severity)
            if category:
                q = q.where(FindingRow.category == category)
            return [Finding.model_validate_json(b) for b in s.scalars(q)]

    # ---- jobs ---------------------------------------------------------------------------------
    def create_job(self, tenant: str, config_id: str, baseline_config_id: str | None, profile: AuditProfile) -> str:
        jid = new_id()
        with self.session() as s:
            s.add(JobRow(id=jid, tenant_id=tenant, status="queued", config_id=config_id, baseline_config_id=baseline_config_id,
                         profile_json=profile.model_dump_json()))
        return jid

    def get_job(self, tenant: str, job_id: str) -> Optional[dict]:
        with self.session() as s:
            r = s.scalar(select(JobRow).where(JobRow.id == job_id, JobRow.tenant_id == tenant))
            return None if r is None else self._job_dict(r)

    def job_payload(self, job_id: str) -> Optional[tuple[str, str, str | None, AuditProfile]]:
        """Worker-side lookup (tenant comes from the job row itself): tenant, config_id, baseline, profile."""
        with self.session() as s:
            r = s.get(JobRow, job_id)
            return None if r is None else (r.tenant_id, r.config_id, r.baseline_config_id, AuditProfile.model_validate_json(r.profile_json))

    def mark_job(self, job_id: str, status: str, audit_id: str | None = None, error: str | None = None) -> None:
        vals: dict = {"status": status}
        now = utcnow()
        if status == "running":
            vals["started_at"] = now
        else:
            vals["finished_at"] = now
        if audit_id:
            vals["audit_id"] = audit_id
        if error is not None:
            vals["error"] = sanitize_config(error)[:2000]
        with self.session() as s:
            s.execute(update(JobRow).where(JobRow.id == job_id).values(**vals))

    def fail_stale_jobs(self) -> int:
        """Jobs left queued/running by a previous process can never finish (in-process workers)."""
        with self.session() as s:
            res = s.execute(update(JobRow).where(JobRow.status.in_(("queued", "running")))
                            .values(status="failed", error="interrupted by service restart", finished_at=utcnow()))
            return res.rowcount or 0

    @staticmethod
    def _job_dict(r: JobRow) -> dict:
        def iso(d: datetime | None) -> str | None:
            return _utc(d).isoformat() if d else None
        return {"job_id": r.id, "status": r.status, "config_id": r.config_id, "audit_id": r.audit_id, "error": r.error,
                "created_at": iso(r.created_at), "started_at": iso(r.started_at), "finished_at": iso(r.finished_at)}
