"""SQLAlchemy schema and engine factory. SQLite by default, PostgreSQL via `NETDRIFT_DATABASE_URL`
(e.g. `postgresql+psycopg://user:pw@host/netdrift`, needs `pip install "netdrift-auditor[postgres]"`).

Tables are created on start-up (`create_schema`, idempotent). Every row carries `tenant_id`; the
repository (`store.py`) filters on it for every query, so tenants cannot read each other's data.
Document-shaped payloads (parsed config, audit result) are stored as JSON text for portability
across SQLite/PostgreSQL; the fields queried on are real columns with indexes.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool

SCHEMA_VERSION = 1


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ConfigRow(Base):
    __tablename__ = "configs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64))
    redactions: Mapped[int] = mapped_column(Integer, default=0)
    sanitized_text: Mapped[str] = mapped_column(Text)  # post-sanitization only (see store.put_config)
    config_json: Mapped[str] = mapped_column(Text)     # canonical FirewallConfig
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BaselineRow(Base):
    __tablename__ = "baselines"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    config_id: Mapped[str] = mapped_column(ForeignKey("configs.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditRow(Base):
    __tablename__ = "audit_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    config_id: Mapped[str] = mapped_column(ForeignKey("configs.id", ondelete="CASCADE"), index=True)
    baseline_config_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float)
    grade: Mapped[str] = mapped_column(String(2))
    profile_json: Mapped[str] = mapped_column(Text)
    result_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingRow(Base):
    __tablename__ = "findings"
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id", ondelete="CASCADE"))
    tenant_id: Mapped[str] = mapped_column(String(64))
    ref: Mapped[str] = mapped_column(String(16))  # ND-0001
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    body_json: Mapped[str] = mapped_column(Text)
    __table_args__ = (Index("ix_findings_audit_sev", "audit_id", "severity"), Index("ix_findings_tenant", "tenant_id"))


class JobRow(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # queued | running | succeeded | failed
    config_id: Mapped[str] = mapped_column(String(32))
    baseline_config_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    profile_json: Mapped[str] = mapped_column(Text)
    audit_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MetaRow(Base):
    __tablename__ = "schema_meta"
    key: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[str] = mapped_column(String(64))


def make_engine(url: str) -> Engine:
    kw: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if url in ("sqlite://", "sqlite:///:memory:") or ":memory:" in url:
            kw["poolclass"] = StaticPool  # one shared connection so every thread sees the same in-memory DB
    engine = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _rec):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            if ":memory:" not in url and url not in ("sqlite://",):
                cur.execute("PRAGMA journal_mode=WAL")  # readers do not block the job worker's writes
            cur.close()
    return engine


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import Session
    with Session(engine) as s:
        if s.get(MetaRow, "schema_version") is None:
            s.add(MetaRow(key="schema_version", value=str(SCHEMA_VERSION)))
            s.commit()
