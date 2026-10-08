"""Audit-level request/response models."""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Network
from typing import Optional

from pydantic import BaseModel, Field

from .models import Severity


class CriticalAsset(BaseModel):
    name: str
    cidr: IPv4Network
    zone: Optional[str] = Field(None, description="Inferred from interface subnets when omitted")
    criticality: Severity = Severity.CRITICAL
    category: str = "generic"


class AuditProfile(BaseModel):
    entry_points: list[str] = Field(min_length=1, description="Node id / label / zone name / CIDR / 'internet'")
    critical_assets: list[CriticalAsset] = Field(min_length=1)
    max_hops: int = Field(5, ge=1, le=10)
    max_paths_per_target: int = Field(10, ge=1, le=100)


class Finding(BaseModel):
    id: str = ""
    category: str
    severity: Severity
    title: str
    description: str
    rule_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    compliance: list[str] = Field(default_factory=list)


class PathHop(BaseModel):
    src_id: str
    dst_id: str
    src: str
    dst: str
    rule_ids: list[str]
    services: list[str]
    implicit: bool = False
    nat: list[str] = Field(default_factory=list, description="Address translations applied on this hop")


class AttackPath(BaseModel):
    entry: str
    target: str
    target_category: str = "generic"
    length: int
    severity: Severity
    hops: list[PathHop]

    @property
    def rule_ids(self) -> list[str]:
        seen: list[str] = []
        for h in self.hops:
            for r in h.rule_ids:
                if r not in seen:
                    seen.append(r)
        return seen


class ComplianceItem(BaseModel):
    requirement: str
    description: str
    status: str  # PASS | WARN | FAIL
    finding_ids: list[str] = Field(default_factory=list)


class ScoreCard(BaseModel):
    score: float
    grade: str
    counts: dict[str, int]
    penalty_findings: float
    penalty_paths: float


class DriftSummary(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    reordered: int = 0


class AuditResult(BaseModel):
    audit_id: str
    config_id: str = ""
    hostname: str
    vendor: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_count: int
    graph_nodes: int
    graph_edges: int
    score: ScoreCard
    findings: list[Finding]
    attack_paths: list[AttackPath]
    compliance: list[ComplianceItem]
    drift: Optional[DriftSummary] = None
    warnings: list[str] = Field(default_factory=list)
