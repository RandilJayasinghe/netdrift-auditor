"""Risk score (0-100, higher is better) and compliance matrix."""
from __future__ import annotations

from ..models import Severity
from ..schemas import AttackPath, ComplianceItem, Finding, ScoreCard

FINDING_W = {Severity.CRITICAL: 12.0, Severity.HIGH: 6.0, Severity.MEDIUM: 2.5, Severity.LOW: 0.5, Severity.INFO: 0.0}
PATH_W = {Severity.CRITICAL: 10.0, Severity.HIGH: 5.0, Severity.MEDIUM: 2.0, Severity.LOW: 0.5, Severity.INFO: 0.0}
CAP = 60.0  # per bucket, so one noisy category cannot zero the score on its own

REQUIREMENTS: dict[str, tuple[str, set[str]]] = {
    "PCI-DSS v4.0 1.2.5": ("Only necessary, approved services/protocols/ports are allowed", {"OVERLY_PERMISSIVE", "MGMT_EXPOSURE"}),
    "PCI-DSS v4.0 1.2.7": ("Network security control rule sets are reviewed regularly (no stale/shadowed/drifted rules)",
                           {"SHADOWED_RULE", "DISABLED_RULE", "UNUSED_RULE", "POLICY_DRIFT"}),
    "PCI-DSS v4.0 1.3.1": ("Inbound traffic to the CDE is restricted to what is necessary",
                           {"OVERLY_PERMISSIVE", "MGMT_EXPOSURE", "NAT_EXPOSURE", "ATTACK_PATH"}),
    "ISO 27001:2022 A.8.22": ("Segregation of networks (no unmonitored lateral paths to critical segments)", {"ATTACK_PATH", "MGMT_EXPOSURE"}),
}


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 50 else "F"


def compute_score(findings: list[Finding], paths: list[AttackPath]) -> ScoreCard:
    non_path = [f for f in findings if f.category != "ATTACK_PATH"]
    pf = min(CAP, sum(FINDING_W[f.severity] for f in non_path))
    worst: dict[tuple[str, str], Severity] = {}
    for p in paths:
        k = (p.entry, p.target)
        if k not in worst or p.severity.rank < worst[k].rank:
            worst[k] = p.severity
    pp = min(CAP, sum(PATH_W[s] for s in worst.values()))
    score = round(max(0.0, 100.0 - pf - pp), 1)
    counts = {s.value: sum(1 for f in findings if f.severity is s) for s in Severity}
    return ScoreCard(score=score, grade=grade(score), counts=counts, penalty_findings=round(pf, 1), penalty_paths=round(pp, 1))


def compliance_matrix(findings: list[Finding]) -> list[ComplianceItem]:
    items: list[ComplianceItem] = []
    for req, (desc, cats) in REQUIREMENTS.items():
        rel = [f for f in findings if f.category in cats and (not f.compliance or req in f.compliance or f.category == "ATTACK_PATH")]
        if any(f.severity.rank <= Severity.MEDIUM.rank for f in rel):
            status = "FAIL"
        elif any(f.severity is not Severity.INFO for f in rel):
            status = "WARN"
        else:
            status = "PASS"
        items.append(ComplianceItem(requirement=req, description=desc, status=status, finding_ids=[f.id for f in rel]))
    return items
