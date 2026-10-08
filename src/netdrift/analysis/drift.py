"""Baseline-vs-current policy drift (semantic, order-insensitive signature + order check)."""
from __future__ import annotations

from ..models import Action, Severity
from ..schemas import DriftSummary, Finding
from .anomalies import PCI_127
from .index import CompiledRule


def _sig(cr: CompiledRule) -> tuple:
    r = cr.rule
    return (r.action.value, r.src_zone, r.dst_zone, tuple(sorted(map(str, cr.src))),
            tuple(sorted(map(str, cr.dst))), tuple(cr.ports.labels()), r.enabled)


def diff_configs(base: list[CompiledRule], cur: list[CompiledRule]) -> tuple[DriftSummary, list[Finding]]:
    bsig = {}
    for c in base:
        bsig.setdefault(_sig(c), c)
    csig = {}
    for c in cur:
        csig.setdefault(_sig(c), c)
    added = [c for s, c in csig.items() if s not in bsig]
    removed = [c for s, c in bsig.items() if s not in csig]
    findings: list[Finding] = []

    for c in added:
        r = c.rule
        risky = r.action is Action.ALLOW and (c.ports.is_everything() or r.src_any or r.dst_any)
        sev = Severity.HIGH if risky else (Severity.MEDIUM if r.action is Action.ALLOW else Severity.LOW)
        findings.append(Finding(
            category="POLICY_DRIFT", severity=sev, title=f"Rule {r.id} added since baseline ({r.action.value} {r.src_zone}->{r.dst_zone})",
            description=f"New/changed rule: {r.src_ref} -> {r.dst_ref} service {r.svc_ref}. {('Comment: ' + r.comment) if r.comment else ''}".strip(),
            rule_ids=[r.id], remediation="Verify a change ticket exists; if it was an emergency change, schedule its review/removal.",
            compliance=[PCI_127]))
    for c in removed:
        r = c.rule
        sev = Severity.MEDIUM if r.action is Action.DENY else Severity.INFO
        findings.append(Finding(
            category="POLICY_DRIFT", severity=sev, title=f"Baseline rule {r.id} removed or modified ({r.action.value} {r.src_zone}->{r.dst_zone})",
            description=f"Baseline rule {r.src_ref} -> {r.dst_ref} service {r.svc_ref} no longer exists in the current policy.",
            rule_ids=[r.id], remediation="Confirm the removal was approved; removed deny rules widen the attack surface.", compliance=[PCI_127]))

    common = [s for s in bsig if s in csig]
    b_order = common
    c_order = [s for s in csig if s in bsig]
    reordered = sum(1 for x, y in zip(b_order, c_order) if x != y)
    if reordered:
        findings.append(Finding(
            category="POLICY_DRIFT", severity=Severity.MEDIUM, title=f"Rule order changed for {reordered} rule position(s)",
            description="First-match semantics make rule order security-relevant; relative order of unchanged rules differs from baseline.",
            remediation="Review the diff; restore baseline ordering unless the change was approved.", compliance=[PCI_127]))
    return DriftSummary(added=[c.rule.id for c in added], removed=[c.rule.id for c in removed], reordered=reordered), findings
