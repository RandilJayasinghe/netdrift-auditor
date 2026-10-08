"""Orchestrates one audit run end to end."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

import networkx as nx

from .analysis.anomalies import (ISO_822, PCI_131, detect_hygiene, detect_mgmt_exposure, detect_nat_exposure,
                                 detect_permissive, detect_shadowed)
from .analysis.drift import diff_configs
from .analysis.index import compile_rules
from .analysis.scoring import compliance_matrix, compute_score
from .graph.builder import build_graph
from .graph.paths import find_attack_paths
from .models import FirewallConfig
from .schemas import AttackPath, AuditProfile, AuditResult, Finding


@dataclass
class AuditRun:
    result: AuditResult
    graph: nx.DiGraph


def _path_findings(paths: list[AttackPath]) -> list[Finding]:
    best: dict[tuple[str, str], AttackPath] = {}
    count: dict[tuple[str, str], int] = {}
    for p in paths:
        k = (p.entry, p.target)
        count[k] = count.get(k, 0) + 1
        if k not in best:
            best[k] = p  # paths are sorted shortest/most severe first
    out = []
    for k, p in best.items():
        chain = " -> ".join([p.hops[0].src] + [h.dst for h in p.hops])
        fw_hops = [h for h in p.hops if not h.implicit]
        out.append(Finding(
            category="ATTACK_PATH", severity=p.severity,
            title=f"Lateral movement: {p.entry} can reach {p.target} in {p.length} hop(s)",
            description=f"Shortest path: {chain}. {count[k]} distinct path(s) found. Per-hop services: "
                        + "; ".join(f"{h.src}->{h.dst} [{', '.join(h.services[:4])}]" for h in p.hops),
            rule_ids=p.rule_ids,
            remediation=("Break the path at its first firewall-enforced hop: tighten or remove rule(s) "
                         + ", ".join(dict.fromkeys(r for h in fw_hops[:1] for r in h.rule_ids)) +
                         ", then re-run the audit to confirm all paths to the asset are closed.") if fw_hops else
                        "Path is entirely within one L2 segment; micro-segment the asset (private VLAN / host firewall).",
            compliance=[PCI_131, ISO_822]))
    return out


def run_audit(config: FirewallConfig, profile: AuditProfile, baseline: Optional[FirewallConfig] = None,
              config_id: str = "", audit_id: str | None = None) -> AuditRun:
    compiled = compile_rules(config)
    findings: list[Finding] = []
    findings += detect_shadowed(compiled)
    findings += detect_permissive(config, compiled)
    findings += detect_mgmt_exposure(config, compiled)
    findings += detect_hygiene(compiled)
    findings += detect_nat_exposure(config)

    graph, gwarn = build_graph(config, compiled, profile)
    paths = find_attack_paths(graph, profile)
    findings += _path_findings(paths)

    drift = None
    if baseline is not None:
        drift, dfind = diff_configs(compile_rules(baseline), compiled)
        findings += dfind

    findings.sort(key=lambda f: (f.severity.rank, f.category, f.rule_ids))
    for i, f in enumerate(findings, 1):
        f.id = f"ND-{i:04d}"

    result = AuditResult(
        audit_id=audit_id or uuid.uuid4().hex[:12], config_id=config_id, hostname=config.hostname, vendor=config.vendor,
        rule_count=len(config.rules), graph_nodes=graph.number_of_nodes(), graph_edges=graph.number_of_edges(),
        score=compute_score(findings, paths), findings=findings, attack_paths=paths,
        compliance=compliance_matrix(findings), drift=drift, warnings=[*config.warnings, *gwarn])
    return AuditRun(result, graph)


def rebuild_graph(config: FirewallConfig, profile: AuditProfile) -> nx.DiGraph:
    """Deterministically recreate the policy graph of a stored audit (graphs are not persisted)."""
    graph, _ = build_graph(config, compile_rules(config), profile)
    return graph
