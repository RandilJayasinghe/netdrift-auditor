"""Lateral-movement path search over the policy graph."""
from __future__ import annotations

from ipaddress import IPv4Network
from itertools import islice

import networkx as nx

from ..errors import ProfileError
from ..models import Severity
from ..schemas import AttackPath, AuditProfile, PathHop


def resolve_entry_points(g: nx.DiGraph, specs: list[str]) -> list[str]:
    found: list[str] = []
    for spec in specs:
        s = spec.strip().lower()
        hits: list[str] = []
        try:
            cidr = IPv4Network(spec.strip(), strict=False)
        except ValueError:
            cidr = None
        for nid, d in g.nodes(data=True):
            info = d["info"]
            if s in (nid.lower(), info.label.lower(), info.zone.lower()) or (s == "internet" and info.kind == "internet"):
                if info.kind != "asset" or s in (nid.lower(), info.label.lower()):
                    hits.append(nid)
            elif cidr is not None and info.kind == "segment" and any(cidr.overlaps(n) for n in info.networks):
                hits.append(nid)
        if not hits:
            raise ProfileError(f"entry point '{spec}' matches no node (try a zone name, CIDR, 'internet', or one of: "
                               + ", ".join(sorted(n for n in g.nodes)) + ")")
        found.extend(h for h in hits if h not in found)
    return found


def path_severity(target_crit: Severity, hops: int) -> Severity:
    return target_crit.lowered(0 if hops <= 1 else 1 if hops <= 3 else 2)


def _hops(g: nx.DiGraph, nodes: list[str]) -> list[PathHop]:
    out = []
    for u, v in zip(nodes, nodes[1:]):
        e = g.edges[u, v]
        out.append(PathHop(src_id=u, dst_id=v, src=g.nodes[u]["info"].label, dst=g.nodes[v]["info"].label,
                           rule_ids=list(e["rule_ids"]), services=list(e["services"]), implicit=e["implicit"],
                           nat=list(e.get("nat", []))))
    return out


def find_attack_paths(g: nx.DiGraph, profile: AuditProfile) -> list[AttackPath]:
    """Yen's k-shortest simple paths from every entry node to every critical asset, bounded by
    `max_hops` and `max_paths_per_target`; shortest (most dangerous) paths are produced first."""
    entries = resolve_entry_points(g, profile.entry_points)
    results: list[AttackPath] = []
    for asset in profile.critical_assets:
        tid = f"asset:{asset.name}"
        if tid not in g:
            continue
        for e in entries:
            if e == tid or not nx.has_path(g, e, tid):
                continue
            for nodes in islice(nx.shortest_simple_paths(g, e, tid), profile.max_paths_per_target):
                hops = len(nodes) - 1
                if hops > profile.max_hops:
                    break
                results.append(AttackPath(
                    entry=g.nodes[e]["info"].label, target=asset.name, target_category=asset.category,
                    length=hops, severity=path_severity(asset.criticality, hops), hops=_hops(g, nodes)))
    results.sort(key=lambda p: (p.severity.rank, p.length, p.target, p.entry))
    return results
