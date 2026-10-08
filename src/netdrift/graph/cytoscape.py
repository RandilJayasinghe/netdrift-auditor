"""Cytoscape.js-compatible export (also trivially mappable to D3 force graphs)."""
from __future__ import annotations

import networkx as nx

from ..schemas import AttackPath


def to_cytoscape(g: nx.DiGraph, paths: list[AttackPath], hostname: str = "firewall") -> dict:
    atk_edges = {(h.src_id, h.dst_id): p.severity.value for p in paths for h in p.hops}
    atk_nodes = {n for p in paths for h in p.hops for n in (h.src_id, h.dst_id)}
    fw = f"fw:{hostname}"
    nodes = [{"data": {"id": fw, "label": hostname, "type": "firewall"}, "classes": "firewall"}]
    edges = []
    for nid, d in g.nodes(data=True):
        i = d["info"]
        cls = [i.kind] + (["attack"] if nid in atk_nodes else []) + ([f"crit-{i.criticality.value}"] if i.criticality else [])
        nodes.append({"data": {"id": nid, "label": i.label, "type": i.kind, "zone": i.zone,
                               "networks": [str(n) for n in i.networks], "category": i.category},
                      "classes": " ".join(cls)})
        if i.kind != "asset":
            edges.append({"data": {"id": f"att:{nid}", "source": nid, "target": fw, "type": "attachment"}, "classes": "attachment"})
    for u, v, e in g.edges(data=True):
        sev = atk_edges.get((u, v))
        edges.append({"data": {"id": f"{u}->{v}", "source": u, "target": v, "type": "flow", "label": ", ".join(e["services"][:3]),
                               "services": e["services"], "rules": e["rule_ids"], "implicit": e["implicit"], "nat": e.get("nat", []),
                               "attack_severity": sev},
                      "classes": ("attack " + sev if sev else "") + (" implicit" if e["implicit"] else "")})
    return {"elements": {"nodes": nodes, "edges": edges},
            "paths": [p.model_dump(mode="json") for p in paths]}
