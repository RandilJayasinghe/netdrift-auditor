"""Directed policy graph.

Nodes  : network segments (one per interface subnet, plus subnets reachable only via static routes),
         'internet' zone nodes (trust 0), and critical-asset nodes taken from the audit profile.
Edges  : u -> v exists when first-match policy evaluation allows at least one (protocol, port)
         from u's address space to v's. Same-segment asset<->segment edges are *implicit*
         (L2-adjacent traffic never crosses the firewall).
NAT    : inbound destination NAT (static 1:1 / port forward) creates internet -> internal edges.
         Access rules are evaluated against the address the *firewall platform* matches on
         (`config.nat_order`: pre_nat = external/VIP address as FortiOS, post_nat = real address as
         ASA 8.3+ / SonicWall / iptables FORWARD) and the result is reported in external-port terms.
         When a config declares any DNAT, un-translated inbound traffic to private space is not
         routable from the Internet, so such direct edges are not created.
Routing: connected + static routes (longest prefix) discover routed-only subnets and veto edges whose
         destination the firewall would forward out of a different zone than the rule matched.
Policy evaluation is conservative (over-approximating reachability): a deny only removes
traffic if it fully covers both endpoints' address space.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import chain
from ipaddress import IPv4Network
from typing import Optional

import networkx as nx

from ..analysis.index import CompiledRule, nets_cover, nets_overlap
from ..models import ANY_NET, Action, DnatRule, FirewallConfig, Severity
from ..portset import PortSet
from ..schemas import AuditProfile
from .routing import RoutingTable


@dataclass(frozen=True)
class NodeInfo:
    id: str
    label: str
    kind: str  # segment | internet | asset
    zone: str
    networks: tuple[IPv4Network, ...]
    criticality: Optional[Severity] = None
    category: str = "generic"


def build_nodes(config: FirewallConfig, profile: AuditProfile) -> tuple[list[NodeInfo], list[str]]:
    warnings: list[str] = []
    nodes: dict[str, NodeInfo] = {}
    for z in config.zones.values():
        if z.trust == 0:
            nodes[f"zone:{z.name}"] = NodeInfo(f"zone:{z.name}", f"Internet ({z.name})", "internet", z.name, (ANY_NET,))
    for itf in config.interfaces.values():
        net = itf.network
        if net is None or config.trust_of(itf.zone) == 0:
            continue
        nid = f"seg:{itf.zone}:{net}"
        nodes.setdefault(nid, NodeInfo(nid, f"{itf.zone} {net}", "segment", itf.zone, (net,)))
    for e in RoutingTable(config).routed_segments():
        if config.trust_of(e.zone) == 0:
            continue
        nid = f"seg:{e.zone}:{e.net}"
        nodes.setdefault(nid, NodeInfo(nid, f"{e.zone} {e.net} (routed)", "segment", e.zone, (e.net,)))
    segs = [n for n in nodes.values() if n.kind == "segment"]
    for a in profile.critical_assets:
        zone = a.zone
        if zone is None:
            owner = sorted((s for s in segs if a.cidr.subnet_of(s.networks[0])), key=lambda s: -s.networks[0].prefixlen)
            if owner:
                zone = owner[0].zone
            else:
                zone = "unknown"
                warnings.append(f"asset '{a.name}' ({a.cidr}) is not inside any interface subnet; zone unknown")
        nid = f"asset:{a.name}"
        nodes[nid] = NodeInfo(nid, a.name, "asset", zone, (a.cidr,), a.criticality, a.category)
    return list(nodes.values()), warnings


def _evaluate(src: NodeInfo, dst: NodeInfo, cands: list[CompiledRule]) -> tuple[PortSet, list[str]]:
    remaining = PortSet.everything()
    allowed = PortSet()
    ids: list[str] = []
    for cr in cands:
        if not nets_overlap(cr.src, src.networks) or not nets_overlap(cr.dst, dst.networks):
            continue
        hit = cr.ports.intersection(remaining)
        if hit.is_empty():
            continue
        if cr.rule.action is Action.ALLOW:
            allowed = allowed.union(hit)
            ids.append(cr.rule.id)
        if nets_cover(cr.src, src.networks) and nets_cover(cr.dst, dst.networks):
            remaining = remaining.difference(cr.ports)
            if remaining.is_empty():
                break
    return allowed, ids


def _merge_edge(g: nx.DiGraph, u: str, v: str, ports: PortSet, services: list[str], rule_ids: list[str],
                nat: list[str] | None = None) -> None:
    if g.has_edge(u, v):
        e = g.edges[u, v]
        e["ports"] = e["ports"].union(ports)
        e["services"] = list(dict.fromkeys([*e["services"], *services]))
        e["rule_ids"] = list(dict.fromkeys([*e["rule_ids"], *rule_ids]))
        e["nat"] = list(dict.fromkeys([*e.get("nat", []), *(nat or [])]))
    else:
        g.add_edge(u, v, ports=ports, services=services, rule_ids=rule_ids, implicit=False, nat=list(nat or []))


def _shift(ports: PortSet, src: tuple[int, int], dst: tuple[int, int]) -> PortSet:
    """Translate the intervals of `ports` (already restricted to `src`) into the `dst` port range."""
    off = dst[0] - src[0]
    return PortSet({p: [(lo + off, hi + off) for lo, hi in iv] for p, iv in ports.intervals().items()})


def _nat_ports(d: DnatRule, space: str) -> PortSet:
    """Ports a DNAT rule applies to, in `space` terms ('ext' or 'mapped')."""
    if d.protocol == "ip" or d.ext_port is None:
        return PortSet.everything()
    return PortSet({d.protocol: [d.ext_port if space == "ext" else d.mapped_port]})  # type: ignore[list-item]


def _dnat_label(d: DnatRule) -> str:
    tgt = str(d.mapped_ip.network_address) if d.mapped_ip.prefixlen == 32 else str(d.mapped_ip)
    if d.mapped_port:
        lo, hi = d.mapped_port
        tgt += f":{lo}" if lo == hi else f":{lo}-{hi}"
    ext = d.ext_ip.network_address if d.ext_ip.prefixlen == 32 else d.ext_ip
    return f"{'port-forward' if d.ext_port else 'static NAT'} {ext} -> {tgt}" + (f" [{d.name}]" if d.name else "")


def _add_dnat_edges(g: nx.DiGraph, config: FirewallConfig, nodes: list[NodeInfo],
                    buckets: dict[tuple[str, str], list[CompiledRule]], rt: RoutingTable) -> None:
    inside = [n for n in nodes if n.kind != "internet"]
    pre = config.nat_order == "pre_nat"
    for d in config.dnat:
        if not d.enabled:
            continue
        ext_if = config.interfaces.get(d.ext_if)
        ext_zone = ext_if.zone if ext_if else (d.ext_if if d.ext_if in config.zones else None)  # ASA names the nameif
        srcs = [n for n in nodes if n.kind == "internet" and (ext_zone is None or n.zone == ext_zone)]
        eval_net = d.ext_ip if pre else d.mapped_ip
        label = _dnat_label(d)
        real_zones = rt.zones_for(d.mapped_ip) if rt else set()
        for v in inside:
            if not any(d.mapped_ip.overlaps(n) for n in v.networks):
                continue
            if real_zones and v.zone != "unknown" and v.zone not in real_zones:
                continue  # the real server is not routed via the zone this node lives in
            probe = NodeInfo(v.id, v.label, v.kind, v.zone, (eval_net,))
            for u in srcs:
                keys = {(sz, dz) for sz in (u.zone, "any") for dz in (v.zone, "any")}
                cands = sorted(chain.from_iterable(buckets.get(k, ()) for k in keys), key=lambda c: c.priority)
                allowed, ids = _evaluate(u, probe, cands)
                translated = bool(d.ext_port and d.mapped_port)
                if pre:
                    in_ext = allowed.intersection(_nat_ports(d, "ext"))
                    if translated and d.ext_port != d.mapped_port:
                        # Platforms differ on whether a VIP policy's service is the external or the mapped
                        # port: accept either (over-approximation, never a missed path).
                        in_ext = in_ext.union(_shift(allowed.intersection(_nat_ports(d, "mapped")), d.mapped_port, d.ext_port))
                    allowed = in_ext
                else:
                    allowed = allowed.intersection(_nat_ports(d, "mapped"))
                    if translated:
                        allowed = _shift(allowed, d.mapped_port, d.ext_port)
                if allowed.is_empty():
                    continue
                _merge_edge(g, u.id, v.id, allowed, [f"{lab} ({label})" for lab in allowed.labels()], ids, [label])


def build_graph(config: FirewallConfig, compiled: list[CompiledRule], profile: AuditProfile) -> tuple[nx.DiGraph, list[str]]:
    nodes, warnings = build_nodes(config, profile)
    rt = RoutingTable(config)
    warnings.extend(rt.warnings)
    g = nx.DiGraph(hostname=config.hostname)
    for n in nodes:
        g.add_node(n.id, info=n)

    buckets: dict[tuple[str, str], list[CompiledRule]] = defaultdict(list)
    for cr in compiled:
        if cr.rule.enabled:
            buckets[(cr.rule.src_zone, cr.rule.dst_zone)].append(cr)

    # implicit same-segment adjacency
    implicit: set[tuple[str, str]] = set()
    for s in (n for n in nodes if n.kind == "segment"):
        members = [a for a in nodes if a.kind == "asset" and a.zone == s.zone and nets_cover(s.networks, a.networks)]
        group = [s, *members]
        for u in group:
            for v in group:
                if u.id != v.id:
                    implicit.add((u.id, v.id))
    for u, v in implicit:
        g.add_edge(u, v, ports=PortSet.everything(), services=["same-segment (not firewall-enforced)"], rule_ids=[],
                   implicit=True, nat=[])

    nat_aware = bool(config.dnat)
    for u in nodes:
        for v in nodes:
            if u.id == v.id or (u.id, v.id) in implicit:
                continue
            if nat_aware and u.kind == "internet" and v.kind != "internet" and all(n.is_private for n in v.networks):
                continue  # private space is only reachable from the Internet through a DNAT mapping
            if rt and v.kind != "internet" and v.zone != "unknown":
                zones = set().union(*(rt.zones_for(n) for n in v.networks))
                if zones and v.zone not in zones:
                    continue  # routing forwards this destination out of another zone
            keys = {(sz, dz) for sz in (u.zone, "any") for dz in (v.zone, "any")}
            cands = sorted(chain.from_iterable(buckets.get(k, ()) for k in keys), key=lambda c: c.priority)
            allowed, ids = _evaluate(u, v, cands)
            if allowed:
                _merge_edge(g, u.id, v.id, allowed, allowed.labels(), ids)
    if nat_aware:
        _add_dnat_edges(g, config, nodes, buckets, rt)
    return g, warnings
