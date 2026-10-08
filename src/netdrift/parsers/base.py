"""Parser interface plus the shared 'pending rule -> resolved Rule' finalisation step."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Literal, Optional

from ..errors import UnresolvedReference
from ..models import ANY_NET, Action, FirewallConfig, Rule, ServiceEntry, Zone

FULL_SERVICE = [ServiceEntry(protocol="ip")]


def guess_trust(name: str, role: str = "") -> int:
    """Best-effort zone trust (0 = Internet .. 100 = fully trusted) for vendors that do not model
    it natively (FortiOS, iptables, FMC). Explicit directives/levels always win over this."""
    n = (role or name).lower()
    if any(k in n for k in ("wan", "internet", "outside", "untrust", "external", "isp")):
        return 0
    if "dmz" in n:
        return 25
    if any(k in n for k in ("guest", "wifi", "wireless")):
        return 20
    if any(k in n for k in ("mgmt", "management", "oob")):
        return 90
    if any(k in n for k in ("lan", "inside", "trust", "internal", "corp")):
        return 100
    return 50


@dataclass
class AddrSpec:
    kind: Literal["any", "name", "nets"] = "any"
    name: str = ""
    nets: list[IPv4Network] = field(default_factory=list)


@dataclass
class SvcSpec:
    kind: Literal["any", "name", "entries"] = "any"
    name: str = ""
    entries: list[ServiceEntry] = field(default_factory=list)


@dataclass
class PendingRule:
    lineno: int
    priority: int
    action: Action
    src_zone: str = "any"
    dst_zone: str = "any"
    src: AddrSpec = field(default_factory=AddrSpec)
    dst: AddrSpec = field(default_factory=AddrSpec)
    svc: SvcSpec = field(default_factory=SvcSpec)
    enabled: bool = True
    name: str = ""
    comment: str = ""
    hit_count: Optional[int] = None


class BaseParser(ABC):
    vendor: str = ""

    @classmethod
    @abstractmethod
    def sniff(cls, text: str) -> bool:
        """Cheap content check used for vendor auto-detection."""

    @abstractmethod
    def parse(self, text: str) -> FirewallConfig: ...


def _addr(cfg: FirewallConfig, spec: AddrSpec) -> tuple[list[IPv4Network], str]:
    if spec.kind == "any":
        return [ANY_NET], "any"
    if spec.kind == "nets":
        return list(spec.nets), spec.name or ",".join(map(str, spec.nets))
    return cfg.resolve_address(spec.name), spec.name


def _svc(cfg: FirewallConfig, spec: SvcSpec) -> tuple[list[ServiceEntry], str]:
    if spec.kind == "any":
        return list(FULL_SERVICE), "any"
    if spec.kind == "entries":
        return list(spec.entries), spec.name or "inline"
    return cfg.resolve_service(spec.name), spec.name


def finalize_rules(cfg: FirewallConfig, pending: list[PendingRule]) -> None:
    """Resolve references and append Rules in priority order. Unresolvable rules are dropped
    *with a warning* (never silently): the report surfaces them as coverage gaps."""
    for p in sorted(pending, key=lambda x: x.priority):
        try:
            src, src_ref = _addr(cfg, p.src)
            dst, dst_ref = _addr(cfg, p.dst)
            svc, svc_ref = _svc(cfg, p.svc)
        except UnresolvedReference as exc:
            cfg.warnings.append(f"line {p.lineno}: rule dropped - {exc}")
            continue
        for z in (p.src_zone, p.dst_zone):
            if z != "any" and z not in cfg.zones:
                cfg.zones[z] = Zone(name=z, trust=50)
                cfg.warnings.append(f"zone '{z}' used by a rule but never declared; assumed trust=50")
        cfg.rules.append(
            Rule(
                id=f"R{p.priority}", priority=p.priority, name=p.name, action=p.action, enabled=p.enabled,
                src_zone=p.src_zone, dst_zone=p.dst_zone, src_nets=src, dst_nets=dst, services=svc,
                src_ref=src_ref, dst_ref=dst_ref, svc_ref=svc_ref, comment=p.comment, hit_count=p.hit_count,
            )
        )
