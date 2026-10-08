"""Pre-compiled rule views: collapsed CIDR sets + interval port sets, computed once per audit."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, collapse_addresses
from typing import Iterable

from ..models import FirewallConfig, Rule
from ..portset import PortSet


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    src: tuple[IPv4Network, ...]
    dst: tuple[IPv4Network, ...]
    ports: PortSet

    @property
    def priority(self) -> int:
        return self.rule.priority


def compile_rules(config: FirewallConfig) -> list[CompiledRule]:
    out = [
        CompiledRule(r, tuple(collapse_addresses(r.src_nets)), tuple(collapse_addresses(r.dst_nets)), r.ports())
        for r in config.rules
    ]
    out.sort(key=lambda c: c.priority)
    return out


def nets_cover(outer: Iterable[IPv4Network], inner: Iterable[IPv4Network]) -> bool:
    """True if every network in `inner` lies inside some network of the (collapsed) `outer` set."""
    outer = tuple(outer)
    return all(any(i.subnet_of(o) for o in outer) for i in inner)


def nets_overlap(a: Iterable[IPv4Network], b: Iterable[IPv4Network]) -> bool:
    b = tuple(b)
    return any(x.overlaps(y) for x in a for y in b)
