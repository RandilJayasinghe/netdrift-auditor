"""Longest-prefix-match routing table built from connected subnets plus static routes.

Used by the graph builder to (a) discover subnets that exist only behind a next hop ("routed
segments") and (b) refuse edges for which the firewall would actually forward the traffic out of a
different interface than the zone the rule matched. When the table cannot decide (no covering route)
the answer is "unknown" and the builder keeps the edge: we only prune what routing *proves* impossible.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network

from ..models import FirewallConfig


@dataclass(frozen=True)
class RouteEntry:
    net: IPv4Network
    zone: str
    interface: str
    connected: bool


class RoutingTable:
    def __init__(self, config: FirewallConfig) -> None:
        self.entries: list[RouteEntry] = []
        self.warnings: list[str] = []
        for itf in config.interfaces.values():
            if itf.network is not None:
                self.entries.append(RouteEntry(itf.network, itf.zone, itf.name, True))
        connected = list(self.entries)
        for r in config.routes:
            itf_name = r.interface
            if itf_name is None and r.next_hop is not None:
                via = [e for e in connected if r.next_hop in e.net]
                itf_name = via[0].interface if via else None
            itf = config.interfaces.get(itf_name) if itf_name else None
            if itf is None and itf_name:  # ASA routes name the nameif (= zone), not the hardware port
                itf = next((i for i in config.interfaces.values() if i.zone == itf_name), None)
            if itf is None:
                self.warnings.append(f"static route {r.dest}: egress interface cannot be determined; ignored")
                continue
            self.entries.append(RouteEntry(r.dest, itf.zone, itf.name, False))

    def __bool__(self) -> bool:
        return bool(self.entries)

    def zones_for(self, net: IPv4Network) -> set[str]:
        """Zones the firewall forwards `net` into (longest prefix wins, ties = ECMP). If no route
        contains `net` but more specific routes lie inside it, every such zone is returned."""
        containing = [e for e in self.entries if net.subnet_of(e.net)]
        if containing:
            best = max(e.net.prefixlen for e in containing)
            return {e.zone for e in containing if e.net.prefixlen == best}
        return {e.zone for e in self.entries if e.net.subnet_of(net)}

    def routed_segments(self) -> list[RouteEntry]:
        """Static routes to real (non-default) prefixes not already covered by a connected subnet."""
        conn = [e.net for e in self.entries if e.connected]
        return [e for e in self.entries
                if not e.connected and e.net.prefixlen > 0 and not any(e.net.subnet_of(c) for c in conn)]
