"""Canonical, vendor-neutral firewall policy model (the 'unified policy schema')."""
from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .errors import UnresolvedReference
from .portset import PortSet

ANY_NET = IPv4Network("0.0.0.0/0")


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:  # 0 = most severe
        return _ORDER.index(self)

    def lowered(self, steps: int = 1) -> "Severity":
        return _ORDER[min(self.rank + steps, len(_ORDER) - 1)]


_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ServiceEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    protocol: Literal["tcp", "udp", "icmp", "ip"]
    port_start: int = Field(0, ge=0, le=65535)
    port_end: int = Field(65535, ge=0, le=65535)

    @model_validator(mode="after")
    def _ordered(self) -> "ServiceEntry":
        if self.port_start > self.port_end:
            raise ValueError("port_start > port_end")
        return self


class Zone(BaseModel):
    name: str
    trust: int = Field(50, ge=0, le=100, description="0 = untrusted/Internet .. 100 = fully trusted")
    security_type: str = ""


class Interface(BaseModel):
    name: str
    zone: str
    address: Optional[IPv4Interface] = None

    @property
    def network(self) -> Optional[IPv4Network]:
        return self.address.network if self.address else None


class AddressObject(BaseModel):
    name: str
    networks: list[IPv4Network]
    zone: Optional[str] = None


class AddressGroup(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)


class ServiceObject(BaseModel):
    name: str
    entries: list[ServiceEntry]


class ServiceGroup(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    """One access rule, with every object/group reference already resolved to concrete values."""

    id: str
    priority: int = Field(description="Evaluation order, 1 = first match wins")
    name: str = ""
    action: Action
    enabled: bool = True
    src_zone: str = "any"
    dst_zone: str = "any"
    src_nets: list[IPv4Network]
    dst_nets: list[IPv4Network]
    services: list[ServiceEntry]
    src_ref: str = "any"
    dst_ref: str = "any"
    svc_ref: str = "any"
    comment: str = ""
    hit_count: Optional[int] = None

    @property
    def src_any(self) -> bool:
        return any(n.prefixlen == 0 for n in self.src_nets)

    @property
    def dst_any(self) -> bool:
        return any(n.prefixlen == 0 for n in self.dst_nets)

    def ports(self) -> PortSet:
        return PortSet.from_entries(self.services)


class NatPolicy(BaseModel):
    inbound_if: str = "any"
    outbound_if: str = "any"
    orig_src: str = "any"
    trans_src: str = "original"
    orig_dst: str = "any"
    trans_dst: str = "original"
    orig_svc: str = "any"
    trans_svc: str = "original"
    enabled: bool = True
    comment: str = ""


class Route(BaseModel):
    """Static route. `interface` is the egress interface name; when only a next hop is known the
    egress interface is inferred from the connected subnet containing it."""
    dest: IPv4Network
    next_hop: Optional[IPv4Address] = None
    interface: Optional[str] = None
    metric: int = 0


class DnatRule(BaseModel):
    """Destination NAT: static 1:1 (no ports) or port forward (PAT). Ports are inclusive ranges and,
    for a range forward, ext/mapped ranges must be the same length (offset mapping)."""
    name: str = ""
    ext_if: str = "any"
    ext_ip: IPv4Network = ANY_NET            # address the outside world connects to (pre-NAT)
    mapped_ip: IPv4Network                    # real internal address (post-NAT)
    protocol: Literal["tcp", "udp", "ip"] = "ip"
    ext_port: Optional[tuple[int, int]] = None
    mapped_port: Optional[tuple[int, int]] = None
    enabled: bool = True

    @model_validator(mode="after")
    def _ports(self) -> "DnatRule":
        if self.ext_port and not self.mapped_port:
            self.mapped_port = self.ext_port
        if self.mapped_port and not self.ext_port:
            self.ext_port = self.mapped_port
        if self.ext_port and self.mapped_port:
            if self.protocol == "ip":
                raise ValueError("port translation needs protocol tcp/udp")
            if self.ext_port[1] - self.ext_port[0] != self.mapped_port[1] - self.mapped_port[0]:
                raise ValueError("ext/mapped port ranges differ in length")
        return self


class FirewallConfig(BaseModel):
    hostname: str = "unknown"
    vendor: str
    zones: dict[str, Zone] = Field(default_factory=dict)
    interfaces: dict[str, Interface] = Field(default_factory=dict)
    address_objects: dict[str, AddressObject] = Field(default_factory=dict)
    address_groups: dict[str, AddressGroup] = Field(default_factory=dict)
    service_objects: dict[str, ServiceObject] = Field(default_factory=dict)
    service_groups: dict[str, ServiceGroup] = Field(default_factory=dict)
    rules: list[Rule] = Field(default_factory=list)
    nat_policies: list[NatPolicy] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    dnat: list[DnatRule] = Field(default_factory=list)
    # What the access rules see for inbound DNAT'd traffic: "post_nat" = the real/mapped destination
    # (ASA 8.3+, SonicWall, iptables FORWARD after PREROUTING); "pre_nat" = the external/VIP address
    # (FortiOS policies reference the VIP object; legacy ASA <8.3 matched the mapped address).
    nat_order: Literal["pre_nat", "post_nat"] = "post_nat"
    warnings: list[str] = Field(default_factory=list)

    # -- helpers -----------------------------------------------------------------------------
    def trust_of(self, zone: str, any_as: int = 0) -> int:
        if zone == "any":
            return any_as
        z = self.zones.get(zone)
        return z.trust if z else 50

    def resolve_address(self, name: str, _stack: tuple[str, ...] = ()) -> list[IPv4Network]:
        if name in _stack:
            raise UnresolvedReference(f"circular address group via '{name}'")
        if name in self.address_objects:
            return list(self.address_objects[name].networks)
        if name in self.address_groups:
            out: list[IPv4Network] = []
            for m in self.address_groups[name].members:
                out.extend(self.resolve_address(m, _stack + (name,)))
            return out
        raise UnresolvedReference(f"unknown address object/group '{name}'")

    def resolve_service(self, name: str, _stack: tuple[str, ...] = ()) -> list[ServiceEntry]:
        if name in _stack:
            raise UnresolvedReference(f"circular service group via '{name}'")
        if name in self.service_objects:
            return list(self.service_objects[name].entries)
        if name in self.service_groups:
            out: list[ServiceEntry] = []
            for m in self.service_groups[name].members:
                out.extend(self.resolve_service(m, _stack + (name,)))
            return out
        raise UnresolvedReference(f"unknown service object/group '{name}'")
