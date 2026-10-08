"""SonicOS-style CLI dialect parser.

Supported (one statement per line, quotes allowed, `exit` closes blocks):

  hostname NAME
  zone NAME security-type untrusted|public|wireless|encrypted|trusted
  interface X0 / zone LAN / ip 10.0.0.1 255.255.255.0 / exit
  address-object ipv4 "N" host IP|network IP MASK|range A B [zone Z]
  address-group ipv4 "N" / address-object ipv4 "M" ... / exit
  service-object "N" TCP|UDP|ICMP LO HI
  service-group "N" / service-object "M" ... / exit
  access-rule ipv4 from Z to Z action allow|deny source address any|name N|host IP|network IP MASK
      service any|name N destination address ... [comment "..."] [disable] [priority N]
  nat-policy ipv4 inbound IF outbound IF source original A translated B destination original A
      translated B service original A translated B [comment "..."] [disable]

Real SonicOS exports vary by firmware; validate this dialect against your own `show current-config`
output and extend `_handle_*` methods where needed.
"""
from __future__ import annotations

import re
import shlex
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, summarize_address_range

from ..errors import ParseError
from ..models import (Action, AddressGroup, AddressObject, FirewallConfig, Interface, NatPolicy,
                      ServiceEntry, ServiceGroup, ServiceObject, Zone)
from .base import AddrSpec, BaseParser, PendingRule, SvcSpec, finalize_rules

_TRUST = {"untrusted": 0, "public": 25, "wireless": 25, "encrypted": 50, "trusted": 100}
_DEFAULT_TYPE = {"WAN": "untrusted", "LAN": "trusted", "DMZ": "public", "VPN": "encrypted", "WLAN": "wireless"}


class SonicWallParser(BaseParser):
    vendor = "sonicwall"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return bool(re.search(r"^\s*(access-rule|address-object)\s+ipv4\b", text, re.M | re.I))

    # ------------------------------------------------------------------------------------------
    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(vendor=self.vendor)
        pending: list[PendingRule] = []
        block: tuple[str, str] | None = None
        auto_prio = 0
        iface_tmp: dict[str, dict] = {}

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line[0] in "#!":
                continue
            try:
                t = shlex.split(line)
            except ValueError as exc:
                cfg.warnings.append(f"line {lineno}: unparsable ({exc})")
                continue
            cmd = t[0].lower()
            if cmd == "exit":
                block = None
                continue
            try:
                # --- block members (robust to a missing `exit`) ---
                if block and block[0] == "addrgroup" and cmd in ("address-object", "address-group") and len(t) == 3:
                    cfg.address_groups[block[1]].members.append(t[2])
                    continue
                if block and block[0] == "svcgroup" and cmd in ("service-object", "service-group") and len(t) == 2:
                    cfg.service_groups[block[1]].members.append(t[1])
                    continue
                if block and block[0] == "interface" and cmd in ("zone", "ip", "ip-address"):
                    d = iface_tmp[block[1]]
                    if cmd == "zone":
                        d["zone"] = t[1]
                    else:
                        d["addr"] = IPv4Interface(f"{t[1]}/{t[2]}")
                    continue
                block = None  # any other statement ends the current block

                if cmd == "hostname":
                    cfg.hostname = t[1]
                elif cmd == "zone":
                    st = (t[t.index("security-type") + 1] if "security-type" in t else _DEFAULT_TYPE.get(t[1], "trusted")).lower()
                    cfg.zones[t[1]] = Zone(name=t[1], trust=_TRUST.get(st, 50), security_type=st)
                elif cmd == "interface":
                    iface_tmp[t[1]] = {}
                    block = ("interface", t[1])
                elif cmd == "address-object":
                    self._address_object(cfg, t)
                elif cmd == "address-group":
                    self._need_ipv4(t)
                    cfg.address_groups[t[2]] = AddressGroup(name=t[2])
                    block = ("addrgroup", t[2])
                elif cmd == "service-object":
                    self._service_object(cfg, t)
                elif cmd == "service-group":
                    cfg.service_groups[t[1]] = ServiceGroup(name=t[1])
                    block = ("svcgroup", t[1])
                elif cmd == "access-rule":
                    auto_prio += 1
                    pending.append(self._access_rule(t, lineno, auto_prio, cfg))
                elif cmd == "nat-policy":
                    cfg.nat_policies.append(self._nat(t))
                else:
                    cfg.warnings.append(f"line {lineno}: unsupported statement '{cmd}' ignored")
            except (ValueError, IndexError, ParseError) as exc:
                cfg.warnings.append(f"line {lineno}: {type(exc).__name__}: {exc} -> '{line[:80]}'")

        for name, d in iface_tmp.items():
            if "zone" in d:
                cfg.interfaces[name] = Interface(name=name, zone=d["zone"], address=d.get("addr"))
        for z, st in _DEFAULT_TYPE.items():  # well-known zones that were never declared
            if any(r.src_zone == z or r.dst_zone == z for r in pending) and z not in cfg.zones:
                cfg.zones[z] = Zone(name=z, trust=_TRUST[st], security_type=st)
        finalize_rules(cfg, pending)
        if not cfg.rules:
            raise ParseError("no usable access rules found - is this a SonicWall CLI export?")
        return cfg

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _need_ipv4(t: list[str]) -> None:
        if len(t) < 3 or t[1].lower() != "ipv4":
            raise ParseError("only ipv4 objects are supported")

    def _address_object(self, cfg: FirewallConfig, t: list[str]) -> None:
        self._need_ipv4(t)
        name, kind = t[2], t[3].lower()
        if kind == "host":
            nets, rest = [IPv4Network(f"{t[4]}/32")], t[5:]
        elif kind == "network":
            nets, rest = [IPv4Network(f"{t[4]}/{t[5]}", strict=False)], t[6:]
        elif kind == "range":
            nets = list(summarize_address_range(IPv4Address(t[4]), IPv4Address(t[5])))
            rest = t[6:]
        else:
            raise ParseError(f"unsupported address-object type '{kind}'")
        zone = rest[rest.index("zone") + 1] if "zone" in rest else None
        cfg.address_objects[name] = AddressObject(name=name, networks=nets, zone=zone)

    @staticmethod
    def _service_object(cfg: FirewallConfig, t: list[str]) -> None:
        name, proto = t[1], t[2].lower()
        if proto not in ("tcp", "udp", "icmp"):
            raise ParseError(f"unsupported IP protocol '{proto}' in service '{name}'")
        lo = int(t[3]) if len(t) > 3 else 0
        hi = int(t[4]) if len(t) > 4 else (lo if len(t) > 3 else 65535)
        cfg.service_objects[name] = ServiceObject(name=name, entries=[ServiceEntry(protocol=proto, port_start=lo, port_end=hi)])

    @staticmethod
    def _addr_spec(t: list[str], i: int) -> tuple[AddrSpec, int]:
        k = t[i].lower()
        if k == "any":
            return AddrSpec("any"), i + 1
        if k == "name":
            return AddrSpec("name", name=t[i + 1]), i + 2
        if k == "host":
            return AddrSpec("nets", name=t[i + 1], nets=[IPv4Network(f"{t[i + 1]}/32")]), i + 2
        if k == "network":
            n = IPv4Network(f"{t[i + 1]}/{t[i + 2]}", strict=False)
            return AddrSpec("nets", name=str(n), nets=[n]), i + 3
        raise ParseError(f"bad address specifier '{t[i]}'")

    def _access_rule(self, t: list[str], lineno: int, prio: int, cfg: FirewallConfig) -> PendingRule:
        self._need_ipv4(t)
        p = PendingRule(lineno=lineno, priority=prio, action=Action.DENY)
        i = 2
        while i < len(t):
            k = t[i].lower()
            if k == "from":
                p.src_zone, i = t[i + 1], i + 2
            elif k == "to":
                p.dst_zone, i = t[i + 1], i + 2
            elif k == "action":
                p.action = Action.ALLOW if t[i + 1].lower() in ("allow", "permit") else Action.DENY
                i += 2
            elif k == "comment":
                p.comment = p.name = t[i + 1]
                i += 2
            elif k == "priority":
                p.priority, i = int(t[i + 1]), i + 2
            elif k == "disable":
                p.enabled, i = False, i + 1
            elif k in ("source", "destination"):
                if t[i + 1].lower() != "address":
                    raise ParseError(f"expected 'address' after '{k}'")
                spec, i = self._addr_spec(t, i + 2)
                if k == "source":
                    p.src = spec
                else:
                    p.dst = spec
            elif k == "service":
                kind = t[i + 1].lower()
                if kind == "any":
                    p.svc, i = SvcSpec("any"), i + 2
                elif kind == "name":
                    p.svc, i = SvcSpec("name", name=t[i + 2]), i + 3
                else:
                    raise ParseError(f"bad service specifier '{t[i + 1]}'")
            else:
                cfg.warnings.append(f"line {lineno}: unknown access-rule keyword '{t[i]}' ignored")
                i += 1
        return p

    @staticmethod
    def _nat(t: list[str]) -> NatPolicy:
        nat = NatPolicy()
        i = 2
        while i < len(t):
            k = t[i].lower()
            if k == "inbound":
                nat.inbound_if, i = t[i + 1], i + 2
            elif k == "outbound":
                nat.outbound_if, i = t[i + 1], i + 2
            elif k in ("source", "destination", "service"):
                # <kw> original A translated B
                a, b = t[i + 2], t[i + 4]
                short = {"source": "src", "destination": "dst", "service": "svc"}[k]
                setattr(nat, f"orig_{short}", a)
                setattr(nat, f"trans_{short}", b)
                i += 5
            elif k == "comment":
                nat.comment, i = t[i + 1], i + 2
            elif k == "disable":
                nat.enabled, i = False, i + 1
            else:
                i += 1
        return nat
