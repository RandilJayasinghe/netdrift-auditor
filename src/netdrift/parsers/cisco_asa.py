"""Cisco ASA / FTD (LINA) running-config parser (extended ACLs, objects, object-groups).

Limitations (documented, surfaced as warnings): IPv6, FQDN objects, time-ranges, `neq` port operators
(treated as 'all ports', i.e. over-approximated) and security-group tags. An `object-group` that
directly follows the *source* address is read as the destination network group.
"""
from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, summarize_address_range

from ..errors import ParseError
from ..models import (Action, AddressGroup, AddressObject, DnatRule, FirewallConfig, Interface, Route, ServiceEntry,
                      ServiceGroup, ServiceObject, Zone)
from .base import AddrSpec, BaseParser, PendingRule, SvcSpec, finalize_rules

_PORT_NAMES = {"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "ftp": 21, "ftp-data": 20,
               "smtp": 25, "domain": 53, "pop3": 110, "imap4": 143, "snmp": 161, "ldap": 389,
               "ldaps": 636, "sqlnet": 1521, "netbios-ssn": 139, "ntp": 123, "syslog": 514, "tftp": 69}
_PORT_OPS = {"eq", "gt", "lt", "range", "neq"}
_HIT = re.compile(r"\(hitcnt=(\d+)\)")


def _port(tok: str) -> int:
    if tok.isdigit():
        return int(tok)
    if tok in _PORT_NAMES:
        return _PORT_NAMES[tok]
    raise ParseError(f"unknown port name '{tok}'")


def _port_spec(t: list[str], i: int) -> tuple[tuple[int, int], int]:
    op = t[i]
    if op == "eq":
        p = _port(t[i + 1]); return (p, p), i + 2
    if op == "range":
        return (_port(t[i + 1]), _port(t[i + 2])), i + 3
    if op == "gt":
        return (_port(t[i + 1]) + 1, 65535), i + 2
    if op == "lt":
        return (0, _port(t[i + 1]) - 1), i + 2
    return (0, 65535), i + 2  # neq: over-approximate


class CiscoAsaParser(BaseParser):
    vendor = "cisco_asa"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return bool(re.search(r"^access-list\s+\S+\s+(line\s+\d+\s+)?extended\s", text, re.M)) or \
            bool(re.search(r"^\s*nameif\s+\S+", text, re.M))

    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(vendor=self.vendor)
        pending: list[PendingRule] = []
        acls: dict[str, list[PendingRule]] = {}
        bindings: dict[str, str] = {}  # acl -> interface nameif (direction 'in' only)
        block: tuple[str, str, str] | None = None
        iface_tmp: dict[str, dict] = {}
        syn = 0
        prio = 0

        for lineno, raw in enumerate(text.splitlines(), 1):
            if not raw.strip() or raw.lstrip()[0] in "!:":
                continue
            indented = raw[0] == " "
            line = _HIT.sub("", raw).split("0x")[0].strip() if "(hitcnt=" in raw else raw.strip()
            hit_m = _HIT.search(raw)
            t = line.split()
            try:
                if indented and block:
                    kind, name, extra = block
                    if kind == "iface":
                        d = iface_tmp[name]
                        if t[0] == "nameif": d["nameif"] = t[1]
                        elif t[0] == "security-level": d["level"] = int(t[1])
                        elif t[:2] == ["ip", "address"] and len(t) >= 4: d["addr"] = IPv4Interface(f"{t[2]}/{t[3]}")
                    elif kind == "objnet" and t[0] == "nat":
                        self._object_nat(cfg, name, t)
                    elif kind == "objnet":
                        cfg.address_objects[name] = AddressObject(name=name, networks=self._net_obj(t))
                    elif kind == "grpnet":
                        syn = self._grpnet_member(cfg, name, t, syn)
                    elif kind == "objsvc":
                        if t[0] == "service":
                            cfg.service_objects[name] = ServiceObject(name=name, entries=[self._svc_entry(t[1:])])
                    elif kind == "grpsvc":
                        syn = self._grpsvc_member(cfg, name, extra, t, syn)
                    continue
                block = None
                if t[0] == "hostname":
                    cfg.hostname = t[1]
                elif t[0] == "interface":
                    iface_tmp[t[1]] = {}
                    block = ("iface", t[1], "")
                elif t[:2] == ["object", "network"]:
                    block = ("objnet", t[2], "")
                elif t[:2] == ["object", "service"]:
                    block = ("objsvc", t[2], "")
                elif t[:2] == ["object-group", "network"]:
                    cfg.address_groups[t[2]] = AddressGroup(name=t[2])
                    block = ("grpnet", t[2], "")
                elif t[:2] == ["object-group", "service"]:
                    cfg.service_groups[t[2]] = ServiceGroup(name=t[2])
                    block = ("grpsvc", t[2], t[3] if len(t) > 3 else "")
                elif t[0] == "route" and len(t) >= 5:
                    cfg.routes.append(Route(dest=IPv4Network(f"{t[2]}/{t[3]}", strict=False), next_hop=IPv4Address(t[4]),
                                            interface=t[1], metric=int(t[5]) if len(t) > 5 and t[5].isdigit() else 1))
                elif t[0] == "access-group" and len(t) >= 5 and t[2] == "in":
                    bindings[t[1]] = t[4]
                elif t[0] == "access-list":
                    if "remark" in t[:4]:
                        continue
                    prio += 1
                    pr = self._acl_line(t, lineno, prio, cfg)
                    if pr:
                        pr.hit_count = int(hit_m.group(1)) if hit_m else None
                        acls.setdefault(t[1], []).append(pr)
                        pending.append(pr)
            except (ValueError, IndexError, ParseError) as exc:
                cfg.warnings.append(f"line {lineno}: {type(exc).__name__}: {exc} -> '{line[:80]}'")

        by_if = {n: d for n, d in iface_tmp.items() if "nameif" in d}
        for hw, d in by_if.items():
            zone = d["nameif"]
            cfg.zones[zone] = Zone(name=zone, trust=d.get("level", 50), security_type=f"level-{d.get('level', 50)}")
            cfg.interfaces[hw] = Interface(name=hw, zone=zone, address=d.get("addr"))
        for acl, rules in acls.items():
            zone = bindings.get(acl)
            if zone is None:
                cfg.warnings.append(f"ACL '{acl}' is not bound with access-group ... in; treated as src zone 'any'")
            for r in rules:
                r.src_zone = zone or "any"
        finalize_rules(cfg, pending)
        if not cfg.rules:
            raise ParseError("no usable access-list entries found - is this a Cisco ASA running-config?")
        return cfg

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _object_nat(cfg: FirewallConfig, obj: str, t: list[str]) -> None:
        """`nat (real,mapped) static <ip|interface> [service tcp|udp <real-port> <mapped-port>]` inside an
        `object network` (ASA 8.3+). Access lists match the *real* address, so nat_order stays post_nat."""
        if len(t) < 4 or t[2] != "static" or obj not in cfg.address_objects:
            cfg.warnings.append(f"object '{obj}': unsupported NAT statement ignored -> '{' '.join(t)[:80]}'")
            return
        try:
            real_if, mapped_if = t[1].strip("()").split(",")
            ext = t[3]
            if ext == "interface":
                ext_ifc = next((i for i in cfg.interfaces.values() if i.zone == mapped_if), None)
                ext_net = ext_ifc.address.ip if ext_ifc and ext_ifc.address else None
                if ext_net is None:
                    cfg.warnings.append(f"object '{obj}': 'static interface' NAT without a known interface address ignored")
                    return
                ext = str(ext_net)
            proto, rport, mport = "ip", None, None
            if "service" in t:
                i = t.index("service")
                proto = t[i + 1]
                rport = (_port(t[i + 2]),) * 2
                mport = (_port(t[i + 3]),) * 2
            real = cfg.address_objects[obj].networks[0]
            cfg.dnat.append(DnatRule(name=obj, ext_if=mapped_if, ext_ip=IPv4Network(f"{ext}/{real.prefixlen}", strict=False),
                                     mapped_ip=real, protocol=proto, ext_port=mport, mapped_port=rport))  # type: ignore[arg-type]
        except (ValueError, IndexError, ParseError) as exc:
            cfg.warnings.append(f"object '{obj}': NAT ignored ({exc})")

    @staticmethod
    def _net_obj(t: list[str]) -> list[IPv4Network]:
        if t[0] == "host":
            return [IPv4Network(f"{t[1]}/32")]
        if t[0] == "subnet":
            return [IPv4Network(f"{t[1]}/{t[2]}", strict=False)]
        if t[0] == "range":
            return list(summarize_address_range(IPv4Address(t[1]), IPv4Address(t[2])))
        raise ParseError(f"unsupported object network statement '{t[0]}'")

    @staticmethod
    def _grpnet_member(cfg: FirewallConfig, grp: str, t: list[str], syn: int) -> int:
        g = cfg.address_groups[grp]
        if t[0] == "group-object" or t[:2] == ["network-object", "object"]:
            g.members.append(t[-1])
            return syn
        if t[0] == "network-object":
            syn += 1
            name = f"{grp}#{syn}"
            if t[1] == "host":
                nets = [IPv4Network(f"{t[2]}/32")]
            else:
                nets = [IPv4Network(f"{t[1]}/{t[2]}", strict=False)]
            cfg.address_objects[name] = AddressObject(name=name, networks=nets)
            g.members.append(name)
        return syn

    @staticmethod
    def _svc_entry(t: list[str]) -> ServiceEntry:
        proto = t[0]
        if proto in ("ip", "icmp"):
            return ServiceEntry(protocol=proto)
        if proto not in ("tcp", "udp"):
            raise ParseError(f"unsupported protocol '{proto}'")
        if "destination" in t:
            (lo, hi), _ = _port_spec(t, t.index("destination") + 1)
            return ServiceEntry(protocol=proto, port_start=lo, port_end=hi)
        return ServiceEntry(protocol=proto)

    def _grpsvc_member(self, cfg: FirewallConfig, grp: str, gproto: str, t: list[str], syn: int) -> int:
        g = cfg.service_groups[grp]
        if t[0] == "group-object" or t[:2] == ["service-object", "object"]:
            g.members.append(t[-1])
            return syn
        entries: list[ServiceEntry] = []
        if t[0] == "port-object":
            (lo, hi), _ = _port_spec(t, 1)
            protos = ("tcp", "udp") if gproto in ("", "tcp-udp") else (gproto,)
            entries = [ServiceEntry(protocol=p, port_start=lo, port_end=hi) for p in protos]  # type: ignore[arg-type]
        elif t[0] == "service-object":
            entries = [self._svc_entry(t[1:])]
        if entries:
            syn += 1
            name = f"{grp}#{syn}"
            cfg.service_objects[name] = ServiceObject(name=name, entries=entries)
            g.members.append(name)
        return syn

    @staticmethod
    def _addr(t: list[str], i: int) -> tuple[AddrSpec, int]:
        k = t[i]
        if k in ("any", "any4"):
            return AddrSpec("any"), i + 1
        if k == "host":
            return AddrSpec("nets", name=t[i + 1], nets=[IPv4Network(f"{t[i + 1]}/32")]), i + 2
        if k in ("object", "object-group"):
            return AddrSpec("name", name=t[i + 1]), i + 2
        n = IPv4Network(f"{t[i]}/{t[i + 1]}", strict=False)
        return AddrSpec("nets", name=str(n), nets=[n]), i + 2

    def _acl_line(self, t: list[str], lineno: int, prio: int, cfg: FirewallConfig) -> PendingRule | None:
        t = [x for x in t]
        if t[2] == "line":
            del t[2:4]
        if t[2] != "extended":
            cfg.warnings.append(f"line {lineno}: non-extended ACL ignored")
            return None
        enabled = "inactive" not in t
        action = Action.ALLOW if t[3] == "permit" else Action.DENY
        i = 4
        proto = t[i]
        svc = SvcSpec("any")
        if proto in ("object", "object-group"):
            svc, i = SvcSpec("name", name=t[i + 1]), i + 2
            proto = ""
        else:
            i += 1
        if "any6" in t or ":" in " ".join(t):
            cfg.warnings.append(f"line {lineno}: IPv6 ACE ignored")
            return None
        src, i = self._addr(t, i)
        if i < len(t) and t[i] in _PORT_OPS:  # source port: unsupported for reachability, skipped
            _, i = _port_spec(t, i)
        dst, i = self._addr(t, i)
        if proto in ("tcp", "udp"):
            if i < len(t) and t[i] in _PORT_OPS:
                (lo, hi), i = _port_spec(t, i)
                svc = SvcSpec("entries", name=f"{proto}/{lo}-{hi}", entries=[ServiceEntry(protocol=proto, port_start=lo, port_end=hi)])
            elif i < len(t) and t[i] == "object-group":
                svc = SvcSpec("name", name=t[i + 1])
            else:
                svc = SvcSpec("entries", name=proto, entries=[ServiceEntry(protocol=proto)])
        elif proto in ("icmp", "ip"):
            svc = SvcSpec("any") if proto == "ip" else SvcSpec("entries", name="icmp", entries=[ServiceEntry(protocol="icmp")])
        elif proto:
            raise ParseError(f"unsupported protocol '{proto}'")
        return PendingRule(lineno=lineno, priority=prio, action=action, src=src, dst=dst, svc=svc,
                           enabled=enabled, name=t[1], comment=f"ACL {t[1]}")
