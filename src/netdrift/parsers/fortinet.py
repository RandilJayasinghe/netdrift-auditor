"""Fortinet FortiOS configuration parser.

Reads the `config ... / edit ... / set ... / next / end` blocks for interfaces, zones, address and
service objects, VIPs (destination NAT), static routes and firewall policies, and emits the canonical
FirewallConfig through the shared `finalize_rules` step.

FortiOS specifics: policies match the *VIP object* (external address) so `nat_order` is `pre_nat`;
a policy with several srcintf/dstintf is expanded into one rule per interface pair (ids `R<n>`,
`R<n>.2`, ...). Limitations (reported as warnings): FQDN/geography addresses, negated address
matches (allow -> over-approximated to 'any', deny -> dropped), IPv6, UTM/application profiles.
"""
from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, summarize_address_range

from ..errors import ParseError, UnresolvedReference
from ..models import (Action, AddressGroup, AddressObject, DnatRule, FirewallConfig, Interface, Route,
                      ServiceEntry, ServiceGroup, ServiceObject, Zone)
from .base import AddrSpec, BaseParser, PendingRule, SvcSpec, finalize_rules, guess_trust

_RE_BLOCK_START = re.compile(r"^config\s+([\w\s-]+)$")
_RE_EDIT = re.compile(r"^edit\s+(.+)$")
_RE_SET = re.compile(r"^set\s+(\S+)\s+(.*)$")

# FortiOS predefined services (the subset that matters for reachability analysis)
_BUILTIN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "HTTP": [("tcp", 80, 80)], "HTTPS": [("tcp", 443, 443)], "SSH": [("tcp", 22, 22)],
    "TELNET": [("tcp", 23, 23)], "FTP": [("tcp", 21, 21)], "SMTP": [("tcp", 25, 25)],
    "DNS": [("tcp", 53, 53), ("udp", 53, 53)], "NTP": [("udp", 123, 123)],
    "SNMP": [("tcp", 161, 162), ("udp", 161, 162)], "RDP": [("tcp", 3389, 3389)], "SMB": [("tcp", 445, 445)],
    "LDAP": [("tcp", 389, 389)], "LDAPS": [("tcp", 636, 636)], "MYSQL": [("tcp", 3306, 3306)],
    "MS-SQL": [("tcp", 1433, 1433)], "ORACLE": [("tcp", 1521, 1521)], "POP3": [("tcp", 110, 110)],
    "IMAP": [("tcp", 143, 143)], "SYSLOG": [("udp", 514, 514)], "PING": [("icmp", 0, 65535)],
    "ALL_ICMP": [("icmp", 0, 65535)], "ALL_TCP": [("tcp", 0, 65535)], "ALL_UDP": [("udp", 0, 65535)],
}


def _clean(val: str) -> str:
    val = val.strip()
    return val[1:-1] if len(val) >= 2 and val[0] == val[-1] == '"' else val


def _values(val: str) -> list[str]:
    return [m[0] or m[1] for m in re.findall(r'"([^"]*)"|(\S+)', val)]


def _port_range(part: str) -> tuple[int, int]:
    dst = part.split(":", 1)[0]  # FortiOS syntax is dst[:src]; only the destination matters here
    lo, _, hi = dst.partition("-")
    return int(lo), int(hi or lo)


class FortinetParser(BaseParser):
    vendor = "fortinet"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return "config firewall policy" in text or "config system interface" in text

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _sections(text: str) -> dict[str, list[dict[str, str]]]:
        sections: dict[str, list[dict[str, str]]] = {}
        stack: list[str] = []
        entry: dict[str, str] | None = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("config "):
                m = _RE_BLOCK_START.match(line)
                name = m.group(1).strip() if m else line[7:].strip()
                stack.append(name)
                if len(stack) == 1:
                    sections.setdefault(name, [])
                    entry = None
                    if name == "system global":  # singleton block without `edit`
                        entry = {"_name": "global"}
                        sections[name].append(entry)
            elif line == "end":
                if stack:
                    stack.pop()
                if not stack:
                    entry = None
            elif line.startswith("edit "):
                if len(stack) == 1:  # nested tables (e.g. `config ip-range`) are ignored
                    entry = {"_name": _clean(_RE_EDIT.match(line).group(1))}
                    sections[stack[0]].append(entry)
            elif line == "next":
                if len(stack) == 1:
                    entry = None
            elif entry is not None and len(stack) == 1 and line.startswith("set "):
                m = _RE_SET.match(line)
                if m:
                    entry[m.group(1)] = m.group(2).strip()
        return sections

    def parse(self, text: str) -> FirewallConfig:
        if not text.strip():
            raise ParseError("empty configuration")
        sec = self._sections(text)
        if not any(k in sec for k in ("firewall policy", "system interface")):
            raise ParseError("not a recognized FortiOS configuration dump")
        cfg = FirewallConfig(vendor=self.vendor, nat_order="pre_nat")
        glob = sec.get("system global", [])
        if glob and "hostname" in glob[0]:
            cfg.hostname = _clean(glob[0]["hostname"])

        self._interfaces_and_zones(cfg, sec)
        self._addresses(cfg, sec)
        self._services(cfg, sec)
        self._vips(cfg, sec)
        self._routes(cfg, sec)
        self._policies(cfg, sec)
        if not cfg.rules:
            raise ParseError("no usable firewall policies found")
        return cfg

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _interfaces_and_zones(cfg: FirewallConfig, sec: dict) -> None:
        roles: dict[str, str] = {}
        for item in sec.get("system interface", []):
            name = item["_name"]
            roles[name] = _clean(item.get("role", ""))
            addr = None
            toks = item.get("ip", "").split()
            if len(toks) == 2 and toks[0] != "0.0.0.0":
                try:
                    addr = IPv4Interface(f"{toks[0]}/{toks[1]}")
                except ValueError:
                    cfg.warnings.append(f"interface {name}: invalid ip '{item['ip']}'")
            cfg.interfaces[name] = Interface(name=name, zone=name, address=addr)
        for item in sec.get("system zone", []):
            zname, members = item["_name"], _values(item.get("interface", ""))
            cfg.zones[zname] = Zone(name=zname, trust=guess_trust(zname), security_type="fortios-zone")
            for m in members:
                if m in cfg.interfaces:
                    cfg.interfaces[m].zone = zname
        for itf in cfg.interfaces.values():
            if itf.zone not in cfg.zones:
                cfg.zones[itf.zone] = Zone(name=itf.zone, trust=guess_trust(itf.zone, roles.get(itf.name, "")),
                                           security_type="fortios-interface")

    @staticmethod
    def _addresses(cfg: FirewallConfig, sec: dict) -> None:
        for item in sec.get("firewall address", []):
            n = item["_name"]
            typ = item.get("type", "ipmask")
            try:
                if typ == "iprange":
                    nets = list(summarize_address_range(IPv4Address(item["start-ip"]), IPv4Address(item["end-ip"])))
                elif typ == "ipmask":
                    a, m = item["subnet"].split()
                    nets = [IPv4Network(f"{a}/{m}", strict=False)]
                else:
                    cfg.warnings.append(f"address '{n}': type '{typ}' (FQDN/geo/dynamic) is not resolvable offline; "
                                        "rules using it are dropped")
                    continue
            except (KeyError, ValueError):
                cfg.warnings.append(f"address '{n}': could not parse")
                continue
            cfg.address_objects[n] = AddressObject(name=n, networks=nets)
        for item in sec.get("firewall addrgrp", []):
            cfg.address_groups[item["_name"]] = AddressGroup(name=item["_name"], members=_values(item.get("member", "")))

    @staticmethod
    def _services(cfg: FirewallConfig, sec: dict) -> None:
        for name, ents in _BUILTIN_SERVICES.items():
            cfg.service_objects[name] = ServiceObject(
                name=name, entries=[ServiceEntry(protocol=p, port_start=lo, port_end=hi) for p, lo, hi in ents])  # type: ignore[arg-type]
        for item in sec.get("firewall service custom", []):
            n, ents = item["_name"], []
            try:
                for key, proto in (("tcp-portrange", "tcp"), ("udp-portrange", "udp")):
                    for part in item.get(key, "").split():
                        lo, hi = _port_range(part)
                        ents.append(ServiceEntry(protocol=proto, port_start=lo, port_end=hi))  # type: ignore[arg-type]
                if not ents and item.get("protocol", "").upper() in ("ICMP", "IP"):
                    ents.append(ServiceEntry(protocol="icmp" if item["protocol"].upper() == "ICMP" else "ip"))
            except ValueError:
                cfg.warnings.append(f"service '{n}': could not parse port range")
                continue
            if ents:
                cfg.service_objects[n] = ServiceObject(name=n, entries=ents)
        for item in sec.get("firewall service group", []):
            cfg.service_groups[item["_name"]] = ServiceGroup(name=item["_name"], members=_values(item.get("member", "")))

    @staticmethod
    def _vips(cfg: FirewallConfig, sec: dict) -> None:
        for item in sec.get("firewall vip", []):
            n = item["_name"]
            try:
                ext = IPv4Network(f"{_clean(item['extip']).split('-')[0]}/32")
                mapped_raw = _clean(item["mappedip"])
                mapped = IPv4Network(f"{mapped_raw.split('-')[0]}/32")
                if "-" in mapped_raw:
                    cfg.warnings.append(f"VIP '{n}': mappedip range - only the first address is modelled")
                fwd = item.get("portforward", "disable") == "enable"
                proto = _clean(item.get("protocol", "tcp")).lower() if fwd else "ip"
                eport = _port_range(item["extport"]) if fwd else None
                mport = _port_range(item.get("mappedport", item["extport"])) if fwd else None
                rule = DnatRule(name=n, ext_if=_clean(item.get("extintf", "any")), ext_ip=ext, mapped_ip=mapped,
                                protocol=proto if proto in ("tcp", "udp") else "ip",  # type: ignore[arg-type]
                                ext_port=eport, mapped_port=mport)
            except (KeyError, ValueError) as exc:
                cfg.warnings.append(f"VIP '{n}': skipped ({type(exc).__name__}: {exc})")
                continue
            cfg.dnat.append(rule)
            cfg.address_objects[n] = AddressObject(name=n, networks=[ext])  # policies reference the VIP by name

    @staticmethod
    def _routes(cfg: FirewallConfig, sec: dict) -> None:
        for item in sec.get("router static", []):
            try:
                a, m = item.get("dst", "0.0.0.0 0.0.0.0").split()
                gw = IPv4Address(item["gateway"]) if "gateway" in item else None
                cfg.routes.append(Route(dest=IPv4Network(f"{a}/{m}", strict=False), next_hop=gw,
                                        interface=_clean(item["device"]) if "device" in item else None))
            except (ValueError, KeyError) as exc:
                cfg.warnings.append(f"static route {item['_name']}: skipped ({exc})")

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _addr_spec(cfg: FirewallConfig, names: list[str], negate: bool, allow: bool, ctx: str) -> AddrSpec | None:
        if negate:
            cfg.warnings.append(f"{ctx}: negated address match is not modelled; "
                                + ("allow rule over-approximated to 'any'" if allow else "deny rule dropped"))
            return AddrSpec("any") if allow else None
        nets: list[IPv4Network] = []
        for n in names:
            if n.lower() == "all":
                return AddrSpec("any")
            nets.extend(cfg.resolve_address(n))
        return AddrSpec("nets", name=",".join(names), nets=nets)

    def _policies(self, cfg: FirewallConfig, sec: dict) -> None:
        pending: list[PendingRule] = []
        ids: dict[int, str] = {}
        seq = 0
        for idx, item in enumerate(sec.get("firewall policy", []), 1):
            pid = item["_name"]
            allow = item.get("action", "deny").lower() in ("accept", "ipsec")
            ctx = f"policy {pid}"
            try:
                src = self._addr_spec(cfg, _values(item.get("srcaddr", "all")), item.get("srcaddr-negate") == "enable", allow, ctx)
                dst = self._addr_spec(cfg, _values(item.get("dstaddr", "all")), item.get("dstaddr-negate") == "enable", allow, ctx)
                if src is None or dst is None:
                    continue
                svc_names = _values(item.get("service", "ALL"))
                if any(s.upper() == "ALL" for s in svc_names):
                    svc = SvcSpec("any")
                else:
                    ents: list[ServiceEntry] = []
                    for s in svc_names:
                        ents.extend(cfg.resolve_service(s))
                    svc = SvcSpec("entries", name=",".join(svc_names), entries=ents)
            except UnresolvedReference as exc:
                cfg.warnings.append(f"{ctx}: rule dropped - {exc}")
                continue
            srcs = _values(item.get("srcintf", "any")) or ["any"]
            dsts = _values(item.get("dstintf", "any")) or ["any"]
            for k, (sz, dz) in enumerate(((s, d) for s in srcs for d in dsts), 1):
                seq += 1
                ids[seq] = f"R{pid}" if k == 1 else f"R{pid}.{k}"
                pending.append(PendingRule(
                    lineno=idx, priority=seq, action=Action.ALLOW if allow else Action.DENY,
                    src_zone="any" if sz.lower() == "any" else sz, dst_zone="any" if dz.lower() == "any" else dz,
                    src=src, dst=dst, svc=svc, enabled=item.get("status", "enable") != "disable",
                    name=_clean(item.get("name", "")), comment=_clean(item.get("comments", ""))))
        finalize_rules(cfg, pending)
        for r in cfg.rules:
            r.id = ids.get(r.priority, r.id)
