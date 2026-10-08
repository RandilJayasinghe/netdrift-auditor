"""Cisco Firepower Threat Defense (FTD) parser for Firepower Management Center (FMC) JSON exports.

Input is the JSON an FMC REST export / backup tool produces: one document that bundles the
configuration-domain collections. Collections may be bare lists or the REST envelope
`{"items": [...]}`; the recognised keys (case-insensitive) are:

    name | device.name            hostname
    securityZones                 [{name, securityLevel?, interfaces:[{name}]}]
    interfaces                    [{name, ifname?, securityZone:{name}, ipv4.static.{address,netmask}}]
    hosts / networks / ranges / networkgroups
    protocolportobjects / portobjectgroups
    accessPolicies                [{name, defaultAction.action, rules | rules.items: [...]}]
    natRules                      [{natType STATIC, enabled, sourceInterface, destinationInterface,
                                    originalSource, translatedSource, originalSourcePort, translatedSourcePort}]
    staticRoutes                  [{network|destination, gateway, interfaceName}]

Access rules: ordered by `metadata.ruleIndex` (else list order); ALLOW/TRUST -> allow,
BLOCK/BLOCK_RESET/BLOCK_INTERACTIVE -> deny, MONITOR is non-terminating and skipped; a rule with
several source/destination zones expands to one rule per pair (ids `R<n>`, `R<n>.2`, ...). FTD matches
access control on the *real* (post-NAT) address, so `nat_order` is `post_nat`. Application/URL/user/IPS
conditions are not modelled: the rule is kept and treated as broader than it really is (warning).
FQDN/dynamic objects and IPv6 are reported as warnings, never dropped silently.
"""
from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, summarize_address_range
from typing import Any

from ..errors import ParseError, UnresolvedReference
from ..models import (Action, AddressGroup, AddressObject, DnatRule, FirewallConfig, Interface, Route,
                      ServiceEntry, ServiceGroup, ServiceObject, Zone)
from .base import AddrSpec, BaseParser, PendingRule, SvcSpec, finalize_rules, guess_trust

_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "icmp": "icmp", "tcp": "tcp", "udp": "udp"}
_ALLOW = {"ALLOW", "TRUST"}
_DENY = {"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"}
_L7_KEYS = ("applications", "urls", "users", "ipsPolicy", "filePolicy", "sourceSecurityGroupTags", "destinationDynamicObjects")


def _items(doc: dict, *keys: str) -> list[dict]:
    lower = {k.lower(): v for k, v in doc.items()}
    for k in keys:
        v = lower.get(k.lower())
        if isinstance(v, dict):
            v = v.get("items", [])
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    return []


def _ref_names(blob: Any) -> list[str]:
    return [o["name"] for o in (blob or {}).get("objects", []) if isinstance(o, dict) and "name" in o]


def _port_range(txt: str) -> tuple[int, int]:
    lo, _, hi = str(txt).strip().partition("-")
    return int(lo), int(hi or lo)


def _value_nets(v: dict, warn: list[str], ctx: str) -> list[IPv4Network]:
    """Network literal/object value -> networks. Handles Host, Network (CIDR), Range ('a-b')."""
    val = str(v.get("value", "")).strip()
    typ = str(v.get("type", "")).lower()
    try:
        if "-" in val and typ in ("range", "addressrange", ""):
            a, b = val.split("-", 1)
            return list(summarize_address_range(IPv4Address(a.strip()), IPv4Address(b.strip())))
        if "/" in val:
            return [IPv4Network(val, strict=False)]
        return [IPv4Network(f"{val}/32")]
    except ValueError:
        warn.append(f"{ctx}: unsupported address value '{val}' (FQDN/IPv6/dynamic) ignored")
        return []


class CiscoFtdParser(BaseParser):
    vendor = "cisco_ftd"

    @classmethod
    def sniff(cls, text: str) -> bool:
        head = text.lstrip()[:200000].lower()
        return head.startswith("{") and ('"accesspolic' in head or '"accessrules"' in head or '"accesspolicies"' in head)

    def parse(self, text: str) -> FirewallConfig:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"FMC export is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ParseError("FMC export must be a JSON object")
        cfg = FirewallConfig(vendor=self.vendor)
        cfg.hostname = str(doc.get("name") or (doc.get("device") or {}).get("name") or "ftd")
        self._zones_and_interfaces(cfg, doc)
        self._address_objects(cfg, doc)
        self._port_objects(cfg, doc)
        self._routes(cfg, doc)
        self._nat(cfg, doc)
        self._access_policy(cfg, doc)
        if not cfg.rules:
            raise ParseError("no usable access rules found - is this an FMC access policy export?")
        return cfg

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _zones_and_interfaces(cfg: FirewallConfig, doc: dict) -> None:
        for z in _items(doc, "securityZones", "zones"):
            lvl = z.get("securityLevel")
            cfg.zones[z["name"]] = Zone(name=z["name"], trust=int(lvl) if lvl is not None else guess_trust(z["name"]),
                                        security_type="fmc-zone")
        for i in _items(doc, "interfaces", "physicalinterfaces"):
            zone = (i.get("securityZone") or {}).get("name") or i.get("ifname") or i.get("name")
            addr = None
            st = ((i.get("ipv4") or {}).get("static")) or {}
            if st.get("address"):
                mask = str(st.get("netmask", "32"))
                try:
                    addr = IPv4Interface(f"{st['address']}/{mask}")
                except ValueError:
                    cfg.warnings.append(f"interface {i.get('name')}: invalid address")
            cfg.interfaces[i["name"]] = Interface(name=i["name"], zone=zone, address=addr)
            cfg.zones.setdefault(zone, Zone(name=zone, trust=guess_trust(zone), security_type="fmc-interface"))

    @staticmethod
    def _address_objects(cfg: FirewallConfig, doc: dict) -> None:
        for kind in ("hosts", "networks", "ranges"):
            for o in _items(doc, kind):
                nets = _value_nets(o, cfg.warnings, f"object '{o.get('name')}'")
                if nets:
                    cfg.address_objects[o["name"]] = AddressObject(name=o["name"], networks=nets)
        for fq in _items(doc, "fqdns"):
            cfg.warnings.append(f"FQDN object '{fq.get('name')}' cannot be resolved offline; rules using it are dropped")
        syn = 0
        for g in _items(doc, "networkgroups"):
            members = _ref_names(g)
            for lit in g.get("literals", []) or []:
                syn += 1
                nets = _value_nets(lit, cfg.warnings, f"group '{g['name']}'")
                if nets:
                    nm = f"{g['name']}#{syn}"
                    cfg.address_objects[nm] = AddressObject(name=nm, networks=nets)
                    members.append(nm)
            cfg.address_groups[g["name"]] = AddressGroup(name=g["name"], members=members)

    @staticmethod
    def _port_entry(proto: str, port: str | None) -> ServiceEntry:
        p = _PROTO_NUM.get(str(proto).lower())
        if p is None:
            raise ValueError(f"unsupported protocol '{proto}'")
        if p == "icmp" or not port:
            return ServiceEntry(protocol=p)  # type: ignore[arg-type]
        lo, hi = _port_range(port)
        return ServiceEntry(protocol=p, port_start=lo, port_end=hi)  # type: ignore[arg-type]

    def _port_objects(self, cfg: FirewallConfig, doc: dict) -> None:
        for o in _items(doc, "protocolportobjects"):
            try:
                cfg.service_objects[o["name"]] = ServiceObject(name=o["name"], entries=[self._port_entry(o.get("protocol", ""), o.get("port"))])
            except ValueError as exc:
                cfg.warnings.append(f"port object '{o.get('name')}': {exc}")
        syn = 0
        for g in _items(doc, "portobjectgroups"):
            members = _ref_names(g)
            for lit in g.get("literals", []) or []:
                try:
                    ent = self._port_entry(lit.get("protocol", ""), lit.get("port"))
                except ValueError as exc:
                    cfg.warnings.append(f"port group '{g['name']}': {exc}")
                    continue
                syn += 1
                nm = f"{g['name']}#{syn}"
                cfg.service_objects[nm] = ServiceObject(name=nm, entries=[ent])
                members.append(nm)
            cfg.service_groups[g["name"]] = ServiceGroup(name=g["name"], members=members)

    @staticmethod
    def _routes(cfg: FirewallConfig, doc: dict) -> None:
        for r in _items(doc, "staticRoutes", "ipv4staticroutes"):
            try:
                dest = r.get("network") or r.get("destination") or "0.0.0.0/0"
                if isinstance(dest, dict):
                    dest = dest.get("value", "0.0.0.0/0")
                gw = r.get("gateway")
                gw = gw.get("value") if isinstance(gw, dict) else gw
                itf = r.get("interfaceName") or r.get("interface")
                itf = itf.get("name") if isinstance(itf, dict) else itf
                cfg.routes.append(Route(dest=IPv4Network(dest, strict=False), next_hop=IPv4Address(gw) if gw else None,
                                        interface=itf, metric=int(r.get("metricValue", 1))))
            except (ValueError, TypeError) as exc:
                cfg.warnings.append(f"static route skipped ({exc})")

    def _nat(self, cfg: FirewallConfig, doc: dict) -> None:
        def one_net(blob: Any) -> IPv4Network | None:
            if not isinstance(blob, dict):
                return None
            if "name" in blob and blob["name"] in cfg.address_objects:
                return cfg.address_objects[blob["name"]].networks[0]
            nets = _value_nets(blob, cfg.warnings, "NAT") if "value" in blob else []
            return nets[0] if nets else None

        def one_port(blob: Any) -> tuple[str, tuple[int, int]] | None:
            if not isinstance(blob, dict):
                return None
            if blob.get("name") in cfg.service_objects:
                e = cfg.service_objects[blob["name"]].entries[0]
                return e.protocol, (e.port_start, e.port_end)
            if "port" in blob:
                p = _PROTO_NUM.get(str(blob.get("protocol", "6")).lower(), "tcp")
                return p, _port_range(blob["port"])
            return None

        for n in _items(doc, "natRules", "ftdnatrules"):
            if str(n.get("natType", "STATIC")).upper() != "STATIC" or not n.get("enabled", True):
                continue  # dynamic NAT/PAT is outbound only: it does not publish internal hosts
            real, mapped = one_net(n.get("originalSource")), one_net(n.get("translatedSource"))
            if real is None or mapped is None:
                cfg.warnings.append(f"NAT rule '{n.get('name', '?')}' ignored: could not resolve original/translated source")
                continue
            rp, mp = one_port(n.get("originalSourcePort") or n.get("originalDestinationPort")), \
                one_port(n.get("translatedSourcePort") or n.get("translatedDestinationPort"))
            proto = (mp or rp or ("ip", None))[0]
            try:
                cfg.dnat.append(DnatRule(
                    name=str(n.get("name", "")), ext_if=(n.get("destinationInterface") or {}).get("name", "any"),
                    ext_ip=mapped, mapped_ip=real, protocol=proto if proto in ("tcp", "udp") else "ip",  # type: ignore[arg-type]
                    ext_port=mp[1] if mp else None, mapped_port=rp[1] if rp else None))
            except ValueError as exc:
                cfg.warnings.append(f"NAT rule '{n.get('name', '?')}' ignored: {exc}")

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _addr(cfg: FirewallConfig, blob: Any, ctx: str) -> AddrSpec:
        if not blob or not (blob.get("objects") or blob.get("literals")):
            return AddrSpec("any")
        nets: list[IPv4Network] = []
        for n in _ref_names(blob):
            nets.extend(cfg.resolve_address(n))
        for lit in blob.get("literals", []) or []:
            nets.extend(_value_nets(lit, cfg.warnings, ctx))
        if not nets:
            raise UnresolvedReference("address condition resolved to no IPv4 networks")
        if any(n.prefixlen == 0 for n in nets):
            return AddrSpec("any")
        names = _ref_names(blob) or [str(n) for n in nets]
        return AddrSpec("nets", name=",".join(names), nets=nets)

    def _svc(self, cfg: FirewallConfig, blob: Any) -> SvcSpec:
        if not blob or not (blob.get("objects") or blob.get("literals")):
            return SvcSpec("any")
        ents: list[ServiceEntry] = []
        for n in _ref_names(blob):
            ents.extend(cfg.resolve_service(n))
        for lit in blob.get("literals", []) or []:
            try:
                ents.append(self._port_entry(lit.get("protocol", ""), lit.get("port")))
            except ValueError as exc:
                cfg.warnings.append(f"port literal ignored: {exc}")
        if not ents:
            raise UnresolvedReference("service condition resolved to no ports")
        return SvcSpec("entries", name=",".join(_ref_names(blob)) or "inline", entries=ents)

    def _access_policy(self, cfg: FirewallConfig, doc: dict) -> None:
        policies = _items(doc, "accessPolicies", "accesspolicy")
        if not policies:
            raise ParseError("no accessPolicies found in FMC export")
        if len(policies) > 1:
            cfg.warnings.append(f"{len(policies)} access policies in export; only '{policies[0].get('name')}' is audited")
        pol = policies[0]
        rules = _items(pol, "rules", "accessrules") or _items(doc, "accessRules")
        rules = sorted(enumerate(rules), key=lambda t: ((t[1].get("metadata") or {}).get("ruleIndex", t[0] + 1), t[0]))
        pending: list[PendingRule] = []
        ids: dict[int, str] = {}
        seq = 0
        for pos, (_, r) in enumerate(rules, 1):
            idx = (r.get("metadata") or {}).get("ruleIndex", pos)
            act = str(r.get("action", "BLOCK")).upper()
            name = r.get("name", f"rule-{idx}")
            if act == "MONITOR":
                cfg.warnings.append(f"rule '{name}': MONITOR is non-terminating and does not affect reachability; skipped")
                continue
            if act not in _ALLOW | _DENY:
                cfg.warnings.append(f"rule '{name}': unknown action '{act}' treated as deny")
            if any(r.get(k) for k in _L7_KEYS):
                cfg.warnings.append(f"rule '{name}': application/URL/user/IPS conditions are not modelled; rule treated as broader than it is")
            try:
                src = self._addr(cfg, r.get("sourceNetworks"), name)
                dst = self._addr(cfg, r.get("destinationNetworks"), name)
                svc = self._svc(cfg, r.get("destinationPorts"))
            except UnresolvedReference as exc:
                cfg.warnings.append(f"rule '{name}': rule dropped - {exc}")
                continue
            szs = _ref_names(r.get("sourceZones")) or ["any"]
            dzs = _ref_names(r.get("destinationZones")) or ["any"]
            hits = (r.get("hitCount") or {}).get("hitCount") if isinstance(r.get("hitCount"), dict) else r.get("hitCount")
            for k, (sz, dz) in enumerate(((s, d) for s in szs for d in dzs), 1):
                seq += 1
                ids[seq] = f"R{idx}" if k == 1 else f"R{idx}.{k}"
                pending.append(PendingRule(
                    lineno=pos, priority=seq, action=Action.ALLOW if act in _ALLOW else Action.DENY,
                    src_zone=sz, dst_zone=dz, src=src, dst=dst, svc=svc, enabled=bool(r.get("enabled", True)),
                    name=name, comment=" ".join(c.get("comment", "") for c in r.get("commentHistoryList", []) or []).strip(),
                    hit_count=int(hits) if isinstance(hits, (int, str)) and str(hits).isdigit() else None))
        da = str((pol.get("defaultAction") or {}).get("action", "BLOCK")).upper()
        if da in _ALLOW | {"NETWORK_DISCOVERY"}:
            seq += 1
            ids[seq] = "RDEFAULT"
            pending.append(PendingRule(lineno=0, priority=seq, action=Action.ALLOW, name="default-action",
                                       comment=f"policy default action {da}"))
            cfg.warnings.append(f"policy default action is {da}: an allow-all rule was appended at the end")
        finalize_rules(cfg, pending)
        for r in cfg.rules:
            r.id = ids.get(r.priority, r.id)
