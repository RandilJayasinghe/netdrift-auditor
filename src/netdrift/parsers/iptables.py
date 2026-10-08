"""Linux iptables parser: `iptables-save` text (optionally with `-c` counters) and a JSON rule dump.

Model: the host is a router/firewall. Only the `filter` table's **FORWARD** chain is audited as transit
policy; each interface is a zone (`-i` = source zone, `-o` = destination zone). The `nat` table's
PREROUTING `-j DNAT` rules become `DnatRule`s; they run *before* FORWARD so `nat_order` is `post_nat`.
INPUT/OUTPUT (traffic to/from the box itself) are not modelled and reported as a warning.

`iptables-save` carries no interface addresses, so supply them as directive comments (they survive
`iptables-save` round trips if kept in the file header)::

    # netdrift-hostname: edge-fw01
    # netdrift-interface: eth0 203.0.113.2/29 zone=wan trust=0
    # netdrift-interface: eth1 10.0.1.1/24 zone=dmz
    # netdrift-route: 10.20.0.0/16 via 10.0.1.254 dev eth1

JSON form::

    {"hostname": "...", "interfaces": [{"name": "eth0", "address": "10.0.0.1/24", "zone": "lan", "trust": 100}],
     "routes": [{"dest": "10.20.0.0/16", "via": "10.0.1.254", "dev": "eth1"}],
     "tables": {"filter": {"chains": {"FORWARD": {"policy": "DROP", "rules": [
         {"in": "eth0", "out": "eth1", "src": "0.0.0.0/0", "dst": "10.0.1.5", "proto": "tcp", "dport": "443", "target": "ACCEPT"}]}}},
                "nat":    {"chains": {"PREROUTING": {"rules": [
         {"in": "eth0", "dst": "203.0.113.5", "proto": "tcp", "dport": 8443, "target": "DNAT", "to_destination": "10.0.1.5:443"}]}}}}}

Unsupported matches (negation `!`, ipset, hostnames, rate limits ...): an ACCEPT rule is kept and
over-approximated (the condition is ignored, with a warning); a DROP/REJECT rule is skipped (with a
warning) because dropping a deny can only widen reachability in the report, never hide it. User-defined
chain jumps are not followed. Stateful return-traffic rules (`--state ESTABLISHED,RELATED` without NEW)
are skipped: they do not open new flows.
"""
from __future__ import annotations

import json
import re
import shlex
import socket
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, summarize_address_range
from typing import Any, Optional

from ..errors import ParseError
from ..models import Action, DnatRule, FirewallConfig, Interface, Route, ServiceEntry, Zone
from .base import AddrSpec, BaseParser, PendingRule, SvcSpec, finalize_rules, guess_trust

_TABLE = re.compile(r"^\*(filter|nat|mangle|raw|security)\s*$", re.M)
_DIRECTIVE = re.compile(r"^#\s*netdrift-(hostname|interface|route):\s*(.+)$")
_KNOWN_MODULES = {"tcp", "udp", "icmp", "comment", "state", "conntrack", "multiport", "iprange"}
_NEGATABLE = {"-s", "--source", "--src", "-d", "--destination", "--dst", "-i", "--in-interface", "-o", "--out-interface",
              "-p", "--protocol", "--dport", "--destination-port", "--dports", "--destination-ports", "--sport",
              "--source-port", "--sports", "--source-ports", "--src-range", "--dst-range"}
_BUILTIN_TARGETS = {"ACCEPT", "DROP", "REJECT", "RETURN", "LOG", "DNAT", "SNAT", "MASQUERADE", "REDIRECT", "QUEUE", "NFQUEUE"}


def _port(tok: str) -> int:
    tok = tok.strip()
    if tok.isdigit():
        return int(tok)
    return socket.getservbyname(tok)


def _ports(spec: Any) -> list[tuple[int, int]]:
    """'80', '8000:8100', '22,80,8000:8100', 80, [80, '443'] -> [(lo, hi), ...]"""
    if isinstance(spec, (int, str)):
        spec = str(spec).split(",")
    out = []
    for p in spec:
        lo, _, hi = str(p).strip().partition(":")
        out.append((_port(lo) if lo else 0, _port(hi) if hi else (_port(lo) if lo else 65535)))
    return out


def _proto(tok: str) -> str:
    t = tok.lower()
    return {"6": "tcp", "17": "udp", "1": "icmp", "0": "all"}.get(t, t)


def _new_spec(lineno: int) -> dict:
    return {"line": lineno, "src": [], "dst": [], "in": None, "out": None, "proto": "all", "dports": [],
            "target": None, "to_dest": None, "states": None, "unmodelled": [], "comment": "", "pkts": None, "sport": False}


def _tokens_to_spec(chain_tokens: list[str], lineno: int) -> dict:
    spec = _new_spec(lineno)
    negate = False
    i = 0
    t = chain_tokens
    while i < len(t):
        tok = t[i]
        if tok == "!":
            negate = True
            i += 1
            continue
        arg = t[i + 1] if i + 1 < len(t) else ""
        consumed = 2
        if negate and tok in _NEGATABLE:
            spec["unmodelled"].append(f"! {tok} {arg}")  # the negated condition is not applied
            negate = False
            i += 2
            continue
        if tok in ("-s", "--source", "--src"):
            spec["src"] = arg.split(",")
        elif tok in ("-d", "--destination", "--dst"):
            spec["dst"] = arg.split(",")
        elif tok in ("-i", "--in-interface"):
            spec["in"] = arg
        elif tok in ("-o", "--out-interface"):
            spec["out"] = arg
        elif tok in ("-p", "--protocol"):
            spec["proto"] = _proto(arg)
        elif tok in ("--dport", "--destination-port", "--dports", "--destination-ports"):
            spec["dports"] = _ports_safe(arg, spec)
        elif tok in ("--sport", "--source-port", "--sports", "--source-ports"):
            spec["sport"] = True
        elif tok in ("-m", "--match"):
            if arg not in _KNOWN_MODULES:
                spec["unmodelled"].append(f"-m {arg}")
        elif tok in ("-j", "--jump", "-g", "--goto"):
            spec["target"] = arg
        elif tok == "--to-destination":
            spec["to_dest"] = arg
        elif tok in ("--state", "--ctstate"):
            spec["states"] = set(arg.upper().split(","))
        elif tok == "--comment":
            spec["comment"] = arg
        elif tok in ("--src-range", "--dst-range"):
            try:
                a, b = arg.split("-")
                nets = [str(n) for n in summarize_address_range(IPv4Address(a), IPv4Address(b))]
                spec["src" if tok == "--src-range" else "dst"] = nets
            except ValueError:
                spec["unmodelled"].append(f"{tok} {arg}")
        elif tok == "-c":
            spec["pkts"] = int(arg) if arg.isdigit() else None
            consumed = 3
        elif tok == "--match-set":
            spec["unmodelled"].append("ipset")
        elif tok in ("-A", "-I"):
            pass
        else:
            consumed = 1
        if negate:  # '!' before something that carries no modelled value (e.g. -m module)
            spec["unmodelled"].append(f"! {tok}")
        negate = False
        i += consumed
    return spec


def _ports_safe(arg: str, spec: dict) -> list[tuple[int, int]]:
    try:
        return _ports(arg)
    except (OSError, ValueError):
        spec["unmodelled"].append(f"port '{arg}'")
        return []


def _json_spec(r: dict, n: int) -> dict:
    spec = _new_spec(n)
    g = lambda *k: next((r[x] for x in k if x in r), None)  # noqa: E731
    src, dst = g("src", "source", "s"), g("dst", "destination", "d")
    spec["src"] = [src] if isinstance(src, str) else list(src or [])
    spec["dst"] = [dst] if isinstance(dst, str) else list(dst or [])
    spec["in"], spec["out"] = g("in", "in_interface", "i"), g("out", "out_interface", "o")
    spec["proto"] = _proto(str(g("proto", "protocol", "p") or "all"))
    dp = g("dport", "dports", "destination_port")
    spec["dports"] = _ports_safe(dp, spec) if dp not in (None, "") else []
    spec["sport"] = g("sport", "sports") not in (None, "")
    spec["target"] = g("target", "jump", "j")
    spec["to_dest"] = g("to_destination", "to-destination")
    st = g("state", "ctstate")
    spec["states"] = {s.upper() for s in (st.split(",") if isinstance(st, str) else st)} if st else None
    spec["comment"] = str(g("comment") or "")
    spec["pkts"] = g("packets", "pkts")
    spec["unmodelled"] = [f"unsupported match '{k}'" for k in (r.get("unsupported") or [])] + \
                         [f"! {k}" for k in (r.get("negated") or [])]
    return spec


class IptablesParser(BaseParser):
    vendor = "iptables"

    @classmethod
    def sniff(cls, text: str) -> bool:
        head = text.lstrip()
        if head.startswith("{"):
            low = head[:200000].lower()
            return '"tables"' in low and '"chains"' in low
        return bool(_TABLE.search(text)) and ("COMMIT" in text or "-A " in text)

    # ------------------------------------------------------------------------------------------
    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(vendor=self.vendor, hostname="iptables-host", nat_order="post_nat")
        zone_of: dict[str, str] = {}
        if text.lstrip().startswith("{"):
            forward, policy, prerouting, other = self._from_json(cfg, text, zone_of)
        else:
            forward, policy, prerouting, other = self._from_text(cfg, text, zone_of)
        if other:
            cfg.warnings.append("INPUT/OUTPUT chains are not modelled (only transit FORWARD policy is audited): "
                                + ", ".join(sorted(other)))
        if not forward and policy is None:
            raise ParseError("no FORWARD chain found - is this iptables-save output?")
        self._rules(cfg, forward, (policy or "ACCEPT"), zone_of)
        self._dnat(cfg, prerouting, zone_of)
        if not cfg.interfaces or all(i.address is None for i in cfg.interfaces.values()):
            cfg.warnings.append("no interface addresses supplied (use '# netdrift-interface: <if> <ip/len> [zone=..] [trust=..]' "
                                "directives or the JSON form): the policy graph will have no internal segments")
        if not cfg.rules:
            raise ParseError("no usable FORWARD rules found - is this iptables-save output?")
        return cfg

    # ---- input front-ends ---------------------------------------------------------------------
    def _from_text(self, cfg: FirewallConfig, text: str, zone_of: dict[str, str]):
        table = None
        forward: list[dict] = []
        prerouting: list[dict] = []
        policy: dict[str, str] = {}
        other: set[str] = set()
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line:
                continue
            m = _DIRECTIVE.match(line)
            if m:
                self._directive(cfg, m.group(1), m.group(2).strip(), zone_of)
                continue
            if line.startswith("#"):
                continue
            if line == "COMMIT":
                table = None
                continue
            if line.startswith("*"):
                table = line[1:]
                continue
            if line.startswith(":"):
                name, pol = (line[1:].split() + ["-"])[:2]
                if table == "filter":
                    policy[name] = pol
                continue
            try:
                toks = shlex.split(line)
            except ValueError:
                cfg.warnings.append(f"line {lineno}: could not tokenise -> '{line[:80]}'")
                continue
            pkts = None
            if toks and toks[0].startswith("[") and ":" in toks[0]:
                pkts = int(toks[0].strip("[]").split(":")[0])
                toks = toks[1:]
            if len(toks) < 2 or toks[0] not in ("-A", "-I"):
                continue
            chain = toks[1]
            spec = _tokens_to_spec(toks[2:], lineno)
            spec["pkts"] = spec["pkts"] if spec["pkts"] is not None else pkts
            if table == "filter" and chain == "FORWARD":
                forward.append(spec)
            elif table == "nat" and chain == "PREROUTING":
                prerouting.append(spec)
            elif table == "filter" and chain in ("INPUT", "OUTPUT"):
                other.add(chain)
            elif table == "filter" and chain not in ("INPUT", "OUTPUT", "FORWARD"):
                cfg.warnings.append(f"user-defined chain '{chain}' is only modelled if reached by a jump; jumps are not followed")
        return forward, policy.get("FORWARD"), prerouting, other

    def _from_json(self, cfg: FirewallConfig, text: str, zone_of: dict[str, str]):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"iptables JSON is invalid: {exc}") from exc
        if not isinstance(doc, dict) or "tables" not in doc:
            raise ParseError("iptables JSON needs a top-level 'tables' object")
        cfg.hostname = str(doc.get("hostname", cfg.hostname))
        for i in doc.get("interfaces", []):
            self._declare_interface(cfg, zone_of, i["name"], i.get("address"), i.get("zone"), i.get("trust"))
        for r in doc.get("routes", []):
            self._directive(cfg, "route", f"{r['dest']} via {r.get('via', '')} dev {r.get('dev', '')}".strip(), zone_of)
        tables = doc["tables"]
        chains = lambda t: (tables.get(t) or {}).get("chains", {})  # noqa: E731
        fwd = chains("filter").get("FORWARD", {})
        pre = chains("nat").get("PREROUTING", {})
        other = {c for c in chains("filter") if c in ("INPUT", "OUTPUT") and chains("filter")[c].get("rules")}
        return ([_json_spec(r, n) for n, r in enumerate(fwd.get("rules", []), 1)], fwd.get("policy"),
                [_json_spec(r, n) for n, r in enumerate(pre.get("rules", []), 1)], other)

    # ---- directives / interfaces ----------------------------------------------------------------
    def _directive(self, cfg: FirewallConfig, kind: str, arg: str, zone_of: dict[str, str]) -> None:
        try:
            if kind == "hostname":
                cfg.hostname = arg
            elif kind == "interface":
                parts = arg.split()
                kv = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
                self._declare_interface(cfg, zone_of, parts[0], parts[1] if len(parts) > 1 else None, kv.get("zone"),
                                        int(kv["trust"]) if "trust" in kv else None)
            elif kind == "route":
                parts = arg.split()
                dest = IPv4Network(parts[0], strict=False)
                via = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else None
                dev = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
                cfg.routes.append(Route(dest=dest, next_hop=IPv4Address(via) if via else None, interface=dev))
        except (ValueError, IndexError, KeyError) as exc:
            cfg.warnings.append(f"netdrift-{kind} directive ignored ({exc}): '{arg}'")

    @staticmethod
    def _declare_interface(cfg: FirewallConfig, zone_of: dict[str, str], name: str, addr: Optional[str],
                           zone: Optional[str], trust: Optional[int]) -> None:
        zname = zone or name
        zone_of[name] = zname
        try:
            address = IPv4Interface(addr) if addr else None
        except ValueError:
            cfg.warnings.append(f"interface {name}: invalid address '{addr}'")
            address = None
        cfg.interfaces[name] = Interface(name=name, zone=zname, address=address)
        old = cfg.zones.get(zname)
        t = trust if trust is not None else (old.trust if old else guess_trust(zname))
        cfg.zones[zname] = Zone(name=zname, trust=t, security_type="iptables-interface")

    @staticmethod
    def _zone(cfg: FirewallConfig, zone_of: dict[str, str], itf: Optional[str]) -> str:
        if not itf:
            return "any"
        if itf not in zone_of:
            zone_of[itf] = itf
            cfg.interfaces.setdefault(itf, Interface(name=itf, zone=itf))
            cfg.zones.setdefault(itf, Zone(name=itf, trust=guess_trust(itf), security_type="iptables-interface"))
        return zone_of[itf]

    # ---- FORWARD rules -------------------------------------------------------------------------
    @staticmethod
    def _nets(vals: list[str]) -> list[IPv4Network]:
        return [IPv4Network(v, strict=False) for v in vals]

    def _rules(self, cfg: FirewallConfig, specs: list[dict], policy: str, zone_of: dict[str, str]) -> None:
        pending: list[PendingRule] = []
        for n, s in enumerate(specs, 1):
            tgt = (s["target"] or "").upper()
            ctx = f"FORWARD rule {n} (line {s['line']})"
            if tgt not in ("ACCEPT", "DROP", "REJECT"):
                if tgt == "RETURN" or tgt in _BUILTIN_TARGETS:
                    if tgt == "RETURN":
                        cfg.warnings.append(f"{ctx}: RETURN is not modelled; skipped")
                elif s["target"]:
                    cfg.warnings.append(f"{ctx}: jump to user chain '{s['target']}' is not followed; skipped")
                continue
            if s["states"] is not None and "NEW" not in s["states"]:
                continue  # return-traffic rule: opens no new flows
            allow = tgt == "ACCEPT"
            try:
                src, dst = self._nets(s["src"]), self._nets(s["dst"])
            except ValueError as exc:
                s["unmodelled"].append(f"address ({exc})")
                src = dst = []
            if s["unmodelled"]:
                what = ", ".join(s["unmodelled"])
                if not allow:
                    cfg.warnings.append(f"{ctx}: DROP/REJECT with unmodelled match ({what}) skipped")
                    continue
                cfg.warnings.append(f"{ctx}: unmodelled match ({what}) ignored; ACCEPT rule over-approximated")
                src, dst = (src if s["src"] and src else []), (dst if s["dst"] and dst else [])
            if s["sport"]:
                cfg.warnings.append(f"{ctx}: source-port match ignored (rule over-approximated)")
            proto = s["proto"]
            if proto in ("tcp", "udp"):
                ents = [ServiceEntry(protocol=proto, port_start=lo, port_end=hi) for lo, hi in s["dports"]] or [ServiceEntry(protocol=proto)]
                svc = SvcSpec("entries", name=proto + ("/" + ",".join(f"{a}-{b}" if a != b else str(a) for a, b in s["dports"]) if s["dports"] else ""), entries=ents)
            elif proto == "icmp":
                svc = SvcSpec("entries", name="icmp", entries=[ServiceEntry(protocol="icmp")])
            elif proto in ("all", ""):
                svc = SvcSpec("any")
            else:
                cfg.warnings.append(f"{ctx}: protocol '{proto}' not modelled; skipped")
                continue
            pending.append(PendingRule(
                lineno=s["line"], priority=n, action=Action.ALLOW if allow else Action.DENY,
                src_zone=self._zone(cfg, zone_of, s["in"]), dst_zone=self._zone(cfg, zone_of, s["out"]),
                src=AddrSpec("nets", name=",".join(map(str, src)), nets=src) if src else AddrSpec("any"),
                dst=AddrSpec("nets", name=",".join(map(str, dst)), nets=dst) if dst else AddrSpec("any"),
                svc=svc, name=s["comment"], comment=s["comment"], hit_count=s["pkts"]))
        if policy.upper() == "ACCEPT":
            pending.append(PendingRule(lineno=0, priority=len(specs) + 1, action=Action.ALLOW, name="chain-policy",
                                       comment="FORWARD policy ACCEPT"))
            cfg.warnings.append("FORWARD chain policy is ACCEPT: an allow-all rule was appended at the end")
        finalize_rules(cfg, pending)

    # ---- DNAT ---------------------------------------------------------------------------------
    def _dnat(self, cfg: FirewallConfig, specs: list[dict], zone_of: dict[str, str]) -> None:
        for s in specs:
            if (s["target"] or "").upper() != "DNAT":
                continue
            ctx = f"PREROUTING line {s['line']}"
            try:
                to = str(s["to_dest"] or "")
                ip, _, port = to.partition(":")
                ip = ip.split("-")[0]
                if "-" in to.partition(":")[0]:
                    cfg.warnings.append(f"{ctx}: DNAT address range - only the first address is modelled")
                proto = s["proto"] if s["proto"] in ("tcp", "udp") else "ip"
                ext_port = s["dports"][0] if s["dports"] else None
                if len(s["dports"]) > 1:
                    cfg.warnings.append(f"{ctx}: multiple destination ports in one DNAT rule; only the first is modelled")
                mapped_port = _ports(port)[0] if port else ext_port
                if proto == "ip" and (ext_port or mapped_port):
                    ext_port = mapped_port = None
                self._zone(cfg, zone_of, s["in"])
                cfg.dnat.append(DnatRule(
                    name=s["comment"], ext_if=s["in"] or "any",
                    ext_ip=IPv4Network(s["dst"][0], strict=False) if s["dst"] else IPv4Network("0.0.0.0/0"),
                    mapped_ip=IPv4Network(f"{ip}/32"), protocol=proto, ext_port=ext_port, mapped_port=mapped_port))  # type: ignore[arg-type]
            except (ValueError, IndexError, OSError) as exc:
                cfg.warnings.append(f"{ctx}: DNAT ignored ({exc})")
