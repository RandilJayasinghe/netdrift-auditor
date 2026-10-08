"""Rule-level detectors: shadowing, over-permissive rules, management exposure, hygiene, NAT."""
from __future__ import annotations

from collections import defaultdict

from ..models import Action, FirewallConfig, Severity
from ..schemas import Finding
from .cover import NetIndex, covering_union
from .index import CompiledRule, nets_cover

PCI_125 = "PCI-DSS v4.0 1.2.5"
PCI_127 = "PCI-DSS v4.0 1.2.7"
PCI_131 = "PCI-DSS v4.0 1.3.1"
ISO_820 = "ISO 27001:2022 A.8.20"
ISO_822 = "ISO 27001:2022 A.8.22"

# port -> (label, base severity when exposed from an untrusted zone)
MGMT_PORTS: dict[int, tuple[str, Severity]] = {
    23: ("Telnet", Severity.CRITICAL), 3389: ("RDP", Severity.CRITICAL), 445: ("SMB", Severity.CRITICAL),
    5985: ("WinRM", Severity.CRITICAL), 22: ("SSH", Severity.HIGH), 5986: ("WinRM-HTTPS", Severity.HIGH),
    161: ("SNMP", Severity.HIGH), 80: ("HTTP (cleartext; verify it is not a management UI)", Severity.LOW),
}
SEMI_TRUSTED_MAX = 25  # zone trust at or below this counts as 'exposed' (WAN, DMZ, guest, wireless)


def _bucket(compiled: list[CompiledRule]) -> dict[tuple[str, str], list[CompiledRule]]:
    b: dict[tuple[str, str], list[CompiledRule]] = defaultdict(list)
    for cr in compiled:
        if cr.rule.enabled:
            b[(cr.rule.src_zone, cr.rule.dst_zone)].append(cr)  # already priority-ordered
    return b


def _finding_shadow(b: CompiledRule, by: list[CompiledRule]) -> Finding:
    rb = b.rule
    ids = [c.rule.id for c in by]
    diff = any(c.rule.action != rb.action for c in by)
    if diff:
        sev = Severity.HIGH if rb.action is Action.DENY else Severity.MEDIUM
        kind = "deny rule never takes effect" if rb.action is Action.DENY else "allow rule is dead (masked by a deny)"
    else:
        sev, kind = Severity.LOW, "redundant duplicate coverage"
    if len(by) == 1:
        a = by[0].rule
        return Finding(
            category="SHADOWED_RULE", severity=sev,
            title=f"Rule {rb.id} is shadowed by {a.id} ({kind})",
            description=(f"Rule {rb.id} ({rb.action.value}, {rb.src_zone}->{rb.dst_zone}, {rb.src_ref} -> {rb.dst_ref}, "
                         f"{rb.svc_ref}) is fully matched by earlier rule {a.id} ({a.action.value}, {a.src_ref} -> {a.dst_ref}, "
                         f"{a.svc_ref}); it can never be evaluated."),
            rule_ids=[rb.id, a.id],
            remediation=f"Delete rule {rb.id}, or move it above rule {a.id} if the intent was a more specific exception.",
            compliance=[PCI_127])
    names = ", ".join(ids)
    parts = "; ".join(f"{c.rule.id} ({c.rule.action.value} {c.rule.src_ref} -> {c.rule.dst_ref}, {c.rule.svc_ref})" for c in by)
    return Finding(
        category="SHADOWED_RULE", severity=sev,
        title=f"Rule {rb.id} is shadowed by the union of {names} ({kind})",
        description=(f"Rule {rb.id} ({rb.action.value}, {rb.src_zone}->{rb.dst_zone}, {rb.src_ref} -> {rb.dst_ref}, {rb.svc_ref}) "
                     f"is not covered by any single earlier rule, but every (source, destination, port) it matches is already "
                     f"matched by the combination of earlier rules {parts}; it can never be evaluated."),
        rule_ids=[rb.id, *ids],
        remediation=f"Delete rule {rb.id}, or move it above {ids[0]} if it was meant as a more specific exception.",
        compliance=[PCI_127])


def detect_shadowed(compiled: list[CompiledRule]) -> list[Finding]:
    """Rule B is shadowed when its whole (zones, src CIDRs, dst CIDRs, ports) space is matched by
    earlier enabled rules. First a single covering rule is tried, then the cumulative *union* of the
    earlier rules in the same zone pair (see `cover.covering_union`). Candidates come from a per-zone-pair
    pair of `NetIndex`es (source and destination CIDRs), so only rules overlapping B in both are ever compared."""
    findings: list[Finding] = []
    order: list[CompiledRule] = []                 # enabled rules already visited = all earlier ones
    index: dict[tuple[str, str], tuple[NetIndex, NetIndex]] = {}  # per zone pair: (src index, dst index)
    for b in (c for c in compiled if c.rule.enabled):
        keys = {(sz, dz) for sz in (b.rule.src_zone, "any") for dz in (b.rule.dst_zone, "any")}
        hits: set[int] = set()
        for k in keys:
            if k in index:
                hits |= index[k][0].query(b.src) & index[k][1].query(b.dst)
        earlier = [order[i] for i in sorted(hits)]
        shadow = next((a for a in earlier if nets_cover(a.src, b.src) and nets_cover(a.dst, b.dst) and a.ports.covers(b.ports)), None)
        if shadow is not None:
            findings.append(_finding_shadow(b, [shadow]))
        elif len(earlier) >= 2:
            used = covering_union((b.src, b.dst, b.ports), ((str(i), (a.src, a.dst, a.ports)) for i, a in enumerate(earlier)))
            if used:
                findings.append(_finding_shadow(b, [earlier[int(i)] for i in used]))
        si, di = index.setdefault((b.rule.src_zone, b.rule.dst_zone), (NetIndex(), NetIndex()))
        si.add(len(order), b.src)
        di.add(len(order), b.dst)
        order.append(b)
    return findings


def _broad(nets, limit: int = 16) -> bool:
    return any(n.prefixlen <= limit for n in nets)


def detect_permissive(config: FirewallConfig, compiled: list[CompiledRule]) -> list[Finding]:
    out: list[Finding] = []
    for cr in compiled:
        r = cr.rule
        if not r.enabled or r.action is not Action.ALLOW:
            continue
        svc_any = cr.ports.is_everything()
        internal_dst = r.dst_zone == "any" or config.trust_of(r.dst_zone) > 0
        sev: Severity | None = None
        title = ""
        fix = ""
        if r.src_any and r.dst_any and svc_any:
            sev = Severity.HIGH if not internal_dst else Severity.CRITICAL
            title = f"Rule {r.id} is Any-to-Any-to-Any ({r.src_zone}->{r.dst_zone})"
            fix = (f"Delete rule {r.id}. If it is a temporary outage workaround, replace it with the minimum explicit "
                   f"source/destination/port tuple and attach an expiry ticket.")
        elif svc_any and internal_dst:
            sev = Severity.HIGH if (_broad(cr.src) or _broad(cr.dst)) else Severity.MEDIUM
            title = f"Rule {r.id} permits ANY service {r.src_zone}->{r.dst_zone} ({r.src_ref} -> {r.dst_ref})"
            fix = f"Replace service 'any' in rule {r.id} with the explicit ports required, and restrict the destination to specific hosts (/32) or at most a /28."
        elif internal_dst and _broad(cr.dst):
            sev = Severity.MEDIUM
            title = f"Rule {r.id} targets a very broad destination ({r.dst_ref})"
            fix = f"Restrict destination of rule {r.id} to the required hosts or a /28 or smaller block."
        elif internal_dst and r.src_any and 1000 < cr.ports.size() < 131070:
            sev = Severity.MEDIUM
            title = f"Rule {r.id} opens a wide port range ({cr.ports.size()} ports) from any source"
            fix = f"Narrow the port ranges of rule {r.id} to the ports the application actually listens on."
        if sev:
            out.append(Finding(
                category="OVERLY_PERMISSIVE", severity=sev, title=title,
                description=(f"Rule {r.id}: {r.action.value} {r.src_zone}->{r.dst_zone}, src {r.src_ref}, dst {r.dst_ref}, "
                             f"service {r.svc_ref}. Violates least privilege. {('Comment: ' + r.comment) if r.comment else ''}").strip(),
                rule_ids=[r.id], remediation=fix, compliance=[PCI_125, PCI_131, ISO_820],
            ))
    return out


def detect_mgmt_exposure(config: FirewallConfig, compiled: list[CompiledRule]) -> list[Finding]:
    out: list[Finding] = []
    for cr in compiled:
        r = cr.rule
        if not r.enabled or r.action is not Action.ALLOW or cr.ports.is_everything():
            continue  # 'any service' rules are reported by detect_permissive
        src_trust = config.trust_of(r.src_zone, any_as=0)
        dst_trust = config.trust_of(r.dst_zone, any_as=100)
        if not src_trust < dst_trust:
            continue  # only less-trusted -> more-trusted flows
        hits = [(p, *MGMT_PORTS[p]) for p in MGMT_PORTS if cr.ports.contains("tcp", p) or (p == 161 and cr.ports.contains("udp", p))]
        if not hits:
            continue
        port, label, sev = min(hits, key=lambda h: h[2].rank)
        if not r.src_any and not _broad(cr.src):
            sev = sev.lowered()
        if src_trust > SEMI_TRUSTED_MAX:
            sev = sev.lowered()
        names = ", ".join(f"{h[1]}/{h[0]}" for h in hits)
        out.append(Finding(
            category="MGMT_EXPOSURE", severity=sev,
            title=f"Rule {r.id} exposes {names} from {r.src_zone} to {r.dst_zone}",
            description=(f"Rule {r.id} allows {r.src_ref} ({r.src_zone}, trust {src_trust}) to reach {r.dst_ref} "
                         f"({r.dst_zone}) on administrative/lateral-movement protocol(s): {names}."),
            rule_ids=[r.id],
            remediation=(f"Remove {names} from rule {r.id}; require a jump host / bastion in the management zone, "
                         f"MFA, and source-restrict to named admin addresses (/32)."),
            compliance=[PCI_125, PCI_131, ISO_822],
        ))
    return out


def detect_hygiene(compiled: list[CompiledRule]) -> list[Finding]:
    out: list[Finding] = []
    for cr in compiled:
        r = cr.rule
        if not r.enabled:
            out.append(Finding(category="DISABLED_RULE", severity=Severity.LOW, title=f"Rule {r.id} is disabled",
                               description=f"Disabled rule {r.id} ({r.comment or r.src_ref + ' -> ' + r.dst_ref}) lingers in the rulebase and can be re-enabled by accident.",
                               rule_ids=[r.id], remediation=f"Delete rule {r.id} after confirming with its owner.", compliance=[PCI_127]))
        elif r.hit_count == 0:
            out.append(Finding(category="UNUSED_RULE", severity=Severity.LOW, title=f"Rule {r.id} has never been hit",
                               description=f"Rule {r.id} shows hit count 0 in the supplied configuration.",
                               rule_ids=[r.id], remediation=f"Review and delete rule {r.id} if no longer required.", compliance=[PCI_127]))
    return out


def detect_nat_exposure(config: FirewallConfig) -> list[Finding]:
    out: list[Finding] = []
    for n in config.nat_policies:
        if not n.enabled or n.trans_dst in ("original", "any"):
            continue
        iface = config.interfaces.get(n.inbound_if)
        if not iface or config.trust_of(iface.zone) != 0:
            continue
        out.append(Finding(
            category="NAT_EXPOSURE", severity=Severity.MEDIUM,
            title=f"Inbound NAT publishes '{n.trans_dst}' from {iface.zone} ({n.orig_dst} -> {n.trans_dst}, service {n.orig_svc})",
            description="An inbound destination NAT maps an externally reachable address to an internal host. Verify the matching access rule is minimal.",
            remediation="Confirm business need, restrict the service, and place the host in a DMZ.", compliance=[PCI_131],
        ))
    return out
