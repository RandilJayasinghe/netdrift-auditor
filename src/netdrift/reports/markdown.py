from __future__ import annotations

from ..models import Severity
from ..schemas import AuditResult

_ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def _c(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(r: AuditResult, max_paths: int = 15) -> str:
    L: list[str] = []
    L += [f"# NetDrift-Auditor Report: {r.hostname}", "",
          f"*Vendor:* `{r.vendor}`  |  *Audit:* `{r.audit_id}`  |  *Generated:* {r.generated_at:%Y-%m-%d %H:%M UTC}", "",
          "## Executive summary", "",
          f"**Security posture score: {r.score.score}/100 (grade {r.score.grade})**", "",
          f"{r.rule_count} rules analysed; policy graph has {r.graph_nodes} nodes and {r.graph_edges} edges.", "",
          "| Severity | Findings |", "|---|---|"]
    L += [f"| {_ICON[s.value]} | {r.score.counts.get(s.value, 0)} |" for s in Severity]
    L += ["", "## Compliance view (indicative)", "", "| Requirement | Status | Description |", "|---|---|---|"]
    L += [f"| {c.requirement} | **{c.status}** | {_c(c.description)} |" for c in r.compliance]
    L += ["", "## Findings", ""]
    for s in Severity:
        fs = [f for f in r.findings if f.severity is s]
        if not fs:
            continue
        L += [f"### {_ICON[s.value]} ({len(fs)})", ""]
        for f in fs:
            L += [f"**{f.id} - {f.title}**", "", f"- Category: `{f.category}`; rules: {', '.join(f.rule_ids) or 'n/a'}",
                  f"- {f.description}", f"- **Remediation:** {f.remediation}",
                  f"- Mapping: {', '.join(f.compliance) or 'n/a'}", ""]
    L += [f"## Lateral movement paths (top {max_paths})", "", "| Sev | Entry | Target | Hops | Route |", "|---|---|---|---|---|"]
    for p in r.attack_paths[:max_paths]:
        route = " -> ".join([p.hops[0].src] + [h.dst for h in p.hops])
        nat = "; ".join(n for h in p.hops for n in h.nat)
        L.append(f"| {_ICON[p.severity.value]} | {_c(p.entry)} | {_c(p.target)} | {p.length} | {_c(route)} (rules {', '.join(p.rule_ids) or 'implicit'}"
                 + (f"; NAT: {_c(nat)}" if nat else "") + ") |")
    if r.drift:
        L += ["", "## Drift vs baseline", "", f"- Added: {', '.join(r.drift.added) or 'none'}",
              f"- Removed/modified: {', '.join(r.drift.removed) or 'none'}", f"- Reordered positions: {r.drift.reordered}"]
    if r.warnings:
        L += ["", "## Parser / coverage warnings", ""] + [f"- {_c(w)}" for w in r.warnings]
    L += ["", "## Method & limitations", "",
          "- Reachability uses first-match semantics and an implicit final deny; it over-approximates (a partial deny does not remove traffic).",
          "- Shadow detection covers single-rule and multi-rule (union) shadowing within a zone pair; ambiguous or very large unions are not reported (no false positives).",
          "- Inbound destination NAT (static / port forward) and static/connected routes are modelled in path search; VPN crypto maps, application/user-ID rules, IPv6 and FQDN objects are not.",
          "- Compliance mapping is indicative; have a QSA/auditor confirm control interpretation."]
    return "\n".join(L) + "\n"
