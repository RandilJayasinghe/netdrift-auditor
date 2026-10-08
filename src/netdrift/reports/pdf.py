from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from ..schemas import AuditResult

_COL = {"critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825", "low": "#2e7d32", "info": "#546e7a"}


def render_pdf(r: AuditResult, max_paths: int = 15) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    st = getSampleStyleSheet()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"NetDrift audit {r.hostname}", leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    S = [Paragraph(f"NetDrift-Auditor Report: {escape(r.hostname)}", st["Title"]),
         Paragraph(f"Vendor {escape(r.vendor)} | Audit {r.audit_id} | {r.generated_at:%Y-%m-%d %H:%M UTC}", st["Normal"]), Spacer(1, 10),
         Paragraph(f"<b>Score {r.score.score}/100 (grade {r.score.grade})</b> - {r.rule_count} rules, {r.graph_nodes} nodes, {r.graph_edges} edges", st["Heading2"])]
    t = Table([["Severity", "Count"]] + [[k.upper(), str(v)] for k, v in r.score.counts.items()], hAlign="LEFT")
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    S += [t, Spacer(1, 10), Paragraph("Compliance (indicative)", st["Heading2"])]
    for c in r.compliance:
        S.append(Paragraph(f"<b>{escape(c.requirement)}</b>: {c.status} - {escape(c.description)}", st["Normal"]))
    S.append(Paragraph("Findings", st["Heading2"]))
    for f in r.findings:
        col = _COL[f.severity.value]
        S.append(Paragraph(f'<font color="{col}"><b>[{f.severity.value.upper()}]</b></font> <b>{f.id}</b> {escape(f.title)}', st["Normal"]))
        S.append(Paragraph(escape(f.description), st["BodyText"]))
        S.append(Paragraph(f"<i>Remediation:</i> {escape(f.remediation)}", st["BodyText"]))
        S.append(Spacer(1, 4))
    S.append(Paragraph(f"Lateral movement paths (top {max_paths})", st["Heading2"]))
    for p in r.attack_paths[:max_paths]:
        route = " -> ".join([p.hops[0].src] + [h.dst for h in p.hops])
        nat = "; ".join(n for h in p.hops for n in h.nat)
        S.append(Paragraph(f"[{p.severity.value.upper()}] {escape(route)} ({p.length} hop(s); rules {escape(', '.join(p.rule_ids) or 'implicit')}"
                           + (f"; NAT: {escape(nat)}" if nat else "") + ")", st["Normal"]))
    doc.build(S)
    return buf.getvalue()
