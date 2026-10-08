"""CLI: netdrift audit CONFIG PROFILE.json [--baseline CFG] [--md out.md] [--pdf out.pdf] [--cytoscape out.json]
     netdrift token --sub NAME [--tenant T] [--role viewer|analyst|admin] [--ttl SECONDS]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import run_audit
from .errors import NetDriftError
from .graph.cytoscape import to_cytoscape
from .parsers import parse_config
from .reports.markdown import render_markdown
from .reports.pdf import render_pdf
from .sanitizer import sanitize_config
from .schemas import AuditProfile


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netdrift")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("config")
    a.add_argument("profile")
    a.add_argument("--vendor")
    a.add_argument("--baseline")
    a.add_argument("--md")
    a.add_argument("--pdf")
    a.add_argument("--cytoscape")
    t = sub.add_parser("token", help="mint an HS256 API token (needs NETDRIFT_JWT_SECRET)")
    t.add_argument("--sub", required=True)
    t.add_argument("--tenant", default="default")
    t.add_argument("--role", choices=["viewer", "analyst", "admin"], default="viewer")
    t.add_argument("--ttl", type=int, default=3600, help="lifetime in seconds")
    args = ap.parse_args(argv)
    if args.cmd == "token":
        from .api.security import issue_token
        try:
            print(issue_token(args.sub, args.tenant, args.role, args.ttl))
        except KeyError:
            print("error: set NETDRIFT_JWT_SECRET", file=sys.stderr)
            return 2
        return 0
    try:
        cfg = parse_config(sanitize_config(Path(args.config).read_text(errors="replace")), args.vendor)
        base = parse_config(sanitize_config(Path(args.baseline).read_text(errors="replace")), args.vendor) if args.baseline else None
        profile = AuditProfile.model_validate_json(Path(args.profile).read_text())
        run = run_audit(cfg, profile, baseline=base)
    except (NetDriftError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    r = run.result
    print(f"{r.hostname}: score {r.score.score}/100 grade {r.score.grade}; findings {r.score.counts}")
    if args.md:
        Path(args.md).write_text(render_markdown(r))
    if args.pdf:
        Path(args.pdf).write_bytes(render_pdf(r))
    if args.cytoscape:
        Path(args.cytoscape).write_text(json.dumps(to_cytoscape(run.graph, r.attack_paths, r.hostname), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
