# NetDrift-Auditor

Automated lateral-movement and firewall rule drift auditor. Parses firewall configs (SonicWall, Cisco ASA, Cisco FTD, FortiOS, iptables) into a vendor-neutral model, builds a NAT- and routing-aware directed policy graph, finds attack paths to critical assets, detects shadowed (single-rule **and multi-rule union**) / over-permissive / management-exposing rules, scores PCI-DSS-style posture, and diffs against a baseline. Results are persisted (SQLite or PostgreSQL) and served by an authenticated, rate-limited, multi-tenant API with async audit jobs.

## Layout
```
src/netdrift/
  models.py portset.py schemas.py errors.py sanitizer.py engine.py cli.py
  parsers/    base.py sonicwall.py cisco_asa.py cisco_ftd.py fortinet.py iptables.py __init__.py (registry + auto-detect)
  analysis/   index.py cover.py (union-shadow algebra + prefix index) anomalies.py drift.py scoring.py
  graph/      builder.py (NAT-aware) routing.py paths.py cytoscape.py
  reports/    markdown.py pdf.py
  api/        static/index.html (dashboard) main.py (app factory) db.py store.py (SQLAlchemy) security.py (auth/RBAC/limits) jobs.py settings.py
tests/        test_audit.py test_api.py test_fortinet.py test_sanitizer.py
              test_union_shadow.py test_new_parsers.py test_nat_routing.py test_persistence_jobs.py test_security.py
              fixtures/{bank_hq_sonicwall.conf, asa_sample.conf, ftd_sample.json, iptables_sample.rules, iptables_sample.json, profile.json}
docs/ARCHITECTURE.md  (also ARCHITECTURE.md at the repo root)
```

## Run
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -v                                               # full suite

# CLI (secrets are redacted before parsing)
netdrift audit tests/fixtures/ftd_sample.json profile.json \
  --md report.md --pdf report.pdf --cytoscape graph.json [--baseline old.conf] [--vendor iptables]
netdrift token --sub ci-bot --tenant acme --role analyst --ttl 3600   # needs NETDRIFT_JWT_SECRET

# API
export NETDRIFT_API_KEYS='[{"name":"ci","tenant":"acme","role":"analyst","key":"change-me"}]'
uvicorn netdrift.api.main:app --port 8000               # docs at /docs
```

## Web dashboard
Start the server (`uvicorn netdrift.api.main:app --port 8000`) and open **http://localhost:8000**. Upload a config (drag & drop), optionally pick a vendor, edit the audit profile, and press *Run Audit & Visualize* to get the score card, an interactive Cytoscape graph (red edges = lateral-movement hops; hover/click for services, NAT and rule ids), and Findings / Attack paths / Compliance tabs plus Markdown and PDF downloads.

* The page (`/`, `/static/*`) is served without authentication; all data calls go to `/api/v1` and are authenticated there. If the server requires auth, paste an API key or JWT into *API credentials* (kept in the tab's session storage, sent as `X-API-Key` / `Bearer`).
* The default profile's entry points that don't exist in the uploaded config (e.g. `wan` on an ASA) are skipped automatically; the default assets (`10.10.30.10`, `10.10.99.2`) are examples, so edit them to match your network.
* Tailwind and Cytoscape load from CDNs, so the browser needs internet access to those hosts (vendor the files into `static/` for air-gapped use).

## Supported inputs
| `vendor` | Input | Notes |
|---|---|---|
| `sonicwall` | CLI dialect | |
| `cisco_asa` | running-config | object NAT `nat (in,out) static …` and `route` lines become DNAT / routes |
| `cisco_ftd` | FMC JSON export | zones, objects, access policy, static NAT, static routes (accepted shape documented in `parsers/cisco_ftd.py`) |
| `fortinet` | FortiOS `config … end` | VIPs (DNAT), `router static`, multi-interface policies |
| `iptables` | `iptables-save` text or JSON | FORWARD + PREROUTING DNAT. `iptables-save` has no IPs, so add header directives (below) |

```
# netdrift-hostname: edge-fw01
# netdrift-interface: eth0 203.0.113.2/29 zone=wan trust=0
# netdrift-interface: eth1 10.0.1.1/24 zone=dmz
# netdrift-route: 10.20.0.0/16 via 10.0.1.254 dev eth1
```
The vendor is auto-detected; pass `vendor` (form field / `--vendor`) to force one.

## API
Everything lives under `/api/v1`; `/health` is open. Roles: `viewer` < `analyst` < `admin`.

| Method & path | Role | Purpose |
|---|---|---|
| `POST /audit/upload` | analyst | multipart `file` (+ `vendor`) → sanitized, parsed, stored → `config_id` |
| `GET /configs`, `DELETE /configs/{id}` | viewer / admin | list / delete (cascades audits, findings, baselines) |
| `POST /baselines`, `GET /baselines` | analyst / viewer | save a config as a named baseline snapshot |
| `POST /audit/analyze` | analyst | synchronous audit (`config_id`, `profile`, `baseline_config_id` or `baseline_id`) |
| `POST /audit/jobs` | analyst | same body; `202 {job_id, poll_url}`; `?wait=true` blocks until done |
| `GET /audit/jobs/{job_id}` | viewer | `queued → running → succeeded \| failed` (+ `audit_id`, `result_url`, `error`) |
| `GET /audit/{audit_id}/findings` | viewer | stored findings, filter by `severity` / `category` |
| `GET /reports/attack-paths`, `GET /reports/summary` | viewer | Cytoscape / JSON paths; markdown / pdf / json report |

```bash
H="X-API-Key: change-me"        # or:  -H "Authorization: Bearer $(netdrift token --sub me --role analyst)"
CID=$(curl -s -H "$H" -F file=@tests/fixtures/ftd_sample.json localhost:8000/api/v1/audit/upload | jq -r .config_id)
JID=$(curl -s -H "$H" -H 'content-type: application/json' localhost:8000/api/v1/audit/jobs \
  -d "{\"config_id\":\"$CID\",\"profile\":{\"entry_points\":[\"internet\"],\"critical_assets\":[{\"name\":\"DB\",\"cidr\":\"10.2.30.10/32\"}]}}" | jq -r .job_id)
curl -s -H "$H" localhost:8000/api/v1/audit/jobs/$JID                       # poll until status = succeeded
curl -s -H "$H" "localhost:8000/api/v1/reports/summary?audit_id=<audit_id>&format=markdown"
```

## Configuration (environment)
| Variable | Default | Meaning |
|---|---|---|
| `NETDRIFT_DATABASE_URL` | `sqlite:///netdrift.db` | SQLAlchemy URL. PostgreSQL: `postgresql+psycopg://user:pw@host/netdrift` (`pip install ".[postgres]"`). Tables are created on start-up |
| `NETDRIFT_API_KEYS` | – | JSON list of `{"name","tenant","role","key_sha256"}` (`"key"` plaintext accepted for dev). Hash with `printf %s "$KEY" \| sha256sum` |
| `NETDRIFT_API_KEY` | – | legacy single key = tenant `default`, role `admin` |
| `NETDRIFT_JWT_SECRET` / `NETDRIFT_JWT_PUBLIC_KEY` + `NETDRIFT_JWT_ALGORITHM` | – | JWT bearer auth (HS256, or RS256/ES256 with `pip install ".[rs256]"`). Claims: `sub`, `exp` (required), `tenant`, `role`. Optional `NETDRIFT_JWT_ISSUER`, `NETDRIFT_JWT_AUDIENCE` |
| `NETDRIFT_REQUIRE_AUTH` | off | refuse to start when no credential is configured (otherwise the API is **open** with a warning) |
| `NETDRIFT_RATE_LIMIT` / `NETDRIFT_RATE_LIMIT_HEAVY` / `NETDRIFT_AUTH_FAIL_LIMIT` | `120/minute` / `20/minute` / `10/minute` | token buckets: general, upload/analyze/jobs, failed logins per IP (`N/second\|minute\|hour`) |
| `NETDRIFT_MAX_UPLOAD_BYTES` / `NETDRIFT_MAX_JSON_BYTES` | 20 MiB / 2 MiB | request body caps (413) |
| `NETDRIFT_ASYNC_WORKERS` | `2` | job threads; `0` runs jobs inline (synchronous fallback) |

Rate-limit state and the job pool are per process. For several workers/nodes put a shared limiter in front and swap the `JobRunner` for Celery/RQ (see ARCHITECTURE §8).

## Security notes
* Configs are sanitized (passwords, PSKs, SNMP communities, FortiOS `ENC` blobs, PEM keys, JSON secret fields) **before** parsing; only post-sanitization text and the parsed model are stored, the store re-verifies this immediately before every insert, and `netdrift.*` log records are redacted. Treat the database as sensitive anyway (topology is confidential).
* Tenants are isolated at the query level; a foreign id returns 404.
* Run behind TLS and a trusted reverse proxy.

## Profile
`entry_points`: zone name, CIDR, node id, or `internet`. `critical_assets`: name, cidr, optional zone, criticality, category.

## What is modelled (and what is not)
* **NAT**: inbound static 1:1 and port-forward DNAT. Attack-path hops show the *external* port and translation (`tcp/8080 (port-forward 198.51.100.4 -> 10.2.50.10:80)`); the ACL is evaluated pre- or post-NAT according to the platform (ASA/FTD/SonicWall/iptables: real address; FortiOS: VIP). When a config declares DNAT, private space is reachable from the Internet only through a mapping.
* **Routing**: connected + static routes discover routed-only subnets and veto edges the firewall would forward out of another zone.
* **Not modelled**: source NAT/PAT, VPN crypto maps, app/user-ID rules, IPv6, FQDN objects, dynamic routing. See ARCHITECTURE §9.

## Extending
Add `parsers/<vendor>.py` with a `BaseParser` subclass (`sniff`, `parse`), emit `PendingRule`s, call `finalize_rules`, register it in `parsers/__init__.py`, and add a fixture + test.
