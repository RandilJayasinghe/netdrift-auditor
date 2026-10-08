# NetDrift-Auditor: Architecture Blueprint

## 1. Pipeline

```
 config dump ─► Parser (vendor) ─► FirewallConfig (canonical, resolved) ─► CompiledRule index
                                                                   │
                         ┌─────────────────────────────────────────┼───────────────────────┐
                         ▼                                         ▼                       ▼
                 Rule anomaly detectors                 Policy graph (NetworkX)      Drift diff (baseline)
          shadow / permissive / mgmt / hygiene / NAT     + k-shortest attack paths
                         └───────────────┬─────────────────────────┴───────────────────────┘
                                         ▼
                        Findings ─► Score + compliance matrix ─► AuditResult
                                         ▼
                      FastAPI  ·  Markdown / PDF  ·  Cytoscape.js JSON
                         │
        auth/RBAC · rate limit · size caps ─► SQLAlchemy store (SQLite | PostgreSQL) ◄─ async job runner
```

Supported inputs: SonicWall CLI, Cisco ASA running-config, Cisco FTD (FMC JSON export), Fortinet FortiOS, Linux iptables (`iptables-save` or JSON).

## 2. Unified policy schema (`netdrift/models.py`)

| Entity | Key fields |
|---|---|
| `Zone` | name, `trust` 0-100 (0 = Internet), security_type |
| `Interface` | name, zone, `IPv4Interface` |
| `AddressObject` / `AddressGroup` | name, `IPv4Network[]` / member names (groups resolved recursively, cycle-safe) |
| `ServiceObject` / `ServiceGroup` | `ServiceEntry(protocol tcp/udp/icmp/ip, port_start, port_end)` |
| `Rule` | id, **priority** (first match wins), action, enabled, src/dst zone, **resolved** src/dst nets and services, original refs, comment, hit_count |
| `NatPolicy` | inbound/outbound interface, original/translated src, dst, service (descriptive, used by the NAT-exposure detector) |
| `DnatRule` | **structured** destination NAT: ext interface, external/mapped network, protocol, external/mapped port range (static 1:1 when no ports, port forward otherwise) |
| `Route` | destination prefix, next hop and/or egress interface |
| `FirewallConfig` | all of the above + `nat_order` (`pre_nat` / `post_nat`) + `warnings` (nothing is dropped silently) |

Audit-level schemas (`schemas.py`): `AuditProfile` (entry points, critical assets), `Finding`, `AttackPath`/`PathHop`, `ScoreCard`, `ComplianceItem`, `AuditResult`.

## 3. Attack-graph formulation

**Nodes**: one *segment* per interface subnet, one *routed segment* per static route whose prefix is not inside a connected subnet, one *internet* node per trust-0 zone (0.0.0.0/0), one *asset* node per critical asset (CIDR + zone, zone inferred from the longest-prefix containing segment).

**Edge u→v** (directed, stateful: return traffic is not an edge) exists iff first-match evaluation of the ordered rulebase allows ≥1 (protocol, port) from u's address space to v's:

```
remaining = ALL ports;  allowed = ∅
for rule in rules matching zone(u)→zone(v) in priority order:
    if rule.src ∩ u = ∅ or rule.dst ∩ v = ∅: continue
    hit = rule.ports ∩ remaining
    if rule is ALLOW: allowed ∪= hit
    if rule.src ⊇ u and rule.dst ⊇ v:  remaining −= rule.ports   # rule fully decides these ports
```
Over-approximation by design: an allow that only overlaps a node still creates an edge (any host in a subnet might be the permitted host after pivoting), and a *partial* deny never removes traffic. For a security tool, a false positive is cheaper than a missed path.

**Implicit edges**: an asset and the segment containing it (and assets in the same segment) are mutually reachable without any firewall rule (`implicit=True`).

### 3.1 NAT-aware entry (`graph/builder.py::_add_dnat_edges`)

Each `DnatRule` adds `internet → internal` edges for the nodes that contain the *mapped* address. The ACL is evaluated against whatever address/port the platform matches on (`config.nat_order`), and the edge is expressed in the **external** port the attacker actually connects to:

| Platform | `nat_order` | ACL sees | Notes |
|---|---|---|---|
| Cisco ASA 8.3+, FTD (LINA/ACP), SonicWall, iptables (`PREROUTING` DNAT before `FORWARD`) | `post_nat` | real (mapped) IP and port | edge ports = rule ports ∩ NAT'd real ports, shifted to the external range |
| FortiOS | `pre_nat` | the VIP (external) address | policy `dstaddr` is the VIP object; the policy `service` is accepted against **either** the external or the mapped port (firmware differs; over-approximation) |

A port-forward only publishes the translated port: `tcp/80` allowed on the real host is *not* reachable from the Internet when the VIP maps `8080 → 80`. Edges carry `nat` labels (`port-forward 198.51.100.4 -> 10.2.50.10:80`) that appear on path hops and in the reports.

**Mode switch**: when a config declares at least one DNAT mapping, private (RFC 1918) destinations are reachable from an internet node *only* through a mapping. Configs with no DNAT keep the original zone-pair semantics (an "allow outside→dmz" rule is taken at face value), so existing results do not change.

### 3.2 Routing (`graph/routing.py`)

A longest-prefix-match table is built from connected subnets plus static routes (`router static`, ASA `route`, FMC `staticRoutes`, `# netdrift-route:` directives, iptables JSON `routes`; next-hop-only routes resolve their egress interface through the connected subnet that contains the next hop). It is used to:

1. create *routed segments* so assets behind a next hop get a real zone instead of `unknown`;
2. drop an edge when routing proves the destination leaves through a **different zone** than the rule matched (ties = ECMP keep the edge);
3. verify the real server's route for DNAT edges.

When no route covers a destination the table is undecided and the edge is kept (only what routing *proves* impossible is pruned). Static routes whose egress interface cannot be determined produce a warning. Not modelled: policy-based/VRF routing, dynamic routing protocols, asymmetric/RPF checks.

**Path search**: Yen's k-shortest simple paths (`nx.shortest_simple_paths`) from every entry node to every critical asset, bounded by `max_hops` and `max_paths_per_target`, so the most dangerous (shortest) paths come first and work is bounded. Path severity = asset criticality, lowered one level for 2-3 hops and two levels for 4+.

## 4. Detection logic

| Detector | Rule |
|---|---|
| Shadowed | enabled rule B whose whole (src CIDRs × dst CIDRs × ports) space is matched by earlier enabled rules in the same-or-`any` zone pair. A **single** covering rule A (superset on all three axes), else the **union** of several earlier rules (see 4.1). If any covering rule has the opposite action: B=deny → **HIGH** (deny never applies), B=allow → MEDIUM (dead rule); all same action → LOW (redundant). |
| Over-permissive | any/any/any → CRITICAL; any service to an internal zone → HIGH if src or dst ≤ /16 else MEDIUM; destination ≤ /16 → MEDIUM; any-source wide port range → MEDIUM |
| Mgmt exposure | allow rules (not already "any service") flowing from a less-trusted to a more-trusted zone that include Telnet/RDP/SMB/WinRM (CRITICAL), SSH/SNMP/WinRM-S (HIGH), HTTP/80 (LOW, needs human check); lowered if the source is narrow or internal |
| Hygiene | disabled rules, hit_count = 0 (ASA `show access-list` output) |
| NAT | enabled inbound destination NAT on a trust-0 interface |
| Drift | semantic signature diff vs baseline (added/removed/modified, order changes) |

### 4.1 Union shadowing (`analysis/cover.py`)

A rule is a *box* `(src CIDR set) × (dst CIDR set) × (port set)`. Subtracting an earlier box A from a region R yields at most three disjoint boxes:

```
R \ A = (R.src \ A.src) × R.dst × R.ports
      ∪ (R.src ∩ A.src) × (R.dst \ A.dst) × R.ports
      ∪ (R.src ∩ A.src) × (R.dst ∩ A.dst) × (R.ports \ A.ports)
```
B is shadowed iff the region `B` minus every earlier box is empty. CIDR blocks are nested-or-disjoint, so ∩ is a subnet test and \ is `address_exclude` (≤ prefixlen pieces); ports use the interval algebra in `portset.py`. Cost control, in order of application:

1. **`NetIndex` prefix index** (per zone pair, one for sources and one for destinations): ancestors by hashing `(prefixlen, prefix bits)` (≤ 33 lookups) plus contained blocks by bisect over start addresses. Candidates must overlap on *both* axes, so unrelated rules are never touched.
2. **Necessary-condition prune**: the merged address spans / port union of the candidates must cover B on each axis separately before any splitting happens.
3. **Residue cap** (`MAX_BOXES = 512`): if the leftover region explodes the answer is "undetermined" and nothing is reported. The detector can therefore only under-report, never produce a false positive.

Measured: a 2,100-rule rulebase containing a 256-rule union finding takes ≈ 0.3 s (the first, unindexed implementation took ≈ 8 s).

## 5. Scoring

`score = 100 − min(60, Σ finding weights) − min(60, Σ worst-path-per-(entry,target) weights)`; weights CRITICAL 12 / HIGH 6 / MEDIUM 2.5 / LOW 0.5 (paths 10 / 5 / 2 / 0.5). Grades A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 50, else F. The compliance matrix maps finding categories to PCI-DSS v4.0 1.2.5 / 1.2.7 / 1.3.1 and ISO 27001:2022 A.8.22 (PASS / WARN / FAIL). **Indicative only: have a QSA confirm control interpretation.**

## 6. Complexity and scaling

* Parsing: O(lines). Group resolution: O(objects).
* Shadow detection: index lookup, then exact residue subtraction only for rules that overlap on every axis and pass the span prune.
* Graph build: O(N² · r_pair), N = nodes (tens to low hundreds), r_pair = rules matching that zone pair.
* Paths: Yen's, bounded by `max_paths_per_target`.
* Next scaling steps: process pool per firewall; Celery/RQ `JobRunner` for multi-host workers (the seam exists, see section 8).

## 7. Parsers

| Vendor | Input | Zones | NAT / routes | Notable behaviour |
|---|---|---|---|---|
| `sonicwall` | CLI dialect | zones with trust | descriptive `NatPolicy` | |
| `cisco_asa` | running-config | `nameif` + security-level | `object network … nat (r,m) static …` → `DnatRule`; `route` | ACLs bound by `access-group … in` |
| `cisco_ftd` | FMC JSON export (accepted shape documented in `parsers/cisco_ftd.py`) | `securityZones` (+level) | FTD static NAT rules → `DnatRule`; `staticRoutes` | MONITOR skipped; multi-zone rules expanded (`R3`, `R3.2`); default action TRUST/ALLOW appends an allow-all; L7 conditions warn and broaden the rule |
| `fortinet` | FortiOS `config … end` | interface / `system zone`, trust from role/name | `firewall vip` → `DnatRule` (`pre_nat`); `router static` | multi-interface policies expanded; builtin services; negated addresses over-approximated |
| `iptables` | `iptables-save [-c]` or JSON | one zone per interface (`# netdrift-interface:` directives supply address/zone/trust) | `nat/PREROUTING -j DNAT` → `DnatRule`; `# netdrift-route:` | FORWARD only; `ESTABLISHED,RELATED` rules skipped; unmodelled matches: ACCEPT over-approximated, DROP skipped (always with a warning) |

All parsers go through `finalize_rules`; anything that cannot be resolved is dropped **with a warning**, never silently.

## 8. Service layer

```
request ─► BodyLimitMiddleware (413) ─► guard(role, heavy): authenticate → RBAC → rate limit ─► handler ─► Store (tenant-scoped SQL)
```

* **Persistence** (`api/db.py`, `api/store.py`): SQLAlchemy 2.0. Tables `configs`, `baselines`, `audit_runs`, `findings`, `jobs`, `schema_meta`, created on start-up (Alembic is the recommended next step once the schema starts evolving). `NETDRIFT_DATABASE_URL` selects SQLite (default `sqlite:///netdrift.db`, WAL, foreign keys on) or PostgreSQL (`postgresql+psycopg://…`, `pip install "netdrift-auditor[postgres]"`). Every row has `tenant_id` and every query filters on it, so another tenant's id behaves exactly like a missing one (404). Graphs are not stored: they are rebuilt deterministically from the stored config + profile when a path report is requested.
* **Authentication** (`api/security.py`): JWT bearer (HS256 secret or RS256/ES256 public key, `exp` + `sub` required, optional issuer/audience, `alg=none` rejected) or API keys (`NETDRIFT_API_KEYS`, stored as SHA-256 and compared in constant time; legacy `NETDRIFT_API_KEY` = default-tenant admin). Credentials are re-read per request. No credentials configured = open dev mode with a start-up warning; `NETDRIFT_REQUIRE_AUTH=1` refuses to start in that state, and a malformed key table fails at start-up.
* **RBAC**: `viewer` (read reports/jobs/findings) < `analyst` (upload, analyze, jobs, baselines) < `admin` (delete configs).
* **Rate limiting**: in-process token buckets per principal (client IP when unauthenticated): general `NETDRIFT_RATE_LIMIT`, heavy endpoints (`upload`, `analyze`, `jobs`) `NETDRIFT_RATE_LIMIT_HEAVY`, plus a per-IP failed-authentication limiter against key guessing. 429 + `Retry-After`. State is per process: put a gateway/Redis limiter in front when running several workers. The client IP is the socket peer; run behind a trusted proxy with `--proxy-headers` rather than trusting `X-Forwarded-For` blindly.
* **Size limits**: a pure-ASGI middleware enforces `NETDRIFT_MAX_UPLOAD_BYTES` (uploads) and `NETDRIFT_MAX_JSON_BYTES` (everything else) on the declared `Content-Length` *and* on streamed/chunked bodies (413); empty (422) and binary (415) uploads are rejected.
* **Secret hygiene** (`sanitizer.py`): (1) `sanitize_config` redacts vendor secret syntax, including FortiOS `ENC` blobs, PEM private keys and JSON `"password"/"psk"/…` values; (2) the only thing the store accepts is a `SanitizedConfig`, re-verified by `verify_sanitized` (a fixed point of the sanitizer and free of high-confidence secret patterns) immediately before the INSERT, and the parsed JSON is scanned too; (3) `install_log_redaction` scrubs every `netdrift.*` log record; (4) the CLI sanitizes before parsing, so parser warnings that echo input lines cannot leak. Only post-sanitization text is ever stored.
* **Jobs** (`api/jobs.py`): `POST /audit/jobs` → `202 {job_id, poll_url}`; poll `GET /audit/jobs/{id}` (`queued → running → succeeded|failed`; failures carry a sanitized error, never a stack trace). `?wait=true`, or `NETDRIFT_ASYNC_WORKERS=0`, runs the job inline (synchronous fallback); `POST /audit/analyze` remains the plain synchronous call. State lives in the database, so jobs interrupted by a restart are marked `failed` on boot. For Celery/RQ implement `JobRunner.submit(job_id)` as `task.delay(job_id)` that calls `execute_job(store, job_id)` in the worker.

## 9. Known limitations (be explicit with auditors)

* Parsers target documented dialects/export shapes; real exports vary by firmware, so validate on your own device output first.
* Implicit final deny is assumed. Platform default rules are only honoured if they appear in the export.
* NAT: only *inbound destination* NAT is modelled (static 1:1 and port forward). Source NAT/PAT, hairpin NAT, twice-NAT, identity NAT and mapped ranges larger than one address (FortiOS uses the first address) are not. FortiOS port-forward policy matching is over-approximated (see 3.1).
* Routing: connected + static routes only (no OSPF/BGP, PBR, VRFs, RPF).
* VPN crypto maps, user/app-ID/URL rules, IPv6 and FQDN objects are not modelled (flagged as warnings where detected).
* Union shadowing is evaluated within one zone pair (plus `any`) and capped; an `any`-zone target covered only by several zone-specific rules is not reported.
* iptables: only `filter/FORWARD` and `nat/PREROUTING`; user-chain jumps are not followed; `iptables-save` carries no interface addresses, so they must be supplied.
* The rate limiter and the in-process job pool are single-node. Use a shared limiter / external worker queue for multi-node deployments.

## 10. Remaining production hardening

OIDC discovery/JWKS rotation (today: a static key) · Alembic migrations · encryption at rest / object storage for large configs · audit logging of administrative actions · upload malware scanning · CI matrix with per-vendor fixtures · signed report artefacts.
