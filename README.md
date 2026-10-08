<div align="center">

# 🛡️ NetDrift-Auditor

### Multi-Vendor Firewall Security, Lateral Movement & Policy Drift Auditing

[![Python](https://img.shields.io/badge/python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![NetworkX](https://img.shields.io/badge/NetworkX-3.2+-F28C28)](https://networkx.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0+-D71F00)](https://www.sqlalchemy.org/)
[![Tests](https://img.shields.io/badge/tests-86%20passed-brightgreen)](#-quick-start)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Audit firewall policies · Model lateral movement · Detect shadowed rules · Track drift · Map to PCI-DSS & ISO 27001**

[Features](#-key-features) · [Architecture](#-architecture) · [Vendors](#-supported-vendors) · [Quick Start](#-quick-start) · [Dashboard](#-web-dashboard) · [API](#-api-reference) · [Security](#-security--data-hygiene)

</div>

---

## 📌 Overview

Enterprise and banking firewalls accumulate thousands of legacy rules, NAT entries and zone policies. Over the years this causes shadowed rules, over-permissive access, hidden lateral-movement paths to core assets, and unreviewed emergency changes.

**NetDrift-Auditor** ingests raw firewall configurations, redacts secrets, normalizes everything into one vendor-neutral model, builds a directed reachability graph, and answers three questions:

1. **Can a compromised host reach my critical assets, and through which rules?**
2. **Which rules are shadowed, over-permissive or exposing management ports?**
3. **What changed since the approved baseline?**

---

## ✨ Key Features

| | Capability | Details |
|---|---|---|
| 🔌 | **Multi-vendor normalization** | SonicWall, Cisco ASA, Cisco FTD, FortiOS and Linux iptables into one canonical schema |
| 🕸️ | **NAT & route-aware graph** | NetworkX digraph modelling static NAT, DNAT/PAT and connected/static routes |
| 🎯 | **Lateral movement pathfinding** | Yen's k-shortest paths from Internet/DMZ/user VLANs to PCI and core assets, severity-ranked |
| 🧹 | **Anomaly detection** | Single-rule and multi-rule (union) shadowing via radix-tree/interval algebra, any/any/any rules, exposed RDP/SSH/Telnet/WinRM, unreferenced objects |
| 📉 | **Drift auditing** | Semantic diff against golden baselines: added, removed and modified rules, order changes |
| ✅ | **Compliance mapping** | PCI-DSS v4.0 (1.2.5, 1.2.7, 1.3.1) and ISO 27001:2022 (A.8.20, A.8.22) |
| 🔐 | **Secret sanitization** | PSKs, password hashes, SNMP communities, PEM keys and FortiOS `ENC` blobs redacted at ingestion |
| 🏢 | **Production backend** | Multi-tenant RBAC, JWT / API key auth, rate limiting, async jobs, SQLite / PostgreSQL |
| 📄 | **Reporting** | Cytoscape.js graph JSON, executive PDF and Markdown reports, A–F score card |

---

## 🏗️ Architecture

```text
                  Raw Firewall Config Dump
                            │
                            ▼
              ┌───────────────────────────┐
              │     Secret Sanitizer      │  redacts PSKs, hashes, keys
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │ Multi-Vendor Parser Layer │  SonicWall · ASA · FTD · Fortinet · iptables
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │   Canonical Policy Model  │  rules · zones · NAT · routes
              └──────┬─────────────┬──────┘
                     ▼             ▼
      ┌──────────────────────┐  ┌──────────────────────────┐
      │ Anomalies & Shadowing│  │ Policy Reachability Graph│
      │ (radix / interval)   │  │ (NAT & routing aware)    │
      └──────────┬───────────┘  └────────────┬─────────────┘
                 │                           ▼
                 │              ┌──────────────────────────┐
                 │              │ Lateral Movement Engine  │
                 │              │ (Yen's k-shortest paths) │
                 │              └────────────┬─────────────┘
                 └─────────────┬─────────────┘
                               ▼
          ┌──────────────────────────────────────────────┐
          │              Audit Orchestrator              │
          │  Score A–F · Compliance Matrix · Drift Diff  │
          └───────────────────┬──────────────────────────┘
               ┌──────────────┼───────────────┐
               ▼              ▼               ▼
        FastAPI + Jobs   Cytoscape UI    PDF / Markdown
```

---

## 🔌 Supported Vendors

| Vendor | Input | NAT | Routing | Notes |
|:--|:--|:--|:--|:--|
| **SonicWall** | SonicOS CLI text | Object NAT | Interface subnets | Zone trust: WAN = 0, LAN = 100 |
| **Cisco ASA** | `show running-config` | Object static NAT / PAT | Static `route` | Extended ACLs bound via `access-group` |
| **Cisco FTD** | FMC JSON export | Manual NAT rules | `staticRoutes` | Multi-zone expansion, default actions |
| **Fortinet** | FortiOS config blocks | `firewall vip` (DNAT) | `router static` | Pre-NAT policy evaluation, built-in services |
| **Linux iptables** | `iptables-save` / JSON | PREROUTING `DNAT` | Routes | Evaluates `FORWARD` chains |

---

## 🚀 Quick Start

```bash
git clone https://github.com/RandilJayasinghe/netdrift-auditor.git
cd netdrift-auditor

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest -v                        # 86 unit, integration and security tests
```

### Run an audit from the CLI

```bash
netdrift audit tests/fixtures/bank_hq_sonicwall.conf tests/fixtures/profile.json \
  --md audit_report.md \
  --pdf audit_report.pdf \
  --cytoscape attack_graph.json
```

Add `--baseline old_config.conf` to include drift analysis.

### Audit profile

```json
{
  "entry_points": ["LAN", "internet"],
  "critical_assets": [
    {"name": "PCI_Zone_DB", "cidr": "10.10.30.10/32", "criticality": "critical", "category": "database"}
  ],
  "max_hops": 5,
  "max_paths_per_target": 10
}
```

`entry_points` accepts a zone name, CIDR, node id or `internet`.

---

## 🔎 What It Finds (Sample Config)

The bundled `bank_hq_sonicwall.conf` has deliberately planted flaws:

| Rule | Flaw | Severity |
|:--|:--|:--|
| **R9** | `DMZ → MGMT` any/any/any left over from an outage | 🔴 Critical |
| **R8** | RDP (3389) open from the Internet to the app server | 🔴 Critical |
| **R7** | Direct LAN → core database over MSSQL (1-hop attack path) | 🔴 Critical |
| **R6** | Deny rule shadowed by broader allow **R5** (never evaluated) | 🟠 High |
| **R5** | Users → DMZ with `any` service | 🟡 Medium |

It also reports multi-hop paths such as `LAN → DMZ → Core switch management` and `Internet → DMZ → Core switch management`.

---

## 🖥️ Web Dashboard

```bash
uvicorn netdrift.api.main:app --port 8000 --reload
```

Open **http://localhost:8000**, drop in a config file, set entry points and critical assets, then click **Run Audit & Visualize**.

- 🔴 **Red edges** are lateral-movement hops on an attack path
- ⬡ **Hexagon / diamond nodes** are firewalls and Internet ingress boundaries
- 🖱️ **Click** any node or edge to see permitted ports, translated NAT services and matched rule IDs

Interactive API docs are at `/docs`.

---

## 📡 API Reference

All endpoints live under `/api/v1` and accept `X-API-Key` or `Authorization: Bearer <JWT>`.

| Method | Endpoint | Role | Description |
|:--|:--|:--|:--|
| `POST` | `/audit/upload` | analyst | Upload and sanitize a firewall configuration |
| `POST` | `/audit/analyze` | analyst | Synchronous audit against an `AuditProfile` |
| `POST` | `/audit/jobs` | analyst | Submit an async audit job for large rulebases |
| `GET` | `/audit/jobs/{job_id}` | viewer | Poll job state (`queued`, `running`, `succeeded`) |
| `GET` | `/reports/attack-paths` | viewer | Cytoscape.js nodes/edges plus path list |
| `GET` | `/reports/summary` | viewer | Export `json`, `markdown` or `pdf` |
| `POST` | `/baselines` | analyst | Register a config as a golden baseline |
| `GET` | `/configs` | viewer | List sanitized configs (tenant-scoped) |
| `GET` | `/health` | public | Liveness and version |

```bash
H="X-API-Key: change-me"
CID=$(curl -s -H "$H" -F file=@tests/fixtures/bank_hq_sonicwall.conf \
      localhost:8000/api/v1/audit/upload | jq -r .config_id)

curl -s -H "$H" -H 'content-type: application/json' \
  localhost:8000/api/v1/audit/analyze \
  -d "{\"config_id\":\"$CID\",\"profile\":$(cat tests/fixtures/profile.json)}"
```

---

## 🔒 Security & Data Hygiene

- **Secret stripping:** passwords, pre-shared keys, SNMP communities, PEM keys and `ENC` blobs become `[REDACTED_*]` before parsing or storage
- **Sanitized-only persistence:** the repository layer rejects anything that is not a `SanitizedConfig`
- **Log masking:** a `LogRecord` factory scrubs credentials from every `netdrift.*` logger
- **Tenant isolation:** row-level partitioning, and cross-tenant access returns `404`
- **Least privilege:** Viewer, Analyst and Admin roles, with token-bucket rate limiting

---

## ⚠️ Scope & Limitations

- Reachability is **conservative**: it may report a path that cannot occur, but it is built not to miss one.
- Vendor dialects vary by firmware, so validate parsers against your own exports.
- Compliance mapping is **indicative** and should be confirmed by a QSA or auditor.
- IPv6, FQDN objects, VPN crypto maps and application/user-ID rules are not modelled.

---

## 🧪 Development

```bash
pytest -v                 # full suite
pytest tests/test_audit.py -k shadow
```

To add a vendor, subclass `BaseParser` (`sniff`, `parse`), register it in `parsers/__init__.py`, and add a fixture and test.

---

## 📄 License

Released under the [MIT License](LICENSE).

<div align="center">

**Built for network and security teams who want evidence, not assumptions.**

</div>
