"""End-to-end verification that the intentional flaws in the fixture are detected."""
import pytest

from netdrift.analysis.index import compile_rules
from netdrift.engine import run_audit
from netdrift.errors import ParseError, ProfileError
from netdrift.models import Action, Severity
from netdrift.parsers import parse_config
from netdrift.portset import PortSet
from netdrift.reports.markdown import render_markdown
from netdrift.reports.pdf import render_pdf
from netdrift.schemas import AuditProfile


@pytest.fixture(scope="module")
def run(cfg, profile):
    return run_audit(cfg, profile)


def by_cat(run, cat):
    return [f for f in run.result.findings if f.category == cat]


# ---- parser ---------------------------------------------------------------------------------
def test_parser_normalises_objects_and_rules(cfg):
    assert cfg.hostname == "BANK-HQ-FW01" and cfg.vendor == "sonicwall"
    assert set(cfg.zones) == {"WAN", "LAN", "DMZ", "PCI_DB", "MGMT"}
    assert cfg.zones["WAN"].trust == 0 and cfg.zones["LAN"].trust == 100
    assert len(cfg.rules) == 10 and not cfg.warnings
    r2 = next(r for r in cfg.rules if r.id == "R2")
    assert sorted(str(n) for n in r2.dst_nets) == ["10.10.30.10/32", "10.10.30.11/32"]  # group expanded
    assert r2.action is Action.ALLOW and r2.ports().labels() == ["tcp/1433"]
    assert len(cfg.nat_policies) == 1


def test_parser_rejects_garbage():
    with pytest.raises(ParseError):
        parse_config("hello world")


def test_unresolved_reference_is_reported_not_silent():
    c = parse_config('address-object ipv4 "A" host 1.1.1.1 zone LAN\n'
                     'access-rule ipv4 from LAN to WAN action allow source address name "A" service any destination address any\n'
                     'access-rule ipv4 from LAN to WAN action allow source address name "GHOST" service any destination address any\n')
    assert len(c.rules) == 1 and any("GHOST" in w for w in c.warnings)


# ---- anomaly detection ----------------------------------------------------------------------
def test_shadowed_rule_detected(run):
    sh = by_cat(run, "SHADOWED_RULE")
    assert [f.rule_ids for f in sh] == [["R6", "R5"]]
    assert sh[0].severity is Severity.HIGH and "Delete rule R6" in sh[0].remediation


def test_any_to_any_detected(run):
    f = [x for x in by_cat(run, "OVERLY_PERMISSIVE") if x.rule_ids == ["R9"]]
    assert f and f[0].severity is Severity.CRITICAL


def test_broad_lan_to_dmz_flagged_medium(run):
    f = [x for x in by_cat(run, "OVERLY_PERMISSIVE") if x.rule_ids == ["R5"]]
    assert f and f[0].severity is Severity.MEDIUM


def test_rdp_from_internet_flagged(run):
    f = [x for x in by_cat(run, "MGMT_EXPOSURE") if x.rule_ids == ["R8"]]
    assert f and f[0].severity is Severity.CRITICAL and "RDP" in f[0].title


def test_nat_exposure(run):
    assert by_cat(run, "NAT_EXPOSURE")


# ---- graph / lateral movement ---------------------------------------------------------------
def test_direct_exposed_database_path(run):
    direct = [p for p in run.result.attack_paths if p.target == "PCI_Zone_DB" and p.entry.startswith("LAN") and p.length == 1]
    assert direct, "LAN -> DB must be a 1-hop path via R7"
    assert direct[0].severity is Severity.CRITICAL and direct[0].rule_ids == ["R7"]
    assert direct[0].hops[0].services == ["tcp/1433"]


def test_multi_hop_path_via_dmz_to_db_and_mgmt(run):
    mg = [p for p in run.result.attack_paths if p.target == "Core_Banking_Switch_Mgmt" and p.entry.startswith("LAN")]
    assert mg and mg[0].length == 2 and {"R5", "R9"} <= set(mg[0].rule_ids)
    assert any(h.dst == "Core_Banking_Switch_Mgmt" for h in mg[0].hops)


def test_internet_reaches_management_via_dmz(run):
    p = [p for p in run.result.attack_paths if p.entry.startswith("Internet") and p.target == "Core_Banking_Switch_Mgmt"]
    assert p and p[0].length == 2 and "R9" in p[0].rule_ids


def test_default_deny_blocks_unlisted_flows(run):
    g = run.graph
    assert not g.has_edge("seg:PCI_DB:10.10.30.0/24", "seg:LAN:10.10.10.0/24")
    assert not g.has_edge("seg:MGMT:10.10.99.0/24", "seg:LAN:10.10.10.0/24")


def test_shadowed_deny_does_not_block_ssh(run):
    e = run.graph.edges["seg:LAN:10.10.10.0/24", "seg:DMZ:10.10.20.0/24"]
    assert "R5" in e["rule_ids"] and e["ports"].contains("tcp", 22)  # deny R6 never effective


# ---- scoring / reports ----------------------------------------------------------------------
def test_score_and_compliance(run):
    r = run.result
    assert r.score.grade in {"D", "F"} and r.score.score < 50
    assert {c.requirement: c.status for c in r.compliance}["PCI-DSS v4.0 1.2.5"] == "FAIL"
    assert all(f.id.startswith("ND-") for f in r.findings)


def test_reports_render(run):
    md = render_markdown(run.result)
    assert "Any-to-Any" in md and "Remediation" in md
    assert render_pdf(run.result)[:4] == b"%PDF"


def test_bad_entry_point(cfg, profile):
    bad = AuditProfile(entry_points=["nope"], critical_assets=profile.critical_assets)
    with pytest.raises(ProfileError):
        run_audit(cfg, bad)


# ---- drift ----------------------------------------------------------------------------------
def test_drift_detects_emergency_rule(sonic_text, profile):
    base_text = "\n".join(l for l in sonic_text.splitlines() if "TEMP-OUTAGE" not in l)
    base, cur = parse_config(base_text), parse_config(sonic_text)
    r = run_audit(cur, profile, baseline=base).result
    assert r.drift and len(r.drift.added) == 1
    assert any(f.category == "POLICY_DRIFT" and f.severity is Severity.HIGH for f in r.findings)
    assert not run_audit(base, profile, baseline=base).result.drift.added


# ---- portset / second vendor ----------------------------------------------------------------
def test_portset_algebra():
    from netdrift.models import ServiceEntry as S
    a = PortSet.from_entries([S(protocol="tcp", port_start=1, port_end=1000)])
    b = PortSet.from_entries([S(protocol="tcp", port_start=400, port_end=500)])
    assert a.covers(b) and not b.covers(a)
    assert a.difference(b).labels() == ["tcp/1-399", "tcp/501-1000"]
    assert PortSet.everything().is_everything() and PortSet().is_empty()


def test_cisco_asa_parser():
    from pathlib import Path
    c = parse_config((Path(__file__).parent / "fixtures" / "asa_sample.conf").read_text())
    assert c.vendor == "cisco_asa" and c.zones["outside"].trust == 0 and len(c.rules) == 5
    assert c.rules[0].src_zone == "outside" and c.rules[0].ports().labels() == ["tcp/80", "tcp/443"]
    assert c.rules[1].hit_count == 0 and c.rules[1].ports().labels() == ["tcp/3389"]
    assert not c.warnings
