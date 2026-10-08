"""NAT-aware reachability (destination NAT / port forwarding) and routing-aware graph generation."""
import json
from ipaddress import IPv4Network as N

import pytest

from netdrift.engine import run_audit
from netdrift.models import Action, DnatRule, FirewallConfig, Interface, Route, Rule, ServiceEntry, Zone
from netdrift.parsers import parse_config
from netdrift.schemas import AuditProfile

from conftest import FIX
from test_new_parsers import FORTI


def profile(*assets, entry="internet", **kw):
    return AuditProfile(entry_points=[entry], critical_assets=[{"name": n, "cidr": c} for n, c in assets], **kw)


def hop_services(run, target):
    return [(h.src, h.dst, h.services, h.nat) for p in run.result.attack_paths if p.target == target and p.length == 2 for h in p.hops][:2]


# ---- port-translation attack paths ------------------------------------------------------------
def test_ftd_post_nat_port_forward_path():
    """FTD matches the *real* address/port (post-NAT); the attacker uses the translated external port 8080."""
    run = run_audit(parse_config((FIX / "ftd_sample.json").read_text()), profile(("DB", "10.2.30.10/32")))
    paths = [p for p in run.result.attack_paths if p.length == 2]
    assert paths, "internet -> (DNAT 8080->80) -> web -> DB:1433 must be found"
    first, second = paths[0].hops
    assert first.src.startswith("Internet") and first.dst == "dmz 10.2.50.0/24"
    assert first.services == ["tcp/8080 (port-forward 198.51.100.4 -> 10.2.50.10:80 [web-publish])"]  # ext port, not 80
    assert first.nat and second.services == ["tcp/1433"] and second.rule_ids == ["R2"]
    edge = run.graph.edges["zone:outside", "seg:dmz:10.2.50.0/24"]
    assert edge["ports"].contains("tcp", 8080) and not edge["ports"].contains("tcp", 80)  # raw tcp/80 is NOT published


def test_config_without_dnat_keeps_legacy_zone_pair_semantics():
    """No DNAT declared -> NAT awareness is off (documented): rule R1 alone exposes the web tier on its real port."""
    doc = json.loads((FIX / "ftd_sample.json").read_text())
    doc["natRules"]["items"][0]["enabled"] = False
    run = run_audit(parse_config(json.dumps(doc)), profile(("DB", "10.2.30.10/32")))
    p = next(p for p in run.result.attack_paths if p.length == 2)
    assert p.hops[0].services == ["tcp/80"] and p.hops[0].nat == []


def test_iptables_dnat_path_and_unpublished_port():
    cfg = parse_config((FIX / "iptables_sample.rules").read_text())
    run = run_audit(cfg, profile(("DB", "10.0.2.10/32")))
    p = next(p for p in run.result.attack_paths if p.length == 2)
    assert p.hops[0].services[0].startswith("tcp/8443") and "10.0.1.5:443" in p.hops[0].services[0]
    assert p.hops[1].services == ["tcp/5432-5433"]
    e = run.graph.edges["zone:wan", "seg:dmz:10.0.1.0/24"]
    assert e["ports"].contains("tcp", 8443) and not e["ports"].contains("tcp", 443)


def test_iptables_dnat_with_dropped_forward_gives_no_path():
    txt = (FIX / "iptables_sample.rules").read_text().replace(
        "-A FORWARD -i eth0 -o eth1 -d 10.0.1.5/32 -p tcp -m tcp --dport 443", "-A FORWARD -i eth0 -o eth1 -d 10.0.1.5/32 -p tcp -m tcp --dport 8443")
    run = run_audit(parse_config(txt), profile(("DB", "10.0.2.10/32")))
    # FORWARD allows 8443 on the real host, but the DNAT target port is 443: the translated packet is dropped
    assert not run.result.attack_paths


def test_fortinet_vip_pre_nat_evaluation():
    """FortiOS policy references the VIP (external address) = pre_nat ordering; HTTPS(443) vs extport 8443."""
    cfg = parse_config(FORTI)
    run = run_audit(cfg, profile(("DB", "10.9.2.10/32")))
    p = next(p for p in run.result.attack_paths if p.length == 2)
    assert "port-forward 203.0.113.10 -> 10.9.1.20:443" in p.hops[0].services[0]
    e = run.graph.edges["zone:wan1", "seg:dmz:10.9.1.0/24"]
    assert e["ports"].contains("tcp", 8443)           # external port reaches the server
    assert not e["ports"].contains("tcp", 443)        # ...and the mapped port is not itself published on the VIP


def test_fortinet_vip_without_matching_policy_is_unreachable():
    cfg = parse_config(FORTI.replace('set dstaddr "VIP-WEB"', 'set dstaddr "DB"'))
    run = run_audit(cfg, profile(("DB", "10.9.2.10/32")))
    assert not run.result.attack_paths  # policy no longer references the VIP address


def test_nat_aware_mode_blocks_unnated_private_inbound():
    """Rule any->10.0.1.0/24 would be 'reachable' in a NAT-less model; with a DNAT table present, private
    space is only reachable through the mappings."""
    cfg = FirewallConfig(
        vendor="t", zones={"wan": Zone(name="wan", trust=0), "dmz": Zone(name="dmz", trust=25)},
        interfaces={"e0": Interface(name="e0", zone="wan"), "e1": Interface(name="e1", zone="dmz", address="10.0.1.1/24")},
        rules=[Rule(id="R1", priority=1, action=Action.ALLOW, src_zone="wan", dst_zone="dmz", src_nets=[N("0.0.0.0/0")],
                    dst_nets=[N("10.0.1.0/24")], services=[ServiceEntry(protocol="tcp", port_start=22, port_end=22)])])
    legacy = run_audit(cfg, profile(("web", "10.0.1.5/32")))
    assert legacy.result.attack_paths and legacy.result.attack_paths[0].hops[0].nat == []
    cfg.dnat.append(DnatRule(ext_if="e0", ext_ip=N("203.0.113.9/32"), mapped_ip=N("10.0.1.99/32"), protocol="tcp",
                             ext_port=(443, 443), mapped_port=(443, 443)))
    aware = run_audit(cfg, profile(("web", "10.0.1.5/32")))
    assert not aware.result.attack_paths  # 10.0.1.5 has no mapping and rule R1 doesn't cover port 443 anyway


# ---- routing ----------------------------------------------------------------------------------
def two_zone_cfg(route_zone: str | None = None) -> FirewallConfig:
    cfg = FirewallConfig(
        vendor="t", zones={z: Zone(name=z, trust=t) for z, t in (("lan", 100), ("dmz", 25), ("db", 90))},
        interfaces={"e1": Interface(name="e1", zone="lan", address="10.0.1.1/24"), "e2": Interface(name="e2", zone="dmz", address="10.0.2.1/24"),
                    "e3": Interface(name="e3", zone="db", address="10.0.3.1/24")},
        rules=[Rule(id="R1", priority=1, action=Action.ALLOW, src_zone="lan", dst_zone="dmz", src_nets=[N("10.0.1.0/24")],
                    dst_nets=[N("10.20.0.0/16")], services=[ServiceEntry(protocol="tcp", port_start=22, port_end=22)])])
    if route_zone:
        cfg.routes.append(Route(dest=N("10.20.0.0/16"), next_hop="10.0.%d.254" % {"dmz": 2, "db": 3}[route_zone]))
    return cfg


def test_routed_subnet_behind_next_hop_is_discovered():
    run = run_audit(two_zone_cfg("dmz"), profile(("far", "10.20.5.5/32"), entry="lan"))
    assert any("routed" in n for n in (d["info"].label for _, d in run.graph.nodes(data=True)))
    p = run.result.attack_paths[0]
    assert p.hops[0].services == ["tcp/22"] and p.hops[-1].dst == "far"


def test_route_to_other_zone_vetoes_rule_edge():
    """The rule says lan->dmz for 10.20/16, but the routing table forwards it out of 'db': no dmz-edge."""
    ok = run_audit(two_zone_cfg("dmz"), profile(("far", "10.20.5.5/32"), entry="lan"))
    veto = run_audit(two_zone_cfg("db"), profile(("far", "10.20.5.5/32"), entry="lan"))
    assert ok.result.attack_paths and not [p for p in veto.result.attack_paths if p.target == "far" and not p.hops[0].implicit]


def test_unresolvable_route_is_reported():
    cfg = two_zone_cfg()
    cfg.routes.append(Route(dest=N("192.168.77.0/24"), next_hop="172.31.0.1"))
    run = run_audit(cfg, profile(("far", "10.20.5.5/32"), entry="lan"))
    assert any("192.168.77.0/24" in w for w in run.result.warnings)


def test_asa_static_nat_and_route_parse():
    txt = (FIX / "asa_sample.conf").read_text() + (
        "object network WEB\n nat (dmz,outside) static 198.51.100.4 service tcp 80 8080\n"
        "route inside 10.30.0.0 255.255.0.0 10.1.0.254 1\n")
    cfg = parse_config(txt, "cisco_asa")
    (d,) = cfg.dnat
    assert (str(d.mapped_ip), str(d.ext_ip), d.ext_port, d.mapped_port, d.ext_if) == ("10.1.50.10/32", "198.51.100.4/32", (8080, 8080), (80, 80), "outside")
    assert str(cfg.routes[0].dest) == "10.30.0.0/16" and cfg.routes[0].interface == "inside"
    run = run_audit(cfg, profile(("web", "10.1.50.10/32")))
    e = next((e for u, v, e in run.graph.edges(data=True) if e.get("nat")), None)
    assert e and e["ports"].contains("tcp", 8080) and not e["ports"].contains("tcp", 80)
