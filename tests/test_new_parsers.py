"""Cisco FTD (FMC JSON) and iptables parsers, plus FortiOS VIP/route extraction."""
import json
from ipaddress import IPv4Network as N

import pytest

from netdrift.errors import ParseError
from netdrift.models import Action
from netdrift.parsers import PARSERS, detect_vendor, parse_config

from conftest import FIX


@pytest.fixture(scope="module")
def ftd():
    return parse_config((FIX / "ftd_sample.json").read_text())


@pytest.fixture(scope="module")
def ipt():
    return parse_config((FIX / "iptables_sample.rules").read_text())


def test_registered_and_sniffed():
    assert {"cisco_ftd", "iptables"} <= set(PARSERS)
    assert detect_vendor((FIX / "ftd_sample.json").read_text()) == "cisco_ftd"
    assert detect_vendor((FIX / "iptables_sample.rules").read_text()) == "iptables"
    assert detect_vendor((FIX / "iptables_sample.json").read_text()) == "iptables"
    # the existing vendors are not stolen by the new sniffers
    assert detect_vendor((FIX / "asa_sample.conf").read_text()) == "cisco_asa"
    assert detect_vendor((FIX / "bank_hq_sonicwall.conf").read_text()) == "sonicwall"


# ---- FTD ---------------------------------------------------------------------------------------
def test_ftd_objects_zones_and_rules(ftd):
    assert ftd.hostname == "FTD-EDGE-01" and ftd.vendor == "cisco_ftd" and ftd.nat_order == "post_nat"
    assert ftd.zones["outside"].trust == 0 and ftd.zones["inside"].trust == 100
    assert str(ftd.interfaces["GigabitEthernet0/1"].address) == "10.2.50.1/24"
    ids = [r.id for r in ftd.rules]
    assert ids == ["R1", "R2", "R3", "R5", "R5.2"]  # MONITOR (R4) skipped; multi-zone rule expanded
    r2 = next(r for r in ftd.rules if r.id == "R2")
    assert sorted(map(str, r2.src_nets)) == ["10.2.50.10/32", "10.2.50.11/32"]  # group object + literal
    assert r2.ports().labels() == ["tcp/1433"] and "app tier" in r2.comment
    assert next(r for r in ftd.rules if r.id == "R3").action is Action.DENY
    r1 = ftd.rules[0]
    assert r1.ports().labels() == ["tcp/80"] and r1.src_any
    assert any("MONITOR" in w for w in ftd.warnings)


def test_ftd_static_nat_becomes_port_forward(ftd):
    (d,) = ftd.dnat
    assert (str(d.ext_ip), str(d.mapped_ip), d.protocol, d.ext_port, d.mapped_port, d.ext_if) == \
           ("198.51.100.4/32", "10.2.50.10/32", "tcp", (8080, 8080), (80, 80), "outside")


def test_ftd_rejects_non_fmc_json():
    with pytest.raises(ParseError):
        parse_config('{"hello": 1}', "cisco_ftd")
    with pytest.raises(ParseError):
        parse_config("{not json", "cisco_ftd")


def test_ftd_unresolved_object_dropped_with_warning():
    doc = json.loads((FIX / "ftd_sample.json").read_text())
    doc["accessPolicies"][0]["rules"]["items"][0]["destinationNetworks"] = {"objects": [{"name": "GHOST"}]}
    cfg = parse_config(json.dumps(doc))
    assert "R1" not in [r.id for r in cfg.rules] and any("GHOST" in w for w in cfg.warnings)


def test_ftd_default_allow_appends_catch_all():
    doc = json.loads((FIX / "ftd_sample.json").read_text())
    doc["accessPolicies"][0]["defaultAction"] = {"action": "TRUST"}
    cfg = parse_config(json.dumps(doc))
    assert cfg.rules[-1].id == "RDEFAULT" and cfg.rules[-1].src_any and cfg.rules[-1].dst_any


# ---- iptables ----------------------------------------------------------------------------------
def test_iptables_text_rules(ipt):
    assert ipt.hostname == "edge-gw01" and ipt.vendor == "iptables"
    assert ipt.zones["wan"].trust == 0 and ipt.zones["dmz"].trust == 25
    assert str(ipt.interfaces["eth1"].address) == "10.0.1.1/24"
    by = {r.id: r for r in ipt.rules}
    assert "R1" not in by  # RELATED,ESTABLISHED return-traffic rule opens no new flow
    assert (by["R2"].src_zone, by["R2"].dst_zone, by["R2"].ports().labels()) == ("wan", "dmz", ["tcp/443"])
    assert by["R3"].ports().labels() == ["tcp/5432-5433"]  # multiport 5432,5433 merged
    assert by["R4"].action is Action.DENY and by["R5"].src_any and by["R5"].dst_any
    assert not any(r.action is Action.ALLOW and r.src_zone == "wan" and r.dst_zone == "wan" for r in ipt.rules)
    # FORWARD policy DROP -> no appended allow-all
    assert all(r.id != "R9" for r in ipt.rules)


def test_iptables_nat_negation_and_inputs(ipt):
    (d,) = ipt.dnat
    assert (str(d.ext_ip), str(d.mapped_ip), d.ext_port, d.mapped_port, d.protocol) == \
           ("203.0.113.5/32", "10.0.1.5/32", (8443, 8443), (443, 443), "tcp")
    assert any("INPUT" in w for w in ipt.warnings)                           # INPUT is reported as not modelled
    assert any("! -s 10.0.3.99/32" in w for w in ipt.warnings)               # negated ACCEPT: over-approximated + warned
    assert {str(r) for r in ipt.routes[0:1] and [ipt.routes[0].dest]} == {"10.0.20.0/24"}


def test_iptables_json_equivalent():
    cfg = parse_config((FIX / "iptables_sample.json").read_text())
    assert cfg.hostname == "edge-gw02" and [r.id for r in cfg.rules] == ["R1", "R2", "R3"]
    assert cfg.rules[1].ports().labels() == ["tcp/5432-5433"] and cfg.dnat[0].mapped_ip == N("10.0.1.5/32")


def test_iptables_policy_accept_and_deny_with_unmodelled_match():
    cfg = parse_config("*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i eth0 -o eth1 -m set --match-set bad src -j DROP\n"
                       "-A FORWARD -i eth0 -o eth1 -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
    assert [r.id for r in cfg.rules] == ["R2", "R3"] and cfg.rules[-1].src_any  # DROP skipped (warned), policy ACCEPT appended
    assert any("skipped" in w and "ipset" in w for w in cfg.warnings)


def test_iptables_rejects_garbage():
    with pytest.raises(ParseError):
        parse_config("*filter\nCOMMIT\n", "iptables")


# ---- FortiOS additions -------------------------------------------------------------------------
FORTI = """
config system global
    set hostname "FGT-EDGE"
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
    edit "dmz"
        set ip 10.9.1.1 255.255.255.0
    next
    edit "internal"
        set ip 10.9.2.1 255.255.255.0
        set role lan
    next
end
config router static
    edit 1
        set dst 10.9.50.0 255.255.255.0
        set gateway 10.9.1.254
        set device "dmz"
    next
end
config firewall address
    edit "DB"
        set subnet 10.9.2.10 255.255.255.255
    next
end
config firewall vip
    edit "VIP-WEB"
        set extip 203.0.113.10
        set extintf "wan1"
        set mappedip "10.9.1.20"
        set portforward enable
        set protocol tcp
        set extport 8443
        set mappedport 443
    next
end
config firewall service custom
    edit "PG"
        set tcp-portrange 5432
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP-WEB"
        set action accept
        set service "HTTPS"
    next
    edit 2
        set srcintf "dmz"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "DB"
        set action accept
        set service "PG"
    next
end
"""


def test_fortinet_vip_route_and_ids():
    cfg = parse_config(FORTI)
    assert cfg.hostname == "FGT-EDGE" and cfg.nat_order == "pre_nat"
    assert cfg.zones["wan1"].trust == 0 and cfg.zones["internal"].trust == 100
    (d,) = cfg.dnat
    assert (str(d.ext_ip), str(d.mapped_ip), d.ext_port, d.mapped_port) == ("203.0.113.10/32", "10.9.1.20/32", (8443, 8443), (443, 443))
    assert cfg.address_objects["VIP-WEB"].networks == [N("203.0.113.10/32")]  # policies reference the VIP by name
    assert [str(r.dest) for r in cfg.routes] == ["10.9.50.0/24"]
    assert [r.id for r in cfg.rules] == ["R1", "R2"] and cfg.rules[0].dst_nets == [N("203.0.113.10/32")]
