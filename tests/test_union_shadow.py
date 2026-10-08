"""Union / multi-rule shadowing (analysis/cover.py + detect_shadowed)."""
import time
from ipaddress import IPv4Network as N

from netdrift.analysis.anomalies import detect_shadowed
from netdrift.analysis.index import compile_rules
from netdrift.models import Action, FirewallConfig, Rule, ServiceEntry, Severity, Zone


def rule(i, action, src, dst, lo=0, hi=65535, proto="tcp", sz="LAN", dz="DMZ"):
    return Rule(id=f"R{i}", priority=i, action=Action(action), src_zone=sz, dst_zone=dz,
                src_nets=[N(s) for s in ([src] if isinstance(src, str) else src)],
                dst_nets=[N(d) for d in ([dst] if isinstance(dst, str) else dst)],
                services=[ServiceEntry(protocol=proto, port_start=lo, port_end=hi)])


def shadow(*rules):
    cfg = FirewallConfig(vendor="test", zones={"LAN": Zone(name="LAN"), "DMZ": Zone(name="DMZ")}, rules=list(rules))
    return detect_shadowed(compile_rules(cfg))


def test_source_split_across_two_rules_shadows_deny():
    f = shadow(rule(1, "allow", "10.0.0.0/25", "10.1.0.0/24", 1, 1000),
               rule(2, "allow", "10.0.0.128/25", "10.1.0.0/24", 1, 1000),
               rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24", 80, 443))
    assert len(f) == 1 and f[0].rule_ids == ["R3", "R1", "R2"]
    assert f[0].severity is Severity.HIGH and "union of R1, R2" in f[0].title  # a deny that never fires


def test_port_split_across_two_rules():
    f = shadow(rule(1, "allow", "10.0.0.0/24", "10.1.0.0/24", 1, 500),
               rule(2, "allow", "10.0.0.0/24", "10.1.0.0/24", 501, 1000),
               rule(3, "allow", "10.0.0.0/24", "10.1.0.0/24", 400, 600))
    assert [x.rule_ids for x in f] == [["R3", "R1", "R2"]]
    assert f[0].severity is Severity.LOW  # all same action: redundant


def test_mixed_actions_in_union():
    f = shadow(rule(1, "deny", "10.0.0.0/25", "10.1.0.0/24", 22, 22),
               rule(2, "allow", "10.0.0.128/25", "10.1.0.0/24", 22, 22),
               rule(3, "allow", "10.0.0.0/24", "10.1.0.0/24", 22, 22))
    assert len(f) == 1 and f[0].severity is Severity.MEDIUM  # allow rule is dead (masked by a deny)


def test_destination_and_source_both_partial():
    # 2x2 grid of /25s covered by four rules: only the full union covers the /24 x /24 target
    rules = [rule(i + 1, "allow", s, d, 80, 80) for i, (s, d) in enumerate(
        [("10.0.0.0/25", "10.1.0.0/25"), ("10.0.0.128/25", "10.1.0.0/25"),
         ("10.0.0.0/25", "10.1.0.128/25"), ("10.0.0.128/25", "10.1.0.128/25")])]
    f = shadow(*rules, rule(5, "deny", "10.0.0.0/24", "10.1.0.0/24", 80, 80))
    assert [x.rule_ids for x in f] == [["R5", "R1", "R2", "R3", "R4"]]


def test_gap_is_not_reported():
    # port gap
    assert shadow(rule(1, "allow", "10.0.0.0/24", "10.1.0.0/24", 1, 500), rule(2, "allow", "10.0.0.0/24", "10.1.0.0/24", 502, 1000),
                  rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24", 400, 600)) == []
    # CIDR gap: 10.0.0.128/26 is covered by nobody
    assert shadow(rule(1, "allow", "10.0.0.0/25", "10.1.0.0/24"), rule(2, "allow", "10.0.0.192/26", "10.1.0.0/24"),
                  rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24")) == []
    # protocol gap: udp is never covered by tcp rules
    f = shadow(rule(1, "allow", "10.0.0.0/24", "10.1.0.0/24"), rule(2, "allow", "10.0.0.0/24", "10.1.0.0/24", 1, 10),
               rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24", proto="udp"))
    assert [x.rule_ids[0] for x in f] == ["R2"]  # R2 is a plain single-rule shadow; the udp deny R3 stays live


def test_zone_pair_is_respected():
    # the covering rules belong to a different zone pair, so they cannot shadow the target
    assert shadow(rule(1, "allow", "10.0.0.0/25", "10.1.0.0/24", sz="DMZ", dz="LAN"),
                  rule(2, "allow", "10.0.0.128/25", "10.1.0.0/24", sz="DMZ", dz="LAN"),
                  rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24")) == []
    # an 'any'-zone rule does participate in the union
    assert len(shadow(rule(1, "allow", "10.0.0.0/25", "10.1.0.0/24", sz="any", dz="any"),
                      rule(2, "allow", "10.0.0.128/25", "10.1.0.0/24"), rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24"))) == 1


def test_single_rule_shadow_still_reported_as_single():
    f = shadow(rule(1, "allow", "0.0.0.0/0", "10.1.0.0/24", 0, 65535), rule(2, "deny", "10.0.0.0/24", "10.1.0.0/24", 22, 22))
    assert f[0].rule_ids == ["R2", "R1"] and "union" not in f[0].title


def test_disabled_rules_do_not_shadow():
    r2 = rule(2, "allow", "10.0.0.128/25", "10.1.0.0/24")
    r2.enabled = False
    assert shadow(rule(1, "allow", "10.0.0.0/25", "10.1.0.0/24"), r2, rule(3, "deny", "10.0.0.0/24", "10.1.0.0/24")) == []


def test_worst_case_same_destination_stays_fast():
    # every rule shares one destination, so the index cannot prune: still must not explode
    rules = [rule(i, "allow", f"10.{i // 250}.{i % 250}.1/32", "10.99.0.0/24", 443, 443) for i in range(1, 1501)]
    t = time.perf_counter()
    shadow(*rules)
    assert time.perf_counter() - t < 10


def test_scales_to_thousands_of_rules():
    rules = [rule(i, "allow", f"172.16.{i // 250}.{i % 250}/32", "10.9.0.0/24", 443, 443) for i in range(1, 1801)]
    # a /24 worth of /32 allows (256 rules) followed by a deny over the whole /24: covered only by the union
    for k in range(256):
        rules.append(rule(1801 + k, "allow", f"10.0.0.{k}/32", "10.1.0.0/24", 80, 80))
    rules.append(rule(2100, "deny", "10.0.0.0/24", "10.1.0.0/24", 80, 80))
    t = time.perf_counter()
    f = shadow(*rules)
    elapsed = time.perf_counter() - t
    assert any(x.rule_ids[0] == "R2100" and len(x.rule_ids) == 257 for x in f)
    assert elapsed < 5, f"shadow detection took {elapsed:.1f}s"
