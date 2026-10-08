"""Tests for Fortinet FortiOS parser."""

from netdrift.models import Action
from netdrift.parsers import parse_config


def test_fortinet_parser_basic():
    config_dump = """
    config system interface
        edit "port1"
            set ip 192.168.1.1 255.255.255.0
        next
        edit "port2"
            set ip 10.0.0.1 255.255.255.0
        next
    end
    config firewall address
        edit "LAN_NET"
            set subnet 192.168.1.0 255.255.255.0
        next
        edit "SERVER_DB"
            set subnet 10.0.0.50 255.255.255.255
        next
    end
    config firewall service custom
        edit "MYSQL"
            set tcp-portrange 3306
        next
    end
    config firewall policy
        edit 1
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "LAN_NET"
            set dstaddr "SERVER_DB"
            set action accept
            set service "MYSQL"
            set comments "Allow LAN to DB"
        next
        edit 2
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set service "ALL"
        next
    end
    """
    cfg = parse_config(config_dump)
    assert cfg.vendor == "fortinet"
    assert len(cfg.rules) == 2
    assert cfg.rules[0].action == Action.ALLOW
    assert cfg.rules[0].src_zone == "port1"
    assert cfg.rules[0].dst_zone == "port2"
    assert cfg.rules[1].action == Action.DENY
    assert "LAN_NET" in cfg.address_objects
    assert "MYSQL" in cfg.service_objects