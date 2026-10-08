from __future__ import annotations

from ..errors import ParseError
from ..models import FirewallConfig
from .base import BaseParser
from .cisco_asa import CiscoAsaParser
from .cisco_ftd import CiscoFtdParser
from .fortinet import FortinetParser
from .iptables import IptablesParser
from .sonicwall import SonicWallParser

PARSERS: dict[str, type[BaseParser]] = {
    SonicWallParser.vendor: SonicWallParser,
    CiscoAsaParser.vendor: CiscoAsaParser,
    FortinetParser.vendor: FortinetParser,
    CiscoFtdParser.vendor: CiscoFtdParser,
    IptablesParser.vendor: IptablesParser,
}


def detect_vendor(text: str) -> str:
    for name, cls in PARSERS.items():
        if cls.sniff(text):
            return name

    raise ParseError("could not auto-detect vendor; pass vendor explicitly (" + ", ".join(PARSERS) + ")")


def parse_config(text: str, vendor: str | None = None) -> FirewallConfig:
    vendor = (vendor or detect_vendor(text)).lower()
    if vendor not in PARSERS:
        raise ParseError(f"unsupported vendor '{vendor}'. Supported: {', '.join(PARSERS)}")
    return PARSERS[vendor]().parse(text)


__all__ = ["parse_config", "detect_vendor", "PARSERS", "BaseParser", "FortinetParser", "CiscoFtdParser", "IptablesParser"]