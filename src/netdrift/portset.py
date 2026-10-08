"""Exact set arithmetic over (protocol, port-interval) pairs.

Service matching is the heart of shadow detection and first-match graph evaluation, so it is
implemented with merged integer intervals rather than expanded port lists (a /0-65535 range
costs one tuple, not 65k entries).
"""
from __future__ import annotations

from typing import Iterable

Interval = tuple[int, int]
PROTOS = ("tcp", "udp", "icmp")
FULL: Interval = (0, 65535)


def _merge(iv: Iterable[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in a:
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


def _intersect(a: list[Interval], b: list[Interval]) -> list[Interval]:
    i = j = 0
    out: list[Interval] = []
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


class PortSet:
    """Immutable-by-convention set of (protocol, port) pairs."""

    __slots__ = ("_d",)

    def __init__(self, d: dict[str, list[Interval]] | None = None) -> None:
        merged = {p: _merge(v) for p, v in (d or {}).items()}
        self._d = {p: v for p, v in merged.items() if v}

    @classmethod
    def from_entries(cls, entries: Iterable) -> "PortSet":
        """Build from objects exposing .protocol/.port_start/.port_end ('ip' = every protocol)."""
        d: dict[str, list[Interval]] = {}
        for e in entries:
            if e.protocol == "ip":
                for p in PROTOS:
                    d.setdefault(p, []).append(FULL)
            else:
                d.setdefault(e.protocol, []).append((e.port_start, e.port_end))
        return cls(d)

    @classmethod
    def everything(cls) -> "PortSet":
        return cls({p: [FULL] for p in PROTOS})

    def intervals(self) -> dict[str, list[Interval]]:
        return {p: list(v) for p, v in self._d.items()}

    def union(self, o: "PortSet") -> "PortSet":
        d = {p: list(v) for p, v in self._d.items()}
        for p, v in o._d.items():
            d.setdefault(p, []).extend(v)
        return PortSet(d)

    def intersection(self, o: "PortSet") -> "PortSet":
        return PortSet({p: _intersect(v, o._d[p]) for p, v in self._d.items() if p in o._d})

    def difference(self, o: "PortSet") -> "PortSet":
        return PortSet({p: _subtract(v, o._d.get(p, [])) for p, v in self._d.items()})

    def is_empty(self) -> bool:
        return not self._d

    def is_everything(self) -> bool:
        return all(self._d.get(p) == [FULL] for p in PROTOS)

    def covers(self, o: "PortSet") -> bool:
        return o.difference(self).is_empty()

    def contains(self, proto: str, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self._d.get(proto, ()))

    def size(self, protos: tuple[str, ...] = ("tcp", "udp")) -> int:
        return sum(hi - lo + 1 for p in protos for lo, hi in self._d.get(p, ()))

    def labels(self) -> list[str]:
        if self.is_everything():
            return ["any"]
        out: list[str] = []
        for p in sorted(self._d):
            for lo, hi in self._d[p]:
                if (lo, hi) == FULL:
                    out.append(f"{p}/any")
                elif lo == hi:
                    out.append(f"{p}/{lo}")
                else:
                    out.append(f"{p}/{lo}-{hi}")
        return out

    def __bool__(self) -> bool:
        return not self.is_empty()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortSet) and self._d == other._d

    def __repr__(self) -> str:
        return f"PortSet({self.labels()})"
