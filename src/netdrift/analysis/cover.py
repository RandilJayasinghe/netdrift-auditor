"""Exact coverage of a rule's (src CIDR set x dst CIDR set x port set) space by a *union* of earlier rules.

Every rule is a product ("box") of three sets. Subtracting box A from box R splits R into at most
three disjoint boxes (the classic sweep decomposition):

    R \\ A = (R.src \\ A.src) x R.dst x R.ports
          u (R.src n A.src) x (R.dst \\ A.dst) x R.ports
          u (R.src n A.src) x (R.dst n A.dst) x (R.ports \\ A.ports)

CIDR blocks are either nested or disjoint (radix-tree property), so n/\\ on CIDR sets needs no
interval sweep, and a difference only ever splits a block along its prefix path (`address_exclude`,
at most `prefixlen` pieces). Ports use the interval algebra in `portset`. The residual region is
capped (`MAX_BOXES`): if a pathological rulebase blows it up the answer is "undetermined" and no
finding is raised, so the detector can only under-report, never produce a false positive.
"""
from __future__ import annotations

from ipaddress import IPv4Network, collapse_addresses
from typing import Iterable, Optional

from ..portset import PortSet

Nets = tuple[IPv4Network, ...]
Box = tuple[Nets, Nets, PortSet]
MAX_BOXES = 512


def _norm(nets: Iterable[IPv4Network]) -> Nets:
    return tuple(collapse_addresses(nets))


def intersect_nets(a: Nets, b: Nets) -> Nets:
    out: list[IPv4Network] = []
    for x in a:
        for y in b:
            if x.subnet_of(y):
                out.append(x)
            elif y.subnet_of(x):
                out.append(y)
    return _norm(out)


def subtract_nets(a: Nets, b: Nets) -> Nets:
    out: list[IPv4Network] = []
    for n in a:
        pieces = [n]
        for s in b:
            nxt: list[IPv4Network] = []
            for p in pieces:
                if p.subnet_of(s):
                    continue
                if s.subnet_of(p):
                    nxt.extend(p.address_exclude(s))
                else:
                    nxt.append(p)
            pieces = nxt
            if not pieces:
                break
        out.extend(pieces)
    return _norm(out)


def subtract_box(r: Box, a: Box) -> Optional[list[Box]]:
    """R minus A as disjoint boxes, or None when A does not overlap R at all."""
    s_int = intersect_nets(r[0], a[0])
    if not s_int:
        return None
    d_int = intersect_nets(r[1], a[1])
    if not d_int:
        return None
    p_int = r[2].intersection(a[2])
    if p_int.is_empty():
        return None
    out: list[Box] = []
    s_rem = subtract_nets(r[0], a[0])
    if s_rem:
        out.append((s_rem, r[1], r[2]))
    d_rem = subtract_nets(r[1], a[1])
    if d_rem:
        out.append((s_int, d_rem, r[2]))
    p_rem = r[2].difference(a[2])
    if p_rem:
        out.append((s_int, d_int, p_rem))
    return out


def overlaps(r: Box, a: Box) -> bool:
    return (any(x.overlaps(y) for x in r[0] for y in a[0]) and any(x.overlaps(y) for x in r[1] for y in a[1])
            and bool(r[2].intersection(a[2])))


def _span_covered(target: Nets, others: Iterable[Nets]) -> bool:
    """Interval check: is every target block inside the merged address span of `others`?"""
    spans = sorted((int(n.network_address), int(n.broadcast_address)) for nets in others for n in nets)
    merged: list[list[int]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return all(any(m[0] <= int(t.network_address) and int(t.broadcast_address) <= m[1] for m in merged) for t in target)


def covering_union(target: Box, earlier: Iterable[tuple[str, Box]]) -> Optional[list[str]]:
    """Return the ids of the earlier boxes (in order) that together cover `target` completely,
    or None if the target keeps any uncovered traffic (or the residue grew past MAX_BOXES).

    A cheap necessary condition runs first: the union of the overlapping boxes must span the target's
    source blocks, destination blocks and ports *separately*. Most non-shadowed rules fail here,
    so the exact (box-splitting) subtraction only runs when a cover is plausible."""
    cands = [(rid, box) for rid, box in earlier if overlaps(target, box)]
    if not cands:
        return None
    if not (_span_covered(target[0], (b[0] for _, b in cands)) and _span_covered(target[1], (b[1] for _, b in cands))):
        return None
    ports = PortSet()
    for _, b in cands:
        ports = ports.union(b[2])
    if not ports.covers(target[2]):
        return None
    region: list[Box] = [target]
    used: list[str] = []
    for rid, box in cands:
        nxt: list[Box] = []
        hit = False
        for piece in region:
            parts = subtract_box(piece, box)
            if parts is None:
                nxt.append(piece)
            else:
                hit = True
                nxt.extend(parts)
        if not hit:
            continue
        used.append(rid)
        region = nxt
        if not region:
            return used
        if len(region) > MAX_BOXES:
            return None
    return None


class NetIndex:
    """Overlap index over CIDR blocks (radix-tree semantics without an explicit tree).

    CIDR blocks are nested or disjoint, so the blocks overlapping a query block `q` are exactly
    (a) its ancestors - at most 33, found by hashing (prefixlen, prefix bits) - and (b) the blocks
    lying inside `q`, which form one contiguous run in start-address order (bisect). A rule whose
    destination is unrelated to `q` is therefore never touched, instead of scanning every earlier rule.
    """

    def __init__(self) -> None:
        self._anc: dict[tuple[int, int], list[int]] = {}
        self._starts: list[tuple[int, int, int]] = []  # (start, -prefixlen, item) kept sorted

    def add(self, item: int, nets: Iterable[IPv4Network]) -> None:
        import bisect
        for n in nets:
            self._anc.setdefault((n.prefixlen, int(n.network_address) >> (32 - n.prefixlen) if n.prefixlen else 0), []).append(item)
            bisect.insort(self._starts, (int(n.network_address), -n.prefixlen, item))

    def query(self, nets: Iterable[IPv4Network]) -> set[int]:
        import bisect
        out: set[int] = set()
        for q in nets:
            base = int(q.network_address)
            for plen in range(q.prefixlen + 1):
                hit = self._anc.get((plen, base >> (32 - plen) if plen else 0))
                if hit:
                    out.update(hit)
            end = int(q.broadcast_address)
            i = bisect.bisect_left(self._starts, (base, -33, -1))
            while i < len(self._starts) and self._starts[i][0] <= end:
                out.add(self._starts[i][2])
                i += 1
        return out
