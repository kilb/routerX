"""Text diversity helpers (shared by D44 / D61)."""
from __future__ import annotations

from itertools import combinations
import re

_WORD_RE = re.compile(r"[a-z']+")


def word_set(text: str) -> set[str]:
    """Lowercase word-token set from ``text``."""
    return set(_WORD_RE.findall(text.lower()))


def mean_jaccard_dist(texts: list[str]) -> float:
    """Mean pairwise Jaccard distance (1 - intersection/union) over word sets."""
    sets = [word_set(t) for t in texts if t]
    if len(sets) < 2:
        return 0.0
    dists: list[float] = []
    for a, b in combinations(sets, 2):
        union = a | b
        if not union:
            continue
        dists.append(1 - len(a & b) / len(union))
    return sum(dists) / len(dists) if dists else 0.0
