"""Statistical helpers for behavioral fingerprinting."""
from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(sequence: list[str] | str) -> float:
    """Bits of entropy in a sequence. Returns 0 for empty input."""
    if not sequence:
        return 0.0
    counts = Counter(sequence)
    total = sum(counts.values())
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c > 0
    )


def extract_digits(text: str) -> list[str]:
    """Extract standalone digits 0-9 from text."""
    return re.findall(r"(?<!\d)([0-9])(?!\d)", text)


def digit_stats(text: str) -> dict:
    """Return entropy, length, max_count, distribution of digits in text.

    The ``counts`` key is a fixed-length list of 10 ints where index i
    holds the occurrence count of digit str(i).
    """
    digits = extract_digits(text)
    if not digits:
        return {
            "count": 0, "entropy": 0.0, "max_count": 0,
            "distribution": {}, "max_digit": None,
            "counts": [0] * 10,
        }
    counts = Counter(digits)
    counts_vec = [counts.get(str(i), 0) for i in range(10)]
    return {
        "count": len(digits),
        "entropy": shannon_entropy(digits),
        "max_count": max(counts.values()),
        "max_digit": counts.most_common(1)[0][0],
        "distribution": dict(counts),
        "counts": counts_vec,
    }


def chi_square_uniform(counts: list[int]) -> float:
    """Chi-square statistic against a uniform distribution.

    Returns 0.0 for empty input. Degrees of freedom = len(counts) - 1
    (9 for decimal digits).
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    expected = total / len(counts)
    return sum((c - expected) ** 2 / expected for c in counts)
