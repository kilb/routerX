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
    """Return entropy, length, max_count, distribution of digits in text."""
    digits = extract_digits(text)
    if not digits:
        return {
            "count": 0, "entropy": 0.0, "max_count": 0,
            "distribution": {}, "max_digit": None,
        }
    counts = Counter(digits)
    return {
        "count": len(digits),
        "entropy": shannon_entropy(digits),
        "max_count": max(counts.values()),
        "max_digit": counts.most_common(1)[0][0],
        "distribution": dict(counts),
    }
