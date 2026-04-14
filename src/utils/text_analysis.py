"""Lightweight text heuristics used by detectors (D4b / D50 / D30 ...)."""
from __future__ import annotations

import re

_COMMON_WORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "can",
    "i", "you", "he", "she", "it", "we", "they",
    "and", "or", "but", "not", "no", "so", "if",
    "of", "in", "on", "at", "to", "for", "with", "from", "by", "as",
    "this", "that", "my", "your", "his", "her", "its", "our", "their",
}

# English negation cues + CJK negations (via unicode escapes to keep the
# source ASCII-only; runtime matching works against rendered Chinese text).
_NEGATIONS = {
    "not", "no", "never",
    "don't", "doesn't", "didn't", "isn't", "aren't",
    "won't", "wouldn't", "couldn't", "shouldn't",
    "cannot", "can't",
    "\u4e0d",          # bu (not)
    "\u6ca1\u6709",    # mei-you (do not have)
    "\u65e0\u6cd5",    # wu-fa (cannot)
    "\u5207\u52ff",    # qie-wu (do not)
    "\u7981\u6b62",    # jin-zhi (forbid)
    "\u4e0d\u8981",    # bu-yao (do not)
    "\u4e0d\u4f1a",    # bu-hui (will not)
    "\u672a",          # wei (have not)
}


def readable_bigram_ratio(text: str) -> float:
    """Return the fraction of adjacent word pairs that are both common words.

    A strong signal that a passage is human-readable natural English.
    Returns 1.0 for very short inputs to avoid false positives.
    """
    words = re.findall(r"[a-zA-Z]+", text.lower())
    if len(words) < 3:
        return 1.0
    pairs = sum(
        1 for i in range(len(words) - 1)
        if words[i] in _COMMON_WORDS and words[i + 1] in _COMMON_WORDS
    )
    return pairs / (len(words) - 1)


_ASCII_NEGATIONS = {n for n in _NEGATIONS if n.isascii()}
_CJK_NEGATIONS = _NEGATIONS - _ASCII_NEGATIONS


def count_negations(text: str) -> int:
    """Count negation cues. ASCII via word-tokenization, CJK via substring
    scan. Each path is exclusive so a token is never double-counted."""
    lowered = text.lower()
    ascii_tokens = re.findall(r"[a-z']+", lowered)
    hits = sum(1 for w in ascii_tokens if w in _ASCII_NEGATIONS)
    for neg in _CJK_NEGATIONS:
        hits += lowered.count(neg)
    return hits
