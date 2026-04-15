"""Writing-style statistics for model-family fingerprinting (D65).

Extracts lightweight textual features (sentence length, em-dash rate,
bullet rate, opening-phrase, passive-voice rate) and computes a
normalized distance from per-family centroids.

HEURISTIC: centroids and stdevs below are hand-tuned plausible values.
TODO: calibrate on real frontier-model traces (Claude 3.5/4, GPT-4o/4.1,
Gemini 2.x, Qwen2.5, Llama 3.x) once a labeled corpus is available.
"""
from __future__ import annotations

import math
import re


_SENT_SPLIT = re.compile(r"[.!?]+(?:\s+|$)")
_WORD_RE = re.compile(r"[A-Za-z']+")
_EM_DASH_RE = re.compile(r"\u2014|--")
_BULLET_LINE_RE = re.compile(r"^\s*(?:[-*\u2022]|\d+[.)])\s+", re.MULTILINE)
_PASSIVE_RE = re.compile(
    r"\b(?:am|is|are|was|were|be|been|being)\s+\w+(?:ed|en)\b",
    re.IGNORECASE,
)
_SURE_OPENER_RE = re.compile(
    r"^\s*(?:sure|certainly|of course|absolutely|here(?:'s| is)|"
    r"happy to help|great question)\b",
    re.IGNORECASE,
)


def sentence_lengths(text: str) -> list[int]:
    """Return word count per non-empty sentence."""
    sentences = [s.strip() for s in _SENT_SPLIT.split(text) if s.strip()]
    return [len(_WORD_RE.findall(s)) for s in sentences if _WORD_RE.findall(s)]


def feature_vector(text: str) -> dict[str, float]:
    """Extract style features from ``text``.

    Returns a dict with:
      - avg_sentence_len: mean words per sentence
      - em_dash_rate: em-dashes per 1000 chars
      - bullet_rate: bullet lines per total lines (0..1)
      - opens_with_sure: 1.0 if opens with an assistant-style pleasantry
      - passive_rate: passive-voice matches per 100 words
    """
    lens = sentence_lengths(text)
    avg_sentence_len = sum(lens) / len(lens) if lens else 0.0

    char_count = max(len(text), 1)
    em_dash_rate = len(_EM_DASH_RE.findall(text)) * 1000.0 / char_count

    lines = text.splitlines() or [text]
    bullet_rate = (
        len(_BULLET_LINE_RE.findall(text)) / len(lines) if lines else 0.0
    )

    opens_with_sure = 1.0 if _SURE_OPENER_RE.match(text) else 0.0

    word_count = max(len(_WORD_RE.findall(text)), 1)
    passive_rate = len(_PASSIVE_RE.findall(text)) * 100.0 / word_count

    return {
        "avg_sentence_len": avg_sentence_len,
        "em_dash_rate": em_dash_rate,
        "bullet_rate": bullet_rate,
        "opens_with_sure": opens_with_sure,
        "passive_rate": passive_rate,
    }


# HEURISTIC centroids — hand-tuned.
# TODO: calibrate FAMILY_CENTROIDS and FAMILY_STDEV empirically.
# Procedure:
# 1. Collect 50+ responses from each family via direct API calls
# 2. Compute feature_vector() on each response
# 3. Set centroid = mean, stdev = sample std dev
# 4. Validate: ensure normalized_distance < 2 for same-family,
#    > 4 for cross-family
#
# Claude: moderate em-dashes, longer sentences, fewer bullets than GPT.
# GPT: bullet-heavy, frequent "Sure" openers, medium sentences.
# Gemini: similar to GPT but fewer openers, slightly shorter sentences.
# Qwen/Llama (bare): short flat sentences, no em-dashes, no bullets.
FAMILY_CENTROIDS: dict[str, dict[str, float]] = {
    "claude": {
        "avg_sentence_len": 18.0,
        "em_dash_rate": 2.5,
        "bullet_rate": 0.15,
        "opens_with_sure": 0.2,
        "passive_rate": 3.0,
    },
    "gpt": {
        "avg_sentence_len": 14.0,
        "em_dash_rate": 1.2,
        "bullet_rate": 0.30,
        "opens_with_sure": 0.5,
        "passive_rate": 2.5,
    },
    "gemini": {
        "avg_sentence_len": 13.0,
        "em_dash_rate": 0.8,
        "bullet_rate": 0.25,
        "opens_with_sure": 0.3,
        "passive_rate": 2.5,
    },
    "qwen": {
        "avg_sentence_len": 10.0,
        "em_dash_rate": 0.2,
        "bullet_rate": 0.08,
        "opens_with_sure": 0.1,
        "passive_rate": 1.5,
    },
    "llama": {
        "avg_sentence_len": 10.0,
        "em_dash_rate": 0.2,
        "bullet_rate": 0.08,
        "opens_with_sure": 0.15,
        "passive_rate": 1.5,
    },
}


# HEURISTIC per-feature stdev used for z-score normalization.
# TODO: calibrate FAMILY_STDEV empirically using the same procedure
# as FAMILY_CENTROIDS above (step 3: stdev = sample std dev).
FAMILY_STDEV: dict[str, dict[str, float]] = {
    "claude": {
        "avg_sentence_len": 6.0,
        "em_dash_rate": 2.0,
        "bullet_rate": 0.15,
        "opens_with_sure": 0.5,
        "passive_rate": 2.0,
    },
    "gpt": {
        "avg_sentence_len": 4.0,
        "em_dash_rate": 3.0,
        "bullet_rate": 0.50,
        "opens_with_sure": 0.6,
        "passive_rate": 2.5,
    },
    "gemini": {
        "avg_sentence_len": 6.0,
        "em_dash_rate": 1.5,
        "bullet_rate": 0.20,
        "opens_with_sure": 0.5,
        "passive_rate": 2.0,
    },
    "qwen": {
        "avg_sentence_len": 5.0,
        "em_dash_rate": 1.0,
        "bullet_rate": 0.15,
        "opens_with_sure": 0.4,
        "passive_rate": 1.5,
    },
    "llama": {
        "avg_sentence_len": 5.0,
        "em_dash_rate": 1.0,
        "bullet_rate": 0.15,
        "opens_with_sure": 0.4,
        "passive_rate": 1.5,
    },
}


def normalized_distance(fv: dict[str, float], family: str) -> float | None:
    """Euclidean z-score distance between ``fv`` and the family centroid.

    Returns None if ``family`` has no known centroid.
    """
    centroid = FAMILY_CENTROIDS.get(family)
    stdev = FAMILY_STDEV.get(family)
    if centroid is None or stdev is None:
        return None
    total = 0.0
    for key, mu in centroid.items():
        sigma = stdev.get(key) or 1.0
        z = (fv.get(key, 0.0) - mu) / sigma
        total += z * z
    return math.sqrt(total)


def infer_family(model: str) -> str | None:
    """Infer the model family from a claimed model name.

    Returns one of "claude"/"gpt"/"gemini"/"qwen"/"llama", or None.
    """
    if not model:
        return None
    m = model.lower()
    if "claude" in m:
        return "claude"
    if "gemini" in m:
        return "gemini"
    if "qwen" in m:
        return "qwen"
    if "llama" in m:
        return "llama"
    if "gpt" in m or re.search(r"\bo[134]\b", m):
        return "gpt"
    return None
