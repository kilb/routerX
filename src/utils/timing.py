"""Chunk-timing analysis for streaming detectors (D32a)."""
from __future__ import annotations

import statistics


def analyze_chunks(timestamps: list[float]) -> dict:
    """Compute TTFB, mean interval, stdev, and coefficient of variation.

    ``timestamps`` must be elapsed seconds from request start, one per SSE
    chunk. Returns ``{"analyzable": False}`` when the sample is too small.
    """
    if len(timestamps) < 3:
        return {"analyzable": False, "count": len(timestamps)}
    intervals = [
        timestamps[i + 1] - timestamps[i]
        for i in range(len(timestamps) - 1)
    ]
    mean = statistics.mean(intervals)
    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    return {
        "analyzable": True,
        "count": len(timestamps),
        "ttfb_s": timestamps[0],
        "mean_ms": mean * 1000,
        "stdev_ms": stdev * 1000,
        "cv": stdev / mean if mean > 0 else 0.0,
    }
