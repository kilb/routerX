"""Empirical latency bands per model family (seconds / tokens-per-second).

These are HEURISTIC thresholds -- actual TTFT and tokens/sec vary by load,
region, and request size. Values chosen so legitimate frontier models
comfortably fit and bare/small OSS on shared VMs clearly don't. Calibration
TODO: replace with percentile distributions from real provider endpoints.
"""
from __future__ import annotations

# (min_ttft_s, max_ttft_s, min_tps, max_tps)
MODEL_BANDS: dict[str, tuple[float, float, float, float]] = {
    "claude-3-5-sonnet": (0.2, 3.0, 20.0, 90.0),
    "claude-3-5-haiku": (0.15, 2.5, 30.0, 150.0),
    "claude-sonnet-4": (0.2, 3.0, 20.0, 90.0),
    "claude-opus": (0.3, 4.0, 15.0, 60.0),
    "gpt-4o-mini": (0.1, 2.0, 40.0, 200.0),
    "gpt-4o": (0.15, 2.5, 25.0, 120.0),
    "gpt-4-turbo": (0.2, 3.0, 20.0, 90.0),
    "o1": (0.3, 5.0, 15.0, 80.0),
    "gemini-1.5-pro": (0.2, 3.0, 20.0, 100.0),
    "gemini-1.5-flash": (0.1, 2.0, 40.0, 180.0),
    "gemini-2": (0.15, 2.5, 25.0, 120.0),
}


def lookup_band(model: str) -> tuple[float, float, float, float] | None:
    """Return the latency band for ``model`` by longest substring match."""
    model_l = model.lower()
    for key in sorted(MODEL_BANDS, key=len, reverse=True):
        if key in model_l:
            return MODEL_BANDS[key]
    return None
