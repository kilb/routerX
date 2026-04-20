"""P01 — Time to First Token (TTFT) benchmark.

Sends streaming requests with varying prompt lengths and measures how long it
takes for the first chunk to arrive.
"""
from __future__ import annotations

import logging
import statistics
from typing import ClassVar

from ..models import ProbeRequest
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value

logger = logging.getLogger("router-auditor.benchmark")

# Topics vary per request to defeat upstream caching.
_TOPICS = [
    "the history of railway engineering",
    "how coral reefs form and sustain marine life",
    "the invention of the printing press and its societal impact",
    "how modern cryptography protects digital communication",
    "the role of bees in global agriculture",
]

_PROMPT_PADS = [
    # short (~50 tokens)
    "",
    # medium (~500 tokens) — pad with context so the prompt is longer
    (
        " Provide extensive background context. Consider economic, social, "
        "and technological factors that contributed to development over "
        "multiple centuries. Discuss key figures, pivotal events, and the "
        "lasting legacy. " * 6
    ),
    # long (~2000 tokens) — repeat padding to reach ~2000 tokens
    (
        " Provide a comprehensive, deeply detailed analysis covering every "
        "major milestone, the people involved, the geopolitical context, "
        "competing theories, and modern-day relevance. Include specific "
        "dates, statistics, and references where appropriate. " * 20
    ),
    # short
    "",
    # medium
    (
        " Elaborate on the subject with thorough detail, examining causes, "
        "effects, historical parallels, and future implications. " * 8
    ),
]

_TTFT_THRESHOLDS: dict[str, float] = {
    "A": 500.0,
    "B": 1000.0,
    "C": 2000.0,
    "D": 4000.0,
}


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Return the value at the given percentile from a pre-sorted list."""
    idx = int(len(sorted_vals) * pct)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


@benchmark
class P01_TTFT(BaseBenchmark):
    bench_id: ClassVar[str] = "P01"
    bench_name: ClassVar[str] = "Time to First Token"
    category: ClassVar[str] = "performance"
    description: ClassVar[str] = (
        "Measures how quickly the first streamed token arrives across "
        "varying prompt lengths."
    )

    async def run(self) -> BenchmarkResult:
        ttft_values: list[float] = []
        errors: list[str] = []

        for i, topic in enumerate(_TOPICS):
            pad = _PROMPT_PADS[i % len(_PROMPT_PADS)]
            prompt = f"Write a brief paragraph about {topic}.{pad}"
            probe = ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 100,
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"TTFT probe {i + 1}",
            )
            resp = await self.client.send_stream(probe)
            if resp.is_network_error:
                errors.append(resp.error or "unknown network error")
                continue
            if resp.status_code != 200:
                errors.append(f"status {resp.status_code}")
                continue
            if not resp.chunk_timestamps:
                errors.append("no chunks received")
                continue
            # chunk_timestamps are relative seconds from request start
            ttft_ms = resp.chunk_timestamps[0] * 1000
            ttft_values.append(ttft_ms)

        if not ttft_values:
            return BenchmarkResult(
                bench_id=self.bench_id,
                name=self.bench_name,
                category=self.category,
                score=0.0,
                grade="F",
                metrics={"error": "all requests failed", "errors": errors},
                description=self.description,
            )

        ttft_values.sort()
        median_ms = statistics.median(ttft_values)
        p95_ms = _percentile(ttft_values, 0.95)
        min_ms = ttft_values[0]
        max_ms = ttft_values[-1]
        grade = grade_value(median_ms, _TTFT_THRESHOLDS, lower_is_better=True)

        return BenchmarkResult(
            bench_id=self.bench_id,
            name=self.bench_name,
            category=self.category,
            score=median_ms,
            grade=grade,
            metrics={
                "median_ms": round(median_ms, 1),
                "p95_ms": round(p95_ms, 1),
                "min_ms": round(min_ms, 1),
                "max_ms": round(max_ms, 1),
                "sample_count": len(ttft_values),
                "errors": errors,
            },
            description=self.description,
        )
