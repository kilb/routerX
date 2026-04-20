"""R03 — Latency Consistency benchmark.

Sends 10 identical requests sequentially and measures how consistent the
response latencies are (coefficient of variation).
"""
from __future__ import annotations

import logging
import statistics
from typing import ClassVar

from ..models import ProbeRequest
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value

logger = logging.getLogger("router-auditor.benchmark")

SAMPLE_COUNT = 10

_CV_THRESHOLDS: dict[str, float] = {
    "A": 0.15,
    "B": 0.3,
    "C": 0.5,
    "D": 0.8,
}


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Return the value at the given percentile from a pre-sorted list."""
    idx = int(len(sorted_vals) * pct)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


@benchmark
class R03_Consistency(BaseBenchmark):
    bench_id: ClassVar[str] = "R03"
    bench_name: ClassVar[str] = "Latency Consistency"
    category: ClassVar[str] = "reliability"
    description: ClassVar[str] = (
        "Sends 10 identical requests sequentially and checks how "
        "consistent the latencies are via coefficient of variation."
    )

    async def run(self) -> BenchmarkResult:
        latencies: list[float] = []
        errors: list[str] = []

        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "messages": [
                    {"role": "user", "content": "What is 2 + 2? Reply with the number only."}
                ],
                "max_tokens": 10,
            },
            endpoint_path=self.config.default_endpoint_path,
            description="latency-consistency probe",
        )

        for i in range(SAMPLE_COUNT):
            resp = await self.client.send(probe)
            if resp.is_network_error:
                errors.append(f"request {i + 1}: {resp.error}")
                continue
            if resp.status_code != 200:
                errors.append(f"request {i + 1}: status {resp.status_code}")
                continue
            latencies.append(resp.latency_ms)

        if len(latencies) < 2:
            return BenchmarkResult(
                bench_id=self.bench_id,
                name=self.bench_name,
                category=self.category,
                score=0.0,
                grade="F",
                metrics={
                    "error": "insufficient successful responses",
                    "errors": errors,
                },
                description=self.description,
            )

        mean_ms = statistics.mean(latencies)
        stdev_ms = statistics.stdev(latencies)
        cv = stdev_ms / mean_ms if mean_ms > 0 else float("inf")

        latencies.sort()
        min_ms = latencies[0]
        max_ms = latencies[-1]
        p95_ms = _percentile(latencies, 0.95)

        grade = grade_value(cv, _CV_THRESHOLDS, lower_is_better=True)

        return BenchmarkResult(
            bench_id=self.bench_id,
            name=self.bench_name,
            category=self.category,
            score=round(cv, 3),
            grade=grade,
            metrics={
                "mean_ms": round(mean_ms, 1),
                "stdev_ms": round(stdev_ms, 1),
                "cv": round(cv, 3),
                "min_ms": round(min_ms, 1),
                "max_ms": round(max_ms, 1),
                "p95_ms": round(p95_ms, 1),
                "sample_count": len(latencies),
                "errors": errors,
            },
            description=self.description,
        )
