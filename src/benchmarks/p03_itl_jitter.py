"""P03 — Inter-Token Latency (ITL) Jitter benchmark.

Sends streaming requests and analyses the consistency of inter-chunk arrival
times.  A low coefficient of variation (CV) indicates smooth, predictable
streaming.
"""
from __future__ import annotations

import logging
import statistics
from typing import ClassVar

from ..models import ProbeRequest
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value

logger = logging.getLogger("router-auditor.benchmark")

_PROMPTS = [
    "Describe the process of photosynthesis in plants step by step.",
    "Explain how a combustion engine works in simple terms.",
    "Write a short story about a robot learning to paint.",
]

_CV_THRESHOLDS: dict[str, float] = {
    "A": 0.3,
    "B": 0.5,
    "C": 0.8,
    "D": 1.2,
}


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Return the value at the given percentile from a pre-sorted list."""
    idx = int(len(sorted_vals) * pct)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


@benchmark
class P03_ITLJitter(BaseBenchmark):
    bench_id: ClassVar[str] = "P03"
    bench_name: ClassVar[str] = "Inter-Token Latency Jitter"
    category: ClassVar[str] = "performance"
    description: ClassVar[str] = (
        "Measures the consistency of inter-chunk arrival times during "
        "streaming. Lower coefficient of variation means smoother delivery."
    )

    async def run(self) -> BenchmarkResult:
        all_itl_ms: list[float] = []
        errors: list[str] = []

        for i, prompt_text in enumerate(_PROMPTS):
            probe = ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "messages": [{"role": "user", "content": prompt_text}],
                    "max_tokens": 256,
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"ITL jitter probe {i + 1}",
            )
            resp = await self.client.send_stream(probe)
            if resp.is_network_error:
                errors.append(resp.error or "unknown network error")
                continue
            if resp.status_code != 200:
                errors.append(f"status {resp.status_code}")
                continue
            if len(resp.chunk_timestamps) < 3:
                errors.append("fewer than 3 chunks received")
                continue

            # Compute inter-token latencies (differences of consecutive timestamps)
            ts = resp.chunk_timestamps
            itl_s = [ts[j + 1] - ts[j] for j in range(len(ts) - 1)]
            all_itl_ms.extend(v * 1000 for v in itl_s)

        if len(all_itl_ms) < 2:
            return BenchmarkResult(
                bench_id=self.bench_id,
                name=self.bench_name,
                category=self.category,
                score=0.0,
                grade="F",
                metrics={
                    "error": "insufficient ITL samples",
                    "errors": errors,
                },
                description=self.description,
            )

        mean_itl = statistics.mean(all_itl_ms)
        stdev_itl = statistics.stdev(all_itl_ms)
        cv = stdev_itl / mean_itl if mean_itl > 0 else float("inf")

        all_itl_ms.sort()
        p99_itl = _percentile(all_itl_ms, 0.99)

        grade = grade_value(cv, _CV_THRESHOLDS, lower_is_better=True)

        return BenchmarkResult(
            bench_id=self.bench_id,
            name=self.bench_name,
            category=self.category,
            score=round(cv, 3),
            grade=grade,
            metrics={
                "mean_itl_ms": round(mean_itl, 2),
                "stdev_itl_ms": round(stdev_itl, 2),
                "cv": round(cv, 3),
                "p99_itl_ms": round(p99_itl, 2),
                "sample_count": len(all_itl_ms),
                "errors": errors,
            },
            description=self.description,
        )
