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
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value, percentile

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
        per_request_cvs: list[float] = []
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
            itl_ms = [(ts[j + 1] - ts[j]) * 1000 for j in range(len(ts) - 1)]
            all_itl_ms.extend(itl_ms)
            # Per-request CV: avoids mixing inter-request variance with intra-request jitter
            if len(itl_ms) >= 2:
                m = statistics.mean(itl_ms)
                s = statistics.stdev(itl_ms)
                per_request_cvs.append(s / m if m > 0 else float("inf"))

        if not per_request_cvs:
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

        mean_itl = statistics.mean(all_itl_ms) if all_itl_ms else 0
        stdev_itl = statistics.stdev(all_itl_ms) if len(all_itl_ms) >= 2 else 0
        # Use median of per-request CVs (not pooled CV) for fairer measurement
        cv = statistics.median(per_request_cvs)

        all_itl_ms.sort()
        p99_itl = percentile(all_itl_ms, 0.99) if all_itl_ms else 0

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
