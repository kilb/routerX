"""P02 — Tokens Per Second (TPS) benchmark.

Sends streaming requests that elicit ~200 tokens and measures throughput as
``token_count / (last_chunk_ts - first_chunk_ts)``.
"""
from __future__ import annotations

import logging
import statistics
from typing import ClassVar

from ..models import ProbeRequest
from ..tokenizer import token_counter
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value

logger = logging.getLogger("router-auditor.benchmark")

_PROMPTS = [
    "List and briefly describe 15 notable inventions of the 20th century.",
    "Explain the water cycle in detail, covering evaporation, condensation, and precipitation.",
    "Describe the plot of a fictional adventure story involving a lost city in the jungle.",
    "Outline the key principles of microeconomics with real-world examples.",
    "Summarize the major events of the space race between 1957 and 1975.",
]

_TPS_THRESHOLDS: dict[str, float] = {
    "A": 80.0,
    "B": 50.0,
    "C": 30.0,
    "D": 15.0,
}


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Return the value at the given percentile from a pre-sorted list."""
    idx = int(len(sorted_vals) * pct)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


@benchmark
class P02_TPS(BaseBenchmark):
    bench_id: ClassVar[str] = "P02"
    bench_name: ClassVar[str] = "Tokens Per Second"
    category: ClassVar[str] = "performance"
    description: ClassVar[str] = (
        "Measures token generation throughput by dividing output token "
        "count by the time between first and last streamed chunks."
    )

    async def run(self) -> BenchmarkResult:
        tps_values: list[float] = []
        errors: list[str] = []

        for i, prompt_text in enumerate(_PROMPTS):
            probe = ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "messages": [{"role": "user", "content": prompt_text}],
                    "max_tokens": 256,
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"TPS probe {i + 1}",
            )
            resp = await self.client.send_stream(probe)
            if resp.is_network_error:
                errors.append(resp.error or "unknown network error")
                continue
            if resp.status_code != 200:
                errors.append(f"status {resp.status_code}")
                continue
            if len(resp.chunk_timestamps) < 2:
                errors.append("fewer than 2 chunks received")
                continue

            content = resp.content
            if not content:
                errors.append("empty content")
                continue

            token_count = token_counter.count(content)
            first_ts = resp.chunk_timestamps[0]
            last_ts = resp.chunk_timestamps[-1]
            duration_s = last_ts - first_ts
            if duration_s <= 0:
                errors.append("zero duration between chunks")
                continue

            tps = token_count / duration_s
            tps_values.append(tps)

        if not tps_values:
            return BenchmarkResult(
                bench_id=self.bench_id,
                name=self.bench_name,
                category=self.category,
                score=0.0,
                grade="F",
                metrics={"error": "all requests failed", "errors": errors},
                description=self.description,
            )

        tps_values.sort()
        median_tps = statistics.median(tps_values)
        p95_tps = _percentile(tps_values, 0.95)
        min_tps = tps_values[0]
        max_tps = tps_values[-1]
        grade = grade_value(
            median_tps, _TPS_THRESHOLDS, lower_is_better=False,
        )

        return BenchmarkResult(
            bench_id=self.bench_id,
            name=self.bench_name,
            category=self.category,
            score=round(median_tps, 1),
            grade=grade,
            metrics={
                "median_tps": round(median_tps, 1),
                "p95_tps": round(p95_tps, 1),
                "min_tps": round(min_tps, 1),
                "max_tps": round(max_tps, 1),
                "sample_count": len(tps_values),
                "errors": errors,
            },
            description=self.description,
        )
