"""R01 — Error Rate benchmark.

Sends 20 simple requests (in concurrent batches of 5) and counts how many
return a non-200 status or a network error.
"""
from __future__ import annotations

import logging
from typing import ClassVar

from ..models import ProbeRequest
from .base import BaseBenchmark, BenchmarkResult, benchmark, grade_value

logger = logging.getLogger("router-auditor.benchmark")

TOTAL_REQUESTS = 20
BATCH_SIZE = 5

_ERROR_RATE_THRESHOLDS: dict[str, float] = {
    "A": 0.0,
    "B": 5.0,
    "C": 10.0,
    "D": 20.0,
}

# Vary prompts across batches to avoid trivial caching.
_PROMPTS = [
    "What is 2 + 2?",
    "Name three primary colours.",
    "What is the capital of France?",
    "How many days are in a week?",
    "What is the boiling point of water in Celsius?",
]


@benchmark
class R01_ErrorRate(BaseBenchmark):
    bench_id: ClassVar[str] = "R01"
    bench_name: ClassVar[str] = "Error Rate"
    category: ClassVar[str] = "reliability"
    description: ClassVar[str] = (
        "Sends 20 concurrent requests in batches and reports the "
        "percentage that fail (non-200 or network error)."
    )

    async def run(self) -> BenchmarkResult:
        error_count = 0
        rate_limited = 0
        total_sent = 0

        for batch_idx in range(TOTAL_REQUESTS // BATCH_SIZE):
            probes = [
                ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "messages": [
                            {
                                "role": "user",
                                "content": _PROMPTS[
                                    (batch_idx * BATCH_SIZE + j)
                                    % len(_PROMPTS)
                                ],
                            }
                        ],
                        "max_tokens": 20,
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description=f"error-rate probe batch {batch_idx + 1} #{j + 1}",
                )
                for j in range(BATCH_SIZE)
            ]
            responses = await self.client.send_concurrent(probes)
            total_sent += len(responses)
            for r in responses:
                if r.status_code == 429:
                    rate_limited += 1
                elif r.is_network_error or r.status_code != 200:
                    error_count += 1

        error_rate_pct = (error_count / total_sent * 100) if total_sent else 100.0
        grade = grade_value(
            error_rate_pct, _ERROR_RATE_THRESHOLDS, lower_is_better=True,
        )

        return BenchmarkResult(
            bench_id=self.bench_id,
            name=self.bench_name,
            category=self.category,
            score=round(error_rate_pct, 1),
            grade=grade,
            metrics={
                "error_count": error_count,
                "rate_limited_429": rate_limited,
                "total": total_sent,
                "error_rate_pct": round(error_rate_pct, 1),
            },
            description=self.description,
        )
