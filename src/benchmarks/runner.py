"""Run all benchmarks and produce a report."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from ..client import RouterClient
from ..models import TestConfig
from .base import BaseBenchmark, BenchmarkResult, get_all_benchmarks

logger = logging.getLogger("router-auditor.benchmark")

_GRADE_MAP: dict[str, int] = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}


class BenchmarkReport:
    """Aggregated results from a full benchmark suite run."""

    def __init__(self) -> None:
        self.results: list[BenchmarkResult] = []
        self.overall_grade: str = ""
        self.total_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        scores = [_GRADE_MAP.get(r.grade, 0) for r in self.results]
        avg = sum(scores) / len(scores) if scores else 0.0
        if avg >= 3.5:
            self.overall_grade = "A"
        elif avg >= 2.5:
            self.overall_grade = "B"
        elif avg >= 1.5:
            self.overall_grade = "C"
        elif avg >= 0.5:
            self.overall_grade = "D"
        else:
            self.overall_grade = "F"
        return {
            "overall_grade": self.overall_grade,
            "total_latency_ms": round(self.total_latency_ms, 1),
            "benchmarks": [r.to_dict() for r in self.results],
        }


class BenchmarkRunner:
    """Instantiate with a :class:`TestConfig` and call :meth:`run_all`."""

    def __init__(self, config: TestConfig) -> None:
        self.config = config

    async def run_all(
        self,
        on_progress: Callable[[int, int, str], None] | None = None,
        on_result: Callable[[BenchmarkResult], None] | None = None,
    ) -> BenchmarkReport:
        """Execute every registered benchmark sequentially.

        *on_progress* is called after each benchmark with ``(done, total, bench_id)``.
        *on_result* is called after each benchmark with the ``BenchmarkResult``.
        """
        import src.benchmarks  # noqa: F401 — trigger auto-import

        all_cls = get_all_benchmarks()
        report = BenchmarkReport()
        t0 = time.perf_counter()

        async with RouterClient(
            endpoint=self.config.router_endpoint,
            api_key=self.config.api_key,
            auth_method=self.config.auth_method,
            extra_headers=self.config.extra_headers,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
        ) as client:
            total = len(all_cls)
            for i, (bid, cls) in enumerate(sorted(all_cls.items())):
                logger.info("[%s] running %s ...", bid, cls.bench_name)
                try:
                    bench: BaseBenchmark = cls(self.config, client)
                    result = await asyncio.wait_for(bench.run(), timeout=120)
                    report.results.append(result)
                except Exception as e:
                    logger.error("[%s] error: %s", bid, e, exc_info=True)
                    report.results.append(BenchmarkResult(
                        bench_id=bid,
                        name=cls.bench_name,
                        category=cls.category,
                        score=0.0,
                        grade="F",
                        metrics={"error": str(e)},
                        description=cls.description,
                    ))
                if on_result is not None:
                    on_result(report.results[-1])
                if on_progress is not None:
                    on_progress(i + 1, total, bid)

        report.total_latency_ms = (time.perf_counter() - t0) * 1000
        report.to_dict()  # compute overall_grade as side effect
        return report
