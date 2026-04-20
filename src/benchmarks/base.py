"""Base class and registry for performance benchmarks."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from ..client import RouterClient
from ..models import TestConfig

logger = logging.getLogger("router-auditor.benchmark")

_BENCH_REGISTRY: dict[str, type[BaseBenchmark]] = {}


def benchmark(cls: type[BaseBenchmark]) -> type[BaseBenchmark]:
    """Class decorator: registers *cls* under ``cls.bench_id``.

    Re-registration of the same class (same ``__name__``) is tolerated so
    that ``python -m`` and auto-import can coexist.  A genuine duplicate
    (different class, same id) raises ``ValueError``.
    """
    existing = _BENCH_REGISTRY.get(cls.bench_id)
    if existing is not None and existing is not cls:
        if existing.__name__ != cls.__name__:
            raise ValueError(
                f"duplicate bench_id {cls.bench_id!r}: "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )
    _BENCH_REGISTRY[cls.bench_id] = cls
    return cls


def get_all_benchmarks() -> dict[str, type[BaseBenchmark]]:
    """Return a snapshot of all registered benchmarks."""
    return dict(_BENCH_REGISTRY)


class BenchmarkResult:
    """Result of a single benchmark run."""

    def __init__(
        self,
        bench_id: str,
        name: str,
        category: str,
        score: float,
        grade: str,
        metrics: dict[str, Any],
        description: str = "",
    ) -> None:
        self.bench_id = bench_id
        self.name = name
        self.category = category
        self.score = score
        self.grade = grade
        self.metrics = metrics
        self.description = description

    def to_dict(self) -> dict[str, Any]:
        return {
            "bench_id": self.bench_id,
            "name": self.name,
            "category": self.category,
            "score": self.score,
            "grade": self.grade,
            "metrics": self.metrics,
            "description": self.description,
        }


def grade_value(
    value: float,
    thresholds: dict[str, float],
    lower_is_better: bool = True,
) -> str:
    """Grade a metric value against ordered thresholds.

    *thresholds* maps grade letters to boundary values, e.g.
    ``{"A": 0.5, "B": 1.0, "C": 2.0, "D": 4.0}``.

    When *lower_is_better* is ``True`` the value must be ``<=`` the
    threshold to earn that grade; when ``False`` it must be ``>=``.
    Grades are evaluated in order A -> B -> C -> D; if none match,
    ``"F"`` is returned.
    """
    for g in ("A", "B", "C", "D"):
        if g not in thresholds:
            continue
        if lower_is_better and value <= thresholds[g]:
            return g
        if not lower_is_better and value >= thresholds[g]:
            return g
    return "F"


class BaseBenchmark(ABC):
    """Abstract base for all benchmarks."""

    bench_id: ClassVar[str]
    bench_name: ClassVar[str]
    category: ClassVar[str]  # "performance" or "reliability"
    description: ClassVar[str] = ""

    def __init__(self, config: TestConfig, client: RouterClient) -> None:
        self.config = config
        self.client = client

    @abstractmethod
    async def run(self) -> BenchmarkResult:
        """Execute the benchmark and return a graded result."""
        ...
