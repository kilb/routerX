"""Detector registry, base class, and self-test harness.

``@detector`` registers a subclass by ``detector_id`` into the module-level
``_REGISTRY``. ``BaseDetector`` implements the uniform ``run()`` lifecycle:

    should_skip -> send_probes -> judge -> Result

For detectors declared ``JudgeMode.MAJORITY_2_OF_2``, ``_execute()`` runs
the probe/judge cycle twice and returns FAIL only when both pass fail.
``self_test`` runs the class-level ``_test_cases`` against ``judge()`` with
a mocked config/client, useful for fast offline regression checks.
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from .client import RouterClient
from .events import Event, EventBus, EventType
from .models import (
    Capability,
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeResponse,
    ProviderType,
    TestConfig,
    Verdict,
)

logger = logging.getLogger("router-auditor.detector")

_REGISTRY: dict[str, type["BaseDetector"]] = {}


def detector(cls: type["BaseDetector"]) -> type["BaseDetector"]:
    """Class decorator: registers ``cls`` under ``cls.detector_id``.

    Raises ``ValueError`` if a *different* class is already registered with
    the same id (copy-paste bug). Re-registration of the *same* class is
    allowed — this happens when ``python -m src.detectors.dXX`` triggers
    both the ``__init__.py`` auto-scan and the ``__main__`` execution.
    """
    existing = _REGISTRY.get(cls.detector_id)
    if existing is not None and existing is not cls:
        # Same class loaded from two module paths (__main__ vs package)?
        # Allow if class names match; reject if they differ (true duplicate).
        if existing.__name__ != cls.__name__:
            raise ValueError(
                f"duplicate detector_id {cls.detector_id!r}: "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )
    _REGISTRY[cls.detector_id] = cls
    return cls


def get_all_detectors() -> dict[str, type["BaseDetector"]]:
    return dict(_REGISTRY)


class BaseDetector(ABC):
    # Required class variables
    detector_id: ClassVar[str]
    detector_name: ClassVar[str]
    priority: ClassVar[Priority]
    judge_mode: ClassVar[JudgeMode]
    # Optional class variables. Sequences default to tuples so subclass
    # authors cannot accidentally ``append`` onto the base-class list.
    request_count: ClassVar[int] = 1
    detector_timeout: ClassVar[float] = 30.0
    required_capabilities: ClassVar[tuple[Capability, ...]] = (Capability.TEXT,)
    required_provider: ClassVar[ProviderType] = ProviderType.ANY
    requires_direct: ClassVar[bool] = False
    requires_single_route_claim: ClassVar[bool] = False
    depends_on: ClassVar[tuple[str, ...]] = ()
    description: ClassVar[str] = ""

    def __init__(
        self,
        config: TestConfig,
        client: RouterClient,
        shared_context: dict[str, Any] | None = None,
        event_bus: EventBus | None = None,
    ):
        self.config = config
        self.client = client
        self.shared = shared_context if shared_context is not None else {}
        self.events = event_bus or EventBus()

    # ---------- public helpers ----------

    @property
    def has_direct(self) -> bool:
        return bool(self.config.direct_endpoint and self.config.direct_api_key)

    def make_direct_client(self) -> RouterClient:
        """Build a client targeting the direct-provider endpoint.

        The returned client is NOT yet entered -- callers MUST use it as
        an async context manager, otherwise ``send()`` will raise
        ``AttributeError`` on the still-None ``_client``::

            async with self.make_direct_client() as dc:
                resp = await dc.send(probe)
        """
        return RouterClient(
            endpoint=self.config.direct_endpoint,
            api_key=self.config.direct_api_key,
            auth_method=self.config.direct_auth_method or self.config.auth_method,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
        )

    def should_skip(self) -> str | None:
        for cap in self.required_capabilities:
            if cap not in self.config.capabilities:
                return f"requires {cap.value}"
        if (self.required_provider != ProviderType.ANY
                and self.config.claimed_provider != self.required_provider):
            return f"requires {self.required_provider.value}"
        if self.requires_single_route_claim and not self.config.claimed_single_route:
            return "requires single provider claim"
        if self.requires_direct and not self.has_direct:
            return "requires direct-provider baseline"
        return None

    # ---------- abstract ----------

    @abstractmethod
    async def send_probes(self) -> list[ProbeResponse]: ...

    @abstractmethod
    def judge(self, responses: list[ProbeResponse]) -> DetectorResult: ...

    # ---------- lifecycle ----------

    @property
    def _effective_timeout(self) -> float:
        """MAJORITY_2_OF_2 runs send_probes twice, so give it 2x the budget.

        This prevents authors from having to manually double every MAJORITY
        detector's ``detector_timeout``.
        """
        if self.judge_mode == JudgeMode.MAJORITY_2_OF_2:
            return self.detector_timeout * 2
        return self.detector_timeout

    async def run(self) -> DetectorResult:
        skip = self.should_skip()
        if skip:
            logger.info("[%s] SKIP: %s", self.detector_id, skip)
            return self._skip(skip)

        self.events.emit(Event(EventType.DETECTOR_START, {
            "id": self.detector_id, "name": self.detector_name,
        }))
        logger.info("[%s] starting %s...", self.detector_id, self.detector_name)
        t0 = time.perf_counter()

        budget = self._effective_timeout
        try:
            result = await asyncio.wait_for(
                self._execute(), timeout=budget,
            )
        except asyncio.TimeoutError:
            logger.error("[%s] timed out (%ss)", self.detector_id, budget)
            result = self._inconclusive(f"timed out after {budget}s")
        except Exception as e:
            logger.error("[%s] error: %s", self.detector_id, e, exc_info=True)
            result = self._inconclusive(f"error: {e}")

        result.latency_ms = (time.perf_counter() - t0) * 1000
        # MAJORITY_2_OF_2 actually sends send_probes() twice.
        multiplier = 2 if self.judge_mode == JudgeMode.MAJORITY_2_OF_2 else 1
        result.request_count = self.request_count * multiplier
        logger.info(
            "[%s] %s (%.0fms)", self.detector_id, result.verdict.value, result.latency_ms,
        )
        self.events.emit(Event(EventType.DETECTOR_END, {
            "id": self.detector_id,
            "verdict": result.verdict.value,
            "latency_ms": result.latency_ms,
        }))
        return result

    @staticmethod
    def _all_network_errors(responses: list) -> bool:
        """True if the list is non-empty AND every non-None response is a
        network error. Detectors like D22 intentionally place ``None`` for
        sub-probes that don't apply to the current provider; those are not
        "network errors" and shouldn't count either way.
        """
        actual = [r for r in responses if r is not None]
        if not actual:
            return False
        return all(r.is_network_error for r in actual)

    @staticmethod
    def _all_http_errors(responses: list) -> bool:
        """True if every non-None response is a network error OR HTTP 4xx/5xx."""
        actual = [r for r in responses if r is not None]
        if not actual:
            return False
        return all(r.is_network_error or r.status_code >= 400 for r in actual)

    async def _execute(self) -> DetectorResult:
        if self.judge_mode == JudgeMode.MAJORITY_2_OF_2:
            return await self._run_majority()
        responses = await self.send_probes()
        if self._all_network_errors(responses):
            first = next(r for r in responses if r is not None)
            non_text_caps = [
                c for c in self.required_capabilities if c != Capability.TEXT
            ]
            if non_text_caps:
                return self._skip(
                    f"endpoint does not support {non_text_caps[0].value} "
                    f"(all requests failed)"
                )
            return self._inconclusive(f"all probes failed: {first.error}")
        # All responses are HTTP errors (400/500 etc.) — the endpoint
        # rejected all our requests. This is not a detector finding,
        # it's an endpoint compatibility issue.
        if self._all_http_errors(responses):
            first = next(r for r in responses if r is not None)
            return self._inconclusive(
                f"all probes returned errors: {first.error_detail}"
            )
        return self.judge(responses)

    async def _run_majority(self) -> DetectorResult:
        results: list[DetectorResult] = []
        net_failures = 0
        for _ in range(2):
            responses = await self.send_probes()
            if self._all_network_errors(responses) or self._all_http_errors(responses):
                net_failures += 1
                continue
            results.append(self.judge(responses))
        # If every attempt died on the network, check whether the detector
        # requires a non-TEXT capability (audio/vision/pdf). If so, the
        # endpoint likely doesn't support that modality → SKIP rather than
        # INCONCLUSIVE.
        if not results:
            non_text_caps = [
                c for c in self.required_capabilities if c != Capability.TEXT
            ]
            if non_text_caps:
                return self._skip(
                    f"endpoint does not support {non_text_caps[0].value} "
                    f"(all requests failed)"
                )
            return self._inconclusive("all majority attempts failed at network")
        if len(results) == 1 and net_failures == 1:
            # Only one valid run: treat as inconclusive (we can't form a
            # 2/2 majority from a single sample).
            return self._inconclusive(
                "only one valid majority attempt; cannot form 2/2 verdict"
            )
        fails = sum(1 for r in results if r.verdict == Verdict.FAIL)
        if fails == 2:
            # Copy so callers that retain results[0] (e.g. shared_context)
            # never see the post-merge mutations.
            merged = results[0].model_copy(deep=True)
            merged.confidence = 0.95
            merged.evidence["majority"] = "2/2 FAIL"
            return merged
        if fails == 1:
            return DetectorResult(
                detector_id=self.detector_id,
                detector_name=self.detector_name,
                priority=self.priority,
                verdict=Verdict.SUSPICIOUS,
                confidence=0.5,
                evidence={
                    "majority": "1/2 FAIL",
                    "run_1": results[0].evidence,
                    "run_2": results[1].evidence,
                },
            )
        return results[0]

    # ---------- result builders ----------

    def _pass(self, evidence: dict[str, Any] | None = None) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.PASS, confidence=1.0,
            evidence=evidence or {},
        )

    def _fail(
        self,
        reason: str,
        evidence: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.FAIL, confidence=confidence,
            evidence={"reason": reason, **(evidence or {})},
        )

    def _fail_degraded(
        self, reason: str, evidence: dict[str, Any] | None = None,
    ) -> DetectorResult:
        return self._fail(reason, evidence, confidence=0.70)

    def _inconclusive(self, reason: str) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.INCONCLUSIVE, confidence=0.0,
            evidence={"reason": reason},
        )

    def _skip(self, reason: str) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.SKIP, confidence=0.0,
            skipped_reason=reason,
        )

    # ---------- self test ----------

    @classmethod
    def self_test(cls) -> None:
        cases = cls._test_cases()
        if not cases:
            print(f"[WARN] {cls.detector_id}: no test cases")
            return
        from unittest.mock import MagicMock

        passed = 0
        for name, mock_resps, expected in cases:
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.shared = {}
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(
                    f"  [FAIL] {name}: expected {expected}, "
                    f"got {r.verdict.value}"
                )
        mark = "OK" if passed == len(cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(cases)}")

    @classmethod
    def _test_cases(cls):
        return []
