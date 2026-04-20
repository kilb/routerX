"""Stage-orchestrated runner.

Runs detectors through five ordered stages (PRE_SCREEN, S0, P0, P1, P2).
S0 and P0 short-circuit subsequent stages on any FAIL. Ctrl-C marks the
run interrupted and emits SKIP results for everything after the signal.

``shared_context`` is a plain dict keyed by ``detector_id``; each entry
holds ``{"result": DetectorResult, "evidence": dict}``. Dependent detectors
(``depends_on``) always run sequentially after their prerequisites even
inside a parallel stage.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

from .client import RouterClient
from .events import Event, EventBus, EventType
from .models import (
    DetectorResult,
    Priority,
    TestConfig,
    TestReport,
    Verdict,
)
from .registry import BaseDetector, get_all_detectors

logger = logging.getLogger("router-auditor.runner")

STAGES: list[dict[str, Any]] = [
    {"name": "pre_screen", "priorities": [Priority.PRE_SCREEN],
     "abort_on_fail": False, "parallel": True},
    {"name": "s0", "priorities": [Priority.S0],
     "abort_on_fail": False, "parallel": True},
    {"name": "p0", "priorities": [Priority.P0],
     "abort_on_fail": False, "parallel": True},
    {"name": "p1", "priorities": [Priority.P1],
     "abort_on_fail": False, "parallel": True},
    {"name": "p2", "priorities": [Priority.P2],
     "abort_on_fail": False, "parallel": True},
]

# Maximum number of detectors to run concurrently within a stage.
# Each detector may itself issue multiple concurrent requests (bounded by
# RouterClient._semaphore), so this limits detector-level parallelism
# while the client limits request-level parallelism.
# Default 3 is conservative — some providers (e.g. OpenRouter) return
# 401 under concurrent load instead of standard 429.
DETECTOR_CONCURRENCY = 3

# Per-model pricing in USD per 1M tokens (prompt_rate, completion_rate).
# Rough 2025 list prices; ``_fuzzy_rate`` picks the longest-prefix match so
# e.g. ``gpt-4o-mini-2024-07-18`` still finds ``gpt-4o-mini``.
_MODEL_PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4": (30.0, 60.0),
    "gpt-3.5-turbo": (0.50, 1.50),
    "o1-mini": (3.0, 12.0),
    "o1": (15.0, 60.0),
    "o3-mini": (1.10, 4.40),
    "claude-3-5-haiku": (0.80, 4.0),
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-sonnet": (3.0, 15.0),
    "claude-3-haiku": (0.25, 1.25),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-1.5-pro": (1.25, 5.0),
    "gemini-2.0-flash": (0.10, 0.40),
}
_DEFAULT_RATE = (2.50, 10.0)  # fallback to gpt-4o-class pricing


def _fuzzy_rate(model: str) -> tuple[float, float]:
    m = model.lower()
    best = ""
    for key in _MODEL_PRICING_USD_PER_MTOK:
        if m.startswith(key) and len(key) > len(best):
            best = key
    return _MODEL_PRICING_USD_PER_MTOK.get(best, _DEFAULT_RATE)


# Detector IDs that belong to expanded "families".
# Original design split D22 into four sub-probes (D22a-d) + D22e. The
# implementation chose a composite: one ``D22`` detector runs the four
# sub-probes internally, and ``D22e`` is a separate detector. The family
# map reflects actually-registered detector_ids, not the design doc's
# hypothetical split, so contradiction rules can match at runtime.
_DETECTOR_FAMILIES: dict[str, tuple[str, ...]] = {
    "D22": ("D22", "D22e"),
    "D21": ("D21",),
    "D23": ("D23",),
}

# Contradiction rules: (PASS_id_or_family, FAIL_id_or_family, note_template).
# If either side is a family key, it expands to the family's members.
# The rule fires when any PASS-side member is PASS AND any FAIL-side is FAIL.
_CONTRADICTIONS: list[tuple[str, str, str]] = [
    ("D31", "D21", "D31 PASS but {fail} FAIL"),
    ("D31", "D22", "D31 PASS but {fail} FAIL"),
    ("D31", "D23", "D31 PASS but {fail} FAIL"),
    ("D24a", "D29", "D24a PASS but D29 FAIL: billing inflated"),
    ("D25", "D54", "D25 PASS but D54 FAIL: semantic truncation"),
]


def _expand(id_or_family: str) -> tuple[str, ...]:
    return _DETECTOR_FAMILIES.get(id_or_family, (id_or_family,))


class TestRunner:
    def __init__(
        self,
        config: TestConfig,
        only: list[str] | None = None,
        event_bus: EventBus | None = None,
    ):
        self.config = config
        self.only = only
        self.events = event_bus or EventBus()
        self.results: list[DetectorResult] = []
        self.shared_context: dict[str, Any] = {}
        self.on_progress: Any = None
        self._interrupted = False

    # ---------- orchestration ----------

    def _get_applicable_detectors(self) -> dict[str, type[BaseDetector]]:
        all_cls = get_all_detectors()
        if self.only:
            wanted = set(self.only)
            unknown = sorted(wanted - set(all_cls))
            if unknown:
                known = ", ".join(sorted(all_cls))
                logger.warning(
                    "--only contained unknown detector IDs: %s (known: %s)",
                    unknown, known,
                )
            all_cls = {k: v for k, v in all_cls.items() if k in wanted}
        return all_cls

    async def run_all(self) -> TestReport:
        self._install_signal_handler()
        try:
            return await self._run_all_inner()
        finally:
            self._uninstall_signal_handler()

    async def _run_all_inner(self) -> TestReport:
        # Reset mutable state so the same TestRunner instance can be reused
        # (e.g. API server running multiple test sessions).
        self.results = []
        self.shared_context = {}
        self._interrupted = False

        all_cls = self._get_applicable_detectors()
        self._total = len(all_cls)
        self._completed = 0
        aborted = False
        abort_reason = ""

        self.events.emit(Event(EventType.TEST_START, {
            "endpoint": self.config.router_endpoint, "detectors": self._total,
        }))

        async with RouterClient(
            endpoint=self.config.router_endpoint,
            api_key=self.config.api_key,
            auth_method=self.config.auth_method,
            extra_headers=self.config.extra_headers,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
            event_bus=self.events,
        ) as client:
            self._client = client  # exposed to _build_report for token totals
            for stage in STAGES:
                stage_cls = {
                    k: v for k, v in all_cls.items()
                    if v.priority in stage["priorities"]
                }
                if not stage_cls:
                    continue

                if self._interrupted or aborted:
                    reason = (
                        "user interrupted" if self._interrupted else abort_reason
                    )
                    for cls in stage_cls.values():
                        skip = self._make_skip(cls, reason)
                        self.results.append(skip)
                        self._completed += 1
                        self._report_progress(skip)
                    continue

                self.events.emit(Event(EventType.STAGE_START, {
                    "name": stage["name"], "count": len(stage_cls),
                }))

                dets = sorted(
                    [
                        cls(self.config, client, self.shared_context, self.events)
                        for cls in stage_cls.values()
                    ],
                    key=lambda d: d.detector_id,
                )

                logger.info("=== %s (%d) ===", stage["name"].upper(), len(dets))

                if stage["parallel"] and len(dets) > 1:
                    stage_results = await self._parallel(dets)
                else:
                    stage_results = await self._sequential(dets)

                self.results.extend(stage_results)

                self.events.emit(Event(EventType.STAGE_END, {
                    "name": stage["name"],
                    "results": [
                        {"id": r.detector_id, "verdict": r.verdict.value}
                        for r in stage_results
                    ],
                }))

                if stage["abort_on_fail"]:
                    fails = [
                        r for r in stage_results if r.verdict == Verdict.FAIL
                    ]
                    if fails:
                        aborted = True
                        abort_reason = (
                            f"{stage['name'].upper()}: {fails[0].detector_id}"
                        )
                        logger.warning("ABORT: %s", abort_reason)
                        self.events.emit(Event(EventType.ABORT, {
                            "reason": abort_reason,
                        }))

        report = self._build_report()
        if self._interrupted:
            report.tier_assignment = f"PARTIAL ({report.tier_assignment})"
        self.events.emit(Event(EventType.TEST_END, {
            "verdict": report.overall_verdict.value,
            "tier": report.tier_assignment,
        }))
        return report

    # ---------- stage runners ----------

    async def _sequential(
        self, dets: list[BaseDetector],
    ) -> list[DetectorResult]:
        out: list[DetectorResult] = []
        for d in dets:
            if self._interrupted:
                skip = self._make_skip(type(d), "user interrupted")
                out.append(skip)
                self._completed += 1
                self._report_progress(skip)
                continue
            r = await d.run()
            out.append(r)
            self._completed += 1
            self._report_progress(r)
            self._publish_to_shared(d.detector_id, r)
        return out

    async def _parallel(
        self, dets: list[BaseDetector],
    ) -> list[DetectorResult]:
        indep = [d for d in dets if not d.depends_on]
        dep = [d for d in dets if d.depends_on]
        out: list[DetectorResult] = []
        # Windowed parallel: run up to DETECTOR_CONCURRENCY detectors at once.
        # Each detector itself uses the RouterClient semaphore for request-level
        # concurrency, so this provides two levels of throttling.
        if indep:
            sem = asyncio.Semaphore(DETECTOR_CONCURRENCY)

            async def _run_one(d: BaseDetector) -> DetectorResult:
                async with sem:
                    return await d.run()

            task_to_det: dict[asyncio.Task, BaseDetector] = {}
            pending: set[asyncio.Task] = set()
            for d in indep:
                t = asyncio.create_task(_run_one(d))
                task_to_det[t] = d
                pending.add(t)
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED,
                )
                for t in done:
                    d = task_to_det[t]
                    try:
                        r = t.result()
                    except Exception as exc:
                        logger.error(
                            "[%s] uncaught exception: %s",
                            d.detector_id, exc, exc_info=True,
                        )
                        r = self._make_skip(type(d), f"error: {exc}")
                    out.append(r)
                    self._completed += 1
                    self._report_progress(r)
                    self._publish_to_shared(d.detector_id, r)
        for d in dep:
            try:
                r = await d.run()
            except Exception as exc:
                logger.error(
                    "[%s] uncaught exception in dep batch: %s",
                    d.detector_id, exc, exc_info=True,
                )
                r = self._make_skip(type(d), f"error: {exc}")
            out.append(r)
            self._completed += 1
            self._report_progress(r)
            self._publish_to_shared(d.detector_id, r)
        return out

    def _publish_to_shared(
        self, detector_id: str, result: DetectorResult,
    ) -> None:
        """Expose a result into shared_context. Both the result and its
        evidence are deep-copied so a downstream detector cannot mutate
        an earlier detector's payload (the canonical ``self.results`` and
        the final ``TestReport`` stay untouched regardless of consumer bugs).
        """
        from copy import deepcopy
        self.shared_context[detector_id] = {
            "result": result.model_copy(deep=True),
            "evidence": deepcopy(result.evidence),
        }

    # ---------- helpers ----------

    def _install_signal_handler(self) -> None:
        try:
            asyncio.get_running_loop().add_signal_handler(
                signal.SIGINT, self._handle_interrupt,
            )
            self._signal_installed = True
        except (NotImplementedError, RuntimeError):
            # Windows / non-main thread: Ctrl+C fallback via KeyboardInterrupt.
            self._signal_installed = False

    def _uninstall_signal_handler(self) -> None:
        if not getattr(self, "_signal_installed", False):
            return
        try:
            asyncio.get_running_loop().remove_signal_handler(signal.SIGINT)
        except (NotImplementedError, RuntimeError, ValueError):
            pass
        self._signal_installed = False

    def _handle_interrupt(self) -> None:
        logger.warning("Interrupted!")
        self._interrupted = True

    def _report_progress(self, last_result: DetectorResult) -> None:
        """Invoke ``on_progress`` with (completed, total, last_result).

        Legacy 2-arg signature ``fn(completed, total)`` is auto-detected once
        and cached. This avoids the fragile ``except TypeError`` pattern that
        can mask real bugs inside the callback.
        """
        if not self.on_progress:
            return
        if not hasattr(self, "_progress_arity"):
            import inspect
            try:
                sig = inspect.signature(self.on_progress)
                self._progress_arity = len(sig.parameters)
            except (ValueError, TypeError):
                self._progress_arity = 3
        if self._progress_arity >= 3:
            self.on_progress(self._completed, self._total, last_result)
        else:
            self.on_progress(self._completed, self._total)

    # ---------- report ----------

    def _build_report(self) -> TestReport:
        p = sum(1 for r in self.results if r.verdict == Verdict.PASS)
        f = sum(1 for r in self.results if r.verdict == Verdict.FAIL)
        s = sum(1 for r in self.results if r.verdict == Verdict.SUSPICIOUS)
        k = sum(1 for r in self.results if r.verdict == Verdict.SKIP)

        s0_fail = any(
            r.verdict == Verdict.FAIL and r.priority == Priority.S0
            for r in self.results
        )
        p0_fail = any(
            r.verdict == Verdict.FAIL and r.priority == Priority.P0
            for r in self.results
        )
        p1_fail = any(
            r.verdict == Verdict.FAIL and r.priority == Priority.P1
            for r in self.results
        )

        if s0_fail or p0_fail:
            overall, tier = Verdict.FAIL, "BLACKLIST"
        elif p1_fail:
            overall, tier = Verdict.PASS, "TIER_2"
        elif s > 0:
            overall, tier = Verdict.PASS, "TIER_1_WATCH"
        else:
            overall, tier = Verdict.PASS, "TIER_1"

        return TestReport(
            router_endpoint=self.config.router_endpoint,
            test_timestamp=datetime.now(timezone.utc).isoformat(),
            overall_verdict=overall,
            tier_assignment=tier,
            total_detectors=len(self.results),
            passed=p, failed=f, suspicious=s, skipped=k,
            total_requests=sum(
                r.request_count for r in self.results
                if r.verdict != Verdict.SKIP
            ),
            total_latency_ms=sum(r.latency_ms for r in self.results),
            estimated_cost_usd=self._compute_cost(),
            results=self.results,
            evidence_notes=self._detect_contradictions(),
        )

    def _compute_cost(self) -> float:
        """Price the actual token usage accumulated by the router client.

        Falls back to 0.0 if no client was attached (unit-test path) or no
        usage data was returned.
        """
        client = getattr(self, "_client", None)
        if client is None:
            return 0.0
        tokens = client.cumulative_tokens
        prompt_rate, completion_rate = _fuzzy_rate(self.config.claimed_model)
        prompt_cost = tokens["prompt"] / 1_000_000 * prompt_rate
        completion_cost = tokens["completion"] / 1_000_000 * completion_rate
        return round(prompt_cost + completion_cost, 4)

    def _detect_contradictions(self) -> list[str]:
        """Apply the CONTRADICTIONS rule table over actual results.

        Each rule names a PASS-side and FAIL-side detector (or family).
        The note fires once per (pass_id, fail_id) pair that matches, and
        a ``CONTRADICTION`` event is emitted for each.
        """
        rm = {r.detector_id: r for r in self.results}
        notes: list[str] = []
        for pass_key, fail_key, tmpl in _CONTRADICTIONS:
            for pass_id in _expand(pass_key):
                p = rm.get(pass_id)
                if not p or p.verdict != Verdict.PASS:
                    continue
                for fail_id in _expand(fail_key):
                    fr = rm.get(fail_id)
                    if fr and fr.verdict == Verdict.FAIL:
                        note = tmpl.format(pass_=pass_id, fail=fail_id)
                        notes.append(note)
                        self.events.emit(Event(EventType.CONTRADICTION, {
                            "pass_id": pass_id,
                            "fail_id": fail_id,
                            "note": note,
                        }))
        return notes

    @staticmethod
    def _make_skip(cls: type[BaseDetector], reason: str) -> DetectorResult:
        return DetectorResult(
            detector_id=cls.detector_id,
            detector_name=cls.detector_name,
            priority=cls.priority,
            verdict=Verdict.SKIP,
            confidence=0.0,
            skipped_reason=reason,
        )
