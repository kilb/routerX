"""D130 ReverseConcurrencyProbe -- detect browser-based reverse proxies via concurrency.

Web reverse proxies (Selenium/Playwright wrappers around chat.openai.com etc.)
typically use a single browser session. They serialize requests: while one
chat is generating, subsequent requests either queue or fail. Legitimate APIs
handle 5+ concurrent requests without artificial serialization.

Sends 5 identical lightweight requests concurrently and analyzes:
  - success rate: reverse proxies often drop or error on concurrent requests
  - latency spread: serialized requests show staircase latency (1x, 2x, 3x...)
  - error patterns: queue-full, rate-limit with very low RPM
"""
from __future__ import annotations

import asyncio
import statistics
import time

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_CONCURRENCY = 5
_PROMPT = "Reply with exactly one word: hello"

# If the slowest request takes > STAIRCASE_RATIO x the fastest, it suggests
# serialization. Legitimate APIs may have 2-3x spread from load, but 5x+
# strongly indicates a serial bottleneck.
_STAIRCASE_RATIO = 5.0
# Minimum absolute latency for the slowest request to matter (avoid false
# positives on fast APIs where even 5x is only 500ms).
_MIN_SLOW_MS = 5000.0
# If more than this fraction of concurrent requests fail, it's suspicious.
_FAIL_FRACTION = 0.6


@detector
class D130_ReverseConcurrencyProbe(BaseDetector):
    detector_id = "D130"
    detector_name = "ReverseConcurrencyProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = _CONCURRENCY
    detector_timeout = 90.0
    description = (
        "Detect browser-based reverse proxies by testing concurrent request "
        "handling — serial bottleneck reveals single-session scraping."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": 5,
                    "temperature": 0,
                    "messages": [{"role": "user", "content": _PROMPT}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D130 concurrent probe {i+1}/{_CONCURRENCY}",
            )
            for i in range(_CONCURRENCY)
        ]
        # Time each request individually
        t0 = time.perf_counter()
        results = []

        async def timed_send(p: ProbeRequest) -> tuple[ProbeResponse, float]:
            start = time.perf_counter()
            resp = await self.client.send(p)
            elapsed = (time.perf_counter() - start) * 1000
            return resp, elapsed

        pairs = await asyncio.gather(*[timed_send(p) for p in probes])
        for resp, elapsed in pairs:
            resp.latency_ms = elapsed
            results.append(resp)
        return results

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        successes = [r for r in responses if not r.is_network_error and r.status_code == 200]
        failures = [r for r in responses if r.is_network_error or r.status_code != 200]
        latencies = [r.latency_ms for r in successes]

        ev = {
            "total": len(responses),
            "successes": len(successes),
            "failures": len(failures),
            "latencies_ms": [round(l, 0) for l in sorted(latencies)],
        }

        # All failed — can't determine
        if not successes:
            return self._pass({"note": "all concurrent requests failed — no evidence of issue"})

        # High failure rate under light concurrency
        fail_frac = len(failures) / len(responses)
        if fail_frac >= _FAIL_FRACTION:
            # Check error patterns: queue-full, single-session signals
            error_texts = []
            for r in failures:
                txt = (r.raw_text or r.error or "").lower()
                error_texts.append(txt[:200])
            ev["error_samples"] = error_texts

            queue_signals = [
                "queue", "busy", "concurrent", "one at a time",
                "try again", "too many", "capacity", "overloaded",
                "session", "already processing",
            ]
            has_queue_signal = any(
                sig in txt for txt in error_texts for sig in queue_signals
            )
            if has_queue_signal:
                return self._fail(
                    f"{len(failures)}/{len(responses)} concurrent requests failed "
                    f"with queue/capacity errors — likely single-session reverse proxy",
                    ev,
                )
            # Many failures but no queue signal — could be rate limit or other issue
            ev["note"] = "high failure rate but no queue signal"
            return self._pass(ev)

        # Staircase latency: serialized requests show progressively longer times
        if len(latencies) >= 3:
            latencies_sorted = sorted(latencies)
            fastest = latencies_sorted[0]
            slowest = latencies_sorted[-1]
            if fastest > 0:
                ratio = slowest / fastest
                ev["fastest_ms"] = round(fastest, 0)
                ev["slowest_ms"] = round(slowest, 0)
                ev["ratio"] = round(ratio, 2)

                if ratio >= _STAIRCASE_RATIO and slowest >= _MIN_SLOW_MS:
                    # Check for staircase pattern: latencies roughly N*base
                    median = statistics.median(latencies)
                    ev["median_ms"] = round(median, 0)
                    return self._fail(
                        f"staircase latency pattern: fastest {fastest:.0f}ms, "
                        f"slowest {slowest:.0f}ms (ratio {ratio:.1f}x) — "
                        f"requests appear serialized",
                        ev,
                    )

        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(latency: float, ok: bool = True) -> ProbeResponse:
            if not ok:
                return ProbeResponse(
                    status_code=429, latency_ms=latency,
                    raw_text='{"error":"queue full, try again"}',
                )
            return ProbeResponse(
                status_code=200, latency_ms=latency,
                body={"choices": [{"message": {"content": "hello"}}]},
            )

        return [
            ("PASS: all fast and concurrent",
             [mk(200), mk(250), mk(180), mk(300), mk(220)],
             "pass"),
            ("FAIL: staircase serialization",
             [mk(1000), mk(2100), mk(3200), mk(5500), mk(7000)],
             "fail"),
            ("FAIL: most requests fail with queue signal",
             [mk(200), mk(500, False), mk(500, False), mk(500, False), mk(500, False)],
             "fail"),
            ("PASS: all failed (no evidence)",
             [mk(0, False)] * 5,
             "pass"),
            ("PASS: some failures but no queue signal",
             [mk(200), mk(250), mk(300),
              ProbeResponse(status_code=500, latency_ms=100, raw_text="internal error"),
              ProbeResponse(status_code=500, latency_ms=100, raw_text="internal error")],
             "pass"),
        ]


if __name__ == "__main__":
    D130_ReverseConcurrencyProbe.self_test()
