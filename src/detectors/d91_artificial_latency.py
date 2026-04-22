"""D91 ArtificialLatencyPadding -- detect routers that pad TTFT regardless of output length.

A legitimate model returns max_tokens=1 nearly instantly (very low TTFT).
A dishonest router may add artificial delay to make cheap models *feel*
like frontier models, resulting in a paradoxically high TTFT even for
trivially short outputs.

Sends two streaming requests: one with max_tokens=1 (should be fast) and
one with max_tokens=200 (legitimately slower). If the short request is
both 1.5x slower AND above 2 seconds absolute, the delay is artificial.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

# Thresholds must be generous: TTFT varies widely due to network
# conditions, server load, cold starts, and queueing. Only flag
# extreme cases where the short request is clearly padded.
TTFT_RATIO_THRESHOLD = 2.0    # was 1.5 — too tight for proxy scenarios
TTFT_ABS_THRESHOLD_MS = 3000.0  # was 2000 — many APIs have 2s+ baseline


@detector
class D91_ArtificialLatencyPadding(BaseDetector):
    detector_id = "D91"
    detector_name = "ArtificialLatencyPadding"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 2
    detector_timeout = 60.0
    description = "Detect artificial TTFT padding regardless of output length"

    async def send_probes(self) -> list[ProbeResponse]:
        short_probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 1,
                "temperature": 0,
                "messages": [{"role": "user", "content": "Say hi"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D91 short probe (max_tokens=1)",
        )
        long_probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 200,
                "temperature": 0.3,
                "messages": [{
                    "role": "user",
                    "content": "Write a paragraph about clouds",
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D91 long probe (max_tokens=200)",
        )
        # Send sequentially -- we are measuring timing
        short_resp = await self.client.send_stream(short_probe)
        long_resp = await self.client.send_stream(long_probe)
        return [short_resp, long_resp]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        short, long = responses[0], responses[1]
        if short.is_network_error:
            return self._inconclusive(short.error or "short probe network error")
        if long.is_network_error:
            return self._inconclusive(long.error or "long probe network error")

        short_ts = short.chunk_timestamps
        long_ts = long.chunk_timestamps
        if not short_ts:
            return self._inconclusive("no chunk timestamps for short probe")
        if not long_ts:
            return self._inconclusive("no chunk timestamps for long probe")

        ttft_short = short_ts[0] * 1000  # seconds -> ms
        ttft_long = long_ts[0] * 1000

        evidence = {
            "ttft_short_ms": ttft_short,
            "ttft_long_ms": ttft_long,
            "ratio": ttft_short / max(ttft_long, 1e-6),
        }

        if ttft_long <= 0:
            return self._inconclusive("long probe TTFT is zero")

        if ttft_short > ttft_long * TTFT_RATIO_THRESHOLD and ttft_short > TTFT_ABS_THRESHOLD_MS:
            return self._fail(
                f"short request TTFT ({ttft_short:.0f}ms) > 1.5x long request "
                f"TTFT ({ttft_long:.0f}ms) and > 2000ms -- artificial padding",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def mk(ts: list[float], content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"full_content": content, "chunk_count": len(ts)},
                chunks=[{"delta": {"content": content}}] * len(ts),
                chunk_timestamps=ts,
                raw_text=content,
            )

        return [
            ("PASS: short fast, long slower",
             [mk([0.1, 0.15], "hi"), mk([0.3, 0.5, 0.8], "clouds are fluffy")],
             "pass"),
            ("FAIL: both slow equally (short artificially padded)",
             [mk([3.5, 3.6], "hi"), mk([1.0, 1.5, 2.0], "clouds are fluffy")],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              mk([0.3, 0.5], "clouds")],
             "inconclusive"),
            ("INCONCLUSIVE: no timestamps",
             [mk([], ""), mk([0.3], "clouds")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D91_ArtificialLatencyPadding.self_test()
