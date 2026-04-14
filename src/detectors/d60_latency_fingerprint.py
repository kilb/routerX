"""D60 LatencyFingerprint -- detect model substitution via TTFT + tokens/sec.

Frontier-model endpoints have characteristic latency signatures. A router
serving a bare OSS model on shared hardware will fall outside the band.
Uses a widened 3x tolerance band to avoid false positives from transient
network conditions. MAJORITY_2_OF_2 further guards against one-off jitter.

Limitations:
- Shared CDNs and regional variation can push legitimate providers near
  band edges; the widened tolerance absorbs most of this.
- First chunk timestamp may include SSE keep-alive bytes (~few ms) -- we
  accept this small imprecision.
- Integration-test coverage via mock_server would require an ~8s sleep,
  which is close to TestConfig.timeout=10.0s and flaky; the self-test
  covers PASS/FAIL/INCONCLUSIVE deterministically instead.
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
from ..tokenizer import token_counter
from ..utils.latency_bands import lookup_band

_TOLERANCE = 3.0  # allow 3x the published band before flagging
_MIN_EDGE_DELTA = 0.5  # require 50% exceedance to avoid edge jitter FAIL


@detector
class D60_LatencyFingerprint(BaseDetector):
    detector_id = "D60"
    detector_name = "LatencyFingerprint"
    priority = Priority.P2
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 1
    detector_timeout = 60.0
    description = (
        "Detect model substitution via streaming TTFT and tokens/sec "
        "compared against family-level latency bands."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 250,
                "temperature": 0.3,
                "messages": [{
                    "role": "user",
                    "content": (
                        "Write a 200-word overview of the history of "
                        "distributed systems. Plain prose, no headers."
                    ),
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D60 latency probe",
        )
        return [await self.client.send_stream(probe)]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        band = lookup_band(self.config.claimed_model)
        if band is None:
            return self._inconclusive(
                f"no latency band for model {self.config.claimed_model!r}"
            )
        min_ttft, max_ttft, min_tps, max_tps = band
        timestamps = r.chunk_timestamps or []
        content = r.content or ""
        if len(timestamps) < 2:
            return self._inconclusive(
                f"not enough stream chunks ({len(timestamps)})"
            )

        ttft = timestamps[0]
        duration = max(timestamps[-1] - timestamps[0], 1e-6)
        local_tokens = token_counter.count(
            content, model=self.config.claimed_model,
        )
        tps = local_tokens / duration if duration > 0 else 0.0

        widened = {
            "ttft": (min_ttft / _TOLERANCE, max_ttft * _TOLERANCE),
            "tps": (min_tps / _TOLERANCE, max_tps * _TOLERANCE),
        }
        ttft_ok = widened["ttft"][0] <= ttft <= widened["ttft"][1]
        tps_ok = widened["tps"][0] <= tps <= widened["tps"][1]

        evidence = {
            "ttft_s": ttft,
            "tokens_per_sec": tps,
            "local_tokens": local_tokens,
            "duration_s": duration,
            "band": band,
            "widened_band": widened,
        }

        if ttft_ok and tps_ok:
            return self._pass(evidence)

        # Check whether the exceedance is significant enough to rule out
        # near-edge jitter. Delta is measured as fractional distance past
        # the nearest widened boundary.
        def _edge_delta(value: float, lo: float, hi: float) -> float:
            if value < lo:
                return (lo - value) / max(lo, 1e-6)
            if value > hi:
                return (value - hi) / max(hi, 1e-6)
            return 0.0

        ttft_delta = _edge_delta(ttft, *widened["ttft"])
        tps_delta = _edge_delta(tps, *widened["tps"])
        max_delta = max(ttft_delta, tps_delta)
        if max_delta < _MIN_EDGE_DELTA:
            return self._inconclusive(
                f"latency near band edge (max delta {max_delta:.2f})"
            )
        return self._fail(
            f"latency outside widened band: ttft={ttft:.2f}s "
            f"(band [{min_ttft}, {max_ttft}]), "
            f"tps={tps:.1f} (band [{min_tps}, {max_tps}])",
            evidence,
        )

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

        good = mk(
            [0.3, 0.4, 0.5, 0.6, 0.7, 1.0],
            "The history of distributed systems " * 40,
        )
        slow = mk([15.0, 15.1, 15.2], "short")
        net = ProbeResponse(status_code=0, error="TIMEOUT")
        too_few = mk([0.3], "")
        return [
            ("PASS: latency inside band", [good], "pass"),
            ("FAIL: TTFT way above band", [slow], "fail"),
            ("INCONCLUSIVE: network error", [net], "inconclusive"),
            ("INCONCLUSIVE: too few chunks", [too_few], "inconclusive"),
        ]


if __name__ == "__main__":
    D60_LatencyFingerprint.self_test()
