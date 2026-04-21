"""D64 StreamingChunkShape -- detect re-streamed non-streaming upstream.

A router claiming stream=true must actually stream token-by-token. Two common
fraud modes:
  - very few large chunks (whole response in 2-3 SSE events)
  - all chunks arrive within a millisecond (burst replay of a cached result)

Complements D32a which only catches the degenerate 2-chunk case.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter


_MIN_CHUNKS_PER_100_TOKENS = 10
_NEAR_ZERO_DELTA_S = 0.001


@detector
class D64_StreamingChunkShape(BaseDetector):
    detector_id = "D64"
    detector_name = "StreamingChunkShape"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = "Detect non-streaming upstream re-wrapped as SSE (chunk shape fraud)."

    async def send_probes(self) -> list[ProbeResponse]:
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 150,
                "temperature": 0.2,
                "messages": [{"role": "user", "content":
                              "Write about 100 words on the history of the "
                              "internet. Plain prose."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D64 chunk-shape probe",
        )
        return [await self.client.send_stream(probe)]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")
        timestamps = r.chunk_timestamps or []
        content = r.content or ""
        tokens = token_counter.count(content, model=self.config.claimed_model)

        if tokens < 20:
            return self._inconclusive(
                f"only {tokens} tokens of output -- too short to judge shape"
            )
        if len(timestamps) < 2:
            return self._fail("fewer than 2 stream chunks",
                              {"timestamps": timestamps, "tokens": tokens})

        chunks_per_100 = len(timestamps) * 100 / max(tokens, 1)
        deltas = [timestamps[i+1] - timestamps[i]
                  for i in range(len(timestamps) - 1)]
        near_zero = sum(1 for d in deltas if d < _NEAR_ZERO_DELTA_S)
        near_zero_frac = near_zero / len(deltas) if deltas else 0.0

        ev = {"chunk_count": len(timestamps), "tokens": tokens,
              "chunks_per_100_tokens": chunks_per_100,
              "near_zero_delta_frac": near_zero_frac}

        if chunks_per_100 < _MIN_CHUNKS_PER_100_TOKENS:
            return self._fail(
                f"only {chunks_per_100:.1f} chunks per 100 tokens "
                f"(< {_MIN_CHUNKS_PER_100_TOKENS}) -- likely re-streamed", ev,
            )
        # Burst-delta check: only meaningful when chunk density is LOW (< 50
        # per 100 tokens). High chunk density with near-zero deltas is normal
        # for proxies that buffer and batch-forward genuine token-level chunks
        # — the chunks are real, just delivered in bursts over TCP.
        if (near_zero_frac > 0.95 and len(timestamps) >= 10
                and chunks_per_100 < 50):
            return self._fail(
                f"{near_zero_frac:.0%} of chunks arrive with < 1ms gap "
                "-- burst replay of cached result", ev,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(ts: list[float], content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"full_content": content, "chunk_count": len(ts)},
                chunks=[{"delta": {"content": ""}}] * len(ts),
                chunk_timestamps=ts,
                raw_text=content,
            )
        long_content = "The internet began as ARPANET " * 20
        # Genuine: ~50 chunks for ~100 tokens, staggered.
        genuine = mk([i * 0.02 for i in range(50)], long_content)
        # Chunky: 3 chunks for 100 tokens.
        chunky = mk([0.1, 0.5, 1.0], long_content)
        # Burst: 20 chunks all within 1ms.
        burst_ts = [0.5 + i * 0.0001 for i in range(20)]
        burst = mk(burst_ts, long_content)
        short = mk([0.1, 0.2], "hi")
        net = ProbeResponse(status_code=0, error="TIMEOUT")
        return [
            ("PASS: genuine streaming shape", [genuine], "pass"),
            ("FAIL: very few chunks", [chunky], "fail"),
            ("FAIL: burst replay (all zero-delta)", [burst], "fail"),
            ("INCONCLUSIVE: too short output", [short], "inconclusive"),
            ("INCONCLUSIVE: network error", [net], "inconclusive"),
        ]


if __name__ == "__main__":
    D64_StreamingChunkShape.self_test()
