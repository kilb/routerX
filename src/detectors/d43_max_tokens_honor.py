"""D43 MaxTokensHonor -- verify max_tokens is honored, not silently capped.

Ask for a response that needs ~1800 tokens with max_tokens=2000. A compliant
provider completes fully (finish_reason=stop). A clamping router truncates
(finish_reason=length) at a much lower cap -- evidence the router is
substituting a cheaper tier or enforcing its own cap.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
    Verdict,
)
from ..registry import BaseDetector, detector
from ..tokenizer import token_counter

USER_MAX_TOKENS = 2000
MIN_ACCEPTABLE_COMPLETION = 1600  # if truncated below this, router clamped
# If model claims "stop" but produced very few tokens despite user requesting
# max_tokens=2000, the router may have artificially ended the generation.
SUSPICIOUS_STOP_THRESHOLD = 500


@detector
class D43_MaxTokensHonor(BaseDetector):
    detector_id = "D43"
    detector_name = "MaxTokensHonor"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = "Detect silent max_tokens clamping."

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = (
            "Write a detailed technical essay on distributed consensus "
            "algorithms (Paxos, Raft, PBFT). Cover history, tradeoffs, "
            "real-world usage, and failure modes. Aim for approximately "
            "1800 tokens of content. Do not stop early."
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": USER_MAX_TOKENS,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D43 max_tokens honor probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content or ""
        finish = (r.finish_reason or "").lower()
        local_tokens = token_counter.count(content, model=self.config.claimed_model)
        ev = {
            "completion_tokens_local": local_tokens,
            "finish_reason": finish,
            "content_len": len(content),
        }

        # Model finished naturally -> check for suspicious early stop.
        if finish in ("stop", "end_turn", "end"):
            if local_tokens >= MIN_ACCEPTABLE_COMPLETION:
                return self._pass(ev)
            if local_tokens < SUSPICIOUS_STOP_THRESHOLD:
                return DetectorResult(
                    detector_id=self.detector_id,
                    detector_name=self.detector_name,
                    priority=self.priority,
                    verdict=Verdict.SUSPICIOUS,
                    confidence=0.5,
                    evidence={
                        "reason": (
                            f"finish_reason=stop but only {local_tokens} tokens "
                            f"(< {SUSPICIOUS_STOP_THRESHOLD}) with "
                            f"max_tokens={USER_MAX_TOKENS} -- router may have "
                            f"artificially ended generation"
                        ),
                        **ev,
                    },
                )
            return self._pass(ev | {"note": "finished naturally below target"})

        # Truncated but close to user cap -> honored.
        if finish in ("length", "max_tokens"):
            if local_tokens >= MIN_ACCEPTABLE_COMPLETION:
                return self._pass(ev | {"note": "truncated near user cap"})
            return self._fail(
                f"finish_reason={finish} but only {local_tokens} tokens "
                f"(< {MIN_ACCEPTABLE_COMPLETION}) -- router clamped max_tokens",
                ev,
            )
        return self._inconclusive(f"unexpected finish_reason: {finish!r}")

    @classmethod
    def _test_cases(cls):
        def mk(content: str, finish: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{
                    "message": {"content": content},
                    "finish_reason": finish,
                }]},
            )

        long_stop = mk("word " * 1800, "stop")
        long_length = mk("word " * 1800, "length")
        short_length = mk("word " * 200, "length")
        # Very short stop -- suspicious artificial early stop
        very_short_stop = mk("word " * 50, "stop")
        return [
            ("PASS: natural stop with good length", [long_stop], "pass"),
            ("PASS: truncated near cap", [long_length], "pass"),
            ("FAIL: clamped below 1600", [short_length], "fail"),
            ("SUSPICIOUS: stop with very few tokens",
             [very_short_stop], "suspicious"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D43_MaxTokensHonor.self_test()
