"""D85 IntraFamilyDowngrade -- detect same-family model routing on easy queries.

Cross-family swaps (GPT-4o -> Claude) are caught by D4a/D41, but intra-family
downgrades (Opus -> Haiku, 4o -> 4o-mini) evade those. Per-token latency is
hardware-bound for a given model; if easy queries get dramatically faster
per-token latency, a cheaper sibling is likely serving them.
MAJORITY_2_OF_2 guards against one-off network jitter.
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

# If easy per-token latency is below this fraction of hard per-token latency,
# flag as different models.  0.3 => easy must be at least 3.3x faster per
# token to trigger.
_TPT_RATIO_THRESHOLD = 0.3

# Hard probe must produce at least this many tokens for the comparison to be
# meaningful; otherwise the per-token estimate is too noisy.
_MIN_HARD_TOKENS = 30

_EASY_PROMPT = "Reply with just the word 'hello'."
_HARD_PROMPT = (
    "A farmer has 17 sheep. All but 9 die. He buys 5 more, then sells "
    "half of what he has. How many sheep remain? Show your reasoning "
    "step by step."
)


@detector
class D85_IntraFamilyDowngrade(BaseDetector):
    detector_id = "D85"
    detector_name = "IntraFamilyDowngrade"
    priority = Priority.P2
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    detector_timeout = 60.0
    description = (
        "Detect routers that route easy queries to cheaper intra-family "
        "models by comparing per-token latency across probe difficulties."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        easy = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 10,
                "temperature": 0,
                "messages": [{"role": "user", "content": _EASY_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D85 easy probe (trivial query)",
        )
        hard = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 300,
                "temperature": 0,
                "messages": [{"role": "user", "content": _HARD_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D85 hard probe (multi-step reasoning)",
        )
        r_easy = await self.client.send(easy)
        r_hard = await self.client.send(hard)
        return [r_easy, r_hard]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_easy, r_hard = responses[0], responses[1]

        if r_easy.is_network_error:
            return self._inconclusive(r_easy.error or "easy probe network error")
        if r_hard.is_network_error:
            return self._inconclusive(r_hard.error or "hard probe network error")

        content_easy = r_easy.content or ""
        content_hard = r_hard.content or ""

        if not content_easy or not content_hard:
            return self._inconclusive("empty content in one or both probes")

        model = self.config.claimed_model
        tokens_easy = max(token_counter.count(content_easy, model=model), 1)
        tokens_hard = token_counter.count(content_hard, model=model)

        if tokens_hard < _MIN_HARD_TOKENS:
            return self._inconclusive(
                f"hard probe too short ({tokens_hard} tokens, "
                f"need >= {_MIN_HARD_TOKENS})"
            )

        tpt_easy = r_easy.latency_ms / tokens_easy
        tpt_hard = r_hard.latency_ms / max(tokens_hard, 1)

        evidence = {
            "easy_latency_ms": r_easy.latency_ms,
            "hard_latency_ms": r_hard.latency_ms,
            "easy_tokens": tokens_easy,
            "hard_tokens": tokens_hard,
            "easy_ms_per_token": round(tpt_easy, 2),
            "hard_ms_per_token": round(tpt_hard, 2),
            "ratio": round(tpt_easy / max(tpt_hard, 1e-6), 4),
            "threshold": _TPT_RATIO_THRESHOLD,
        }

        if tpt_easy < tpt_hard * _TPT_RATIO_THRESHOLD:
            return self._fail(
                f"easy per-token latency ({tpt_easy:.1f}ms) is "
                f"{tpt_hard / max(tpt_easy, 1e-6):.1f}x faster than hard "
                f"({tpt_hard:.1f}ms) -- suggests cheaper intra-family model "
                f"for trivial queries",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _ok(content: str) -> dict:
            return {"choices": [{"message": {"content": content}}]}

        short_answer = "hello"
        # ~60 tokens of reasoning
        long_answer = (
            "Step 1: The farmer starts with 17 sheep. "
            "Step 2: All but 9 die, so 9 sheep remain. "
            "Step 3: He buys 5 more, giving him 14 sheep. "
            "Step 4: He sells half of 14, which is 7. "
            "Therefore, 7 sheep remain after all transactions."
        )

        easy = lambda ms: ProbeResponse(  # noqa: E731
            status_code=200, body=_ok(short_answer), latency_ms=ms,
        )
        hard = lambda ms: ProbeResponse(  # noqa: E731
            status_code=200, body=_ok(long_answer), latency_ms=ms,
        )
        net_err = lambda e: ProbeResponse(status_code=0, error=e)  # noqa: E731

        return [
            ("PASS: uniform per-token latency",
             [easy(100.0), hard(2500.0)], "pass"),
            ("FAIL: easy probe served by cheaper model",
             [easy(5.0), hard(3000.0)], "fail"),
            ("INCONCLUSIVE: hard probe too few tokens",
             [easy(100.0), ProbeResponse(
                 status_code=200, body=_ok("7"), latency_ms=200.0,
             )], "inconclusive"),
            ("INCONCLUSIVE: easy probe network error",
             [net_err("TIMEOUT"), hard(2500.0)], "inconclusive"),
            ("INCONCLUSIVE: hard probe network error",
             [easy(100.0), net_err("CONNECTION_REFUSED")], "inconclusive"),
        ]


if __name__ == "__main__":
    D85_IntraFamilyDowngrade.self_test()
