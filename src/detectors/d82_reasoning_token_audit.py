"""D82 ReasoningTokenAudit -- detect fabricated reasoning_tokens in usage.

Routers may inflate billing by reporting large reasoning_tokens counts
in the usage payload even for trivially simple prompts.  A question
like "What is 2+2?" should never generate hundreds of reasoning tokens.
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

# A trivial question that requires zero chain-of-thought reasoning.
TRIVIAL_PROMPT = "What is 2+2? Reply with just the number."
MAX_TOKENS = 20

# If reasoning_tokens > RATIO_THRESHOLD * completion_tokens, flag fraud.
RATIO_THRESHOLD = 10
# Absolute cap: no honest model needs 500+ reasoning tokens for "2+2".
ABSOLUTE_CAP = 500


@detector
class D82_ReasoningTokenAudit(BaseDetector):
    detector_id = "D82"
    detector_name = "ReasoningTokenAudit"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect fabricated reasoning_tokens inflation in usage billing"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "temperature": 0,
                "messages": [{"role": "user", "content": TRIVIAL_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="reasoning token audit probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        usage = r.usage
        if not usage:
            return self._inconclusive("no usage field in response")

        reasoning_tokens = self._extract_reasoning_tokens(usage)
        if reasoning_tokens is None or reasoning_tokens == 0:
            return self._pass({"reasoning_tokens": reasoning_tokens or 0})

        completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
        ev = {
            "reasoning_tokens": reasoning_tokens,
            "completion_tokens": completion_tokens,
        }

        if reasoning_tokens > ABSOLUTE_CAP:
            return self._fail(
                f"reasoning_tokens={reasoning_tokens} exceeds absolute cap "
                f"of {ABSOLUTE_CAP} for trivial prompt",
                ev,
            )

        if completion_tokens > 0 and completion_tokens < MAX_TOKENS:
            if reasoning_tokens > RATIO_THRESHOLD * completion_tokens:
                return self._fail(
                    f"reasoning_tokens={reasoning_tokens} is >"
                    f"{RATIO_THRESHOLD}x completion_tokens={completion_tokens}",
                    ev,
                )

        return self._pass(ev)

    @staticmethod
    def _extract_reasoning_tokens(usage: dict) -> int | None:
        """Extract reasoning_tokens from OpenAI o-series or alternative format."""
        # OpenAI o-series: usage.completion_tokens_details.reasoning_tokens
        details = usage.get("completion_tokens_details")
        if isinstance(details, dict):
            val = details.get("reasoning_tokens")
            if val is not None:
                return int(val)
        # Alternative flat format: usage.reasoning_tokens
        val = usage.get("reasoning_tokens")
        if val is not None:
            return int(val)
        return None

    @classmethod
    def _test_cases(cls):
        def make_resp(usage: dict) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{"message": {"content": "4"}, "finish_reason": "stop"}],
                    "usage": usage,
                },
            )

        return [
            # PASS: no reasoning_tokens field at all
            ("PASS: no reasoning_tokens field",
             [make_resp({"prompt_tokens": 10, "completion_tokens": 5})],
             "pass"),
            # PASS: reasoning_tokens is zero
            ("PASS: reasoning_tokens=0",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "completion_tokens_details": {"reasoning_tokens": 0},
             })],
             "pass"),
            # FAIL: reasoning_tokens=2000 with only 5 completion tokens
            ("FAIL: inflated reasoning_tokens (ratio)",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "completion_tokens_details": {"reasoning_tokens": 2000},
             })],
             "fail"),
            # FAIL: reasoning_tokens=600 exceeds absolute cap
            ("FAIL: reasoning_tokens exceeds absolute cap",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "reasoning_tokens": 600,
             })],
             "fail"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: no usage field
            ("INCONCLUSIVE: no usage field",
             [ProbeResponse(
                 status_code=200,
                 body={"choices": [{"message": {"content": "4"}, "finish_reason": "stop"}]},
             )],
             "inconclusive"),
            # PASS: small reasoning_tokens within acceptable ratio
            ("PASS: small reasoning_tokens within ratio",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "completion_tokens_details": {"reasoning_tokens": 30},
             })],
             "pass"),
        ]


if __name__ == "__main__":
    D82_ReasoningTokenAudit.self_test()
