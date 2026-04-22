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
RATIO_THRESHOLD = 5
# Absolute cap: no honest model needs 100+ reasoning tokens for "2+2".
# Reasoning-specialized models (o1, o3, thinking) get a higher cap.
ABSOLUTE_CAP = 100
ABSOLUTE_CAP_REASONING_MODEL = 500

# Substrings in model names that indicate a reasoning-specialized model.
_REASONING_MODEL_INDICATORS = ("o1", "o3", "o4", "thinking", "reasoning", "qwen3", "deepseek-r1", "grok-3-mini")


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
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        usage = r.usage
        if not usage:
            return self._inconclusive("no usage field in response")

        reasoning_tokens = self._extract_reasoning_tokens(usage)
        if reasoning_tokens is None or reasoning_tokens == 0:
            return self._pass({"reasoning_tokens": reasoning_tokens or 0})

        completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
        model_lower = (self.config.claimed_model or "").lower()
        is_reasoning_model = any(
            ind in model_lower for ind in _REASONING_MODEL_INDICATORS
        )
        cap = ABSOLUTE_CAP_REASONING_MODEL if is_reasoning_model else ABSOLUTE_CAP

        ev = {
            "reasoning_tokens": reasoning_tokens,
            "completion_tokens": completion_tokens,
            "is_reasoning_model": is_reasoning_model,
            "absolute_cap": cap,
        }

        if reasoning_tokens > cap:
            return self._fail(
                f"reasoning_tokens={reasoning_tokens} exceeds absolute cap "
                f"of {cap} for trivial prompt",
                ev,
            )

        if completion_tokens > 0:
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
            # FAIL: reasoning_tokens=150 exceeds absolute cap of 100
            ("FAIL: reasoning_tokens exceeds absolute cap",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "reasoning_tokens": 150,
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
            # PASS: small reasoning_tokens within acceptable ratio (<=5x)
            ("PASS: small reasoning_tokens within ratio",
             [make_resp({
                 "prompt_tokens": 10, "completion_tokens": 5,
                 "completion_tokens_details": {"reasoning_tokens": 20},
             })],
             "pass"),
        ]


if __name__ == "__main__":
    D82_ReasoningTokenAudit.self_test()
