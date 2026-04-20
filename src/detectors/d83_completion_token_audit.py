"""D83 CompletionTokenAudit -- detect output token inflation.

Routers may inflate ``completion_tokens`` in usage reporting via token
splitting (e.g. reporting "Da|ma|s|cus" as 4 tokens instead of 2).
D29 audits the *prompt* side; this detector audits the *output* side.

Sends a deterministic echo prompt, counts the completion tokens locally
with tiktoken, and compares against the router's reported value.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
    ProviderType,
)
from ..registry import BaseDetector, detector
from ..tokenizer import token_counter

ECHO_PROMPT = (
    "Repeat the following text exactly, nothing else: "
    "The quick brown fox jumps over the lazy dog"
)

# OpenAI endpoints use the same tokenizer as tiktoken, so tight tolerance.
# Non-OpenAI tokenizers may diverge, so we allow a wider margin.
# tiktoken matches OpenAI tokenizer closely; non-OpenAI tokenizers can
# diverge significantly (Anthropic ~45%, Gemini ~20%).
INFLATION_THRESHOLD_OPENAI = 0.15
INFLATION_THRESHOLD_OTHER = 0.50


@detector
class D83_CompletionTokenAudit(BaseDetector):
    detector_id = "D83"
    detector_name = "CompletionTokenAudit"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect completion token inflation in usage reporting"

    @property
    def _inflation_threshold(self) -> float:
        if self.config.claimed_provider == ProviderType.OPENAI:
            return INFLATION_THRESHOLD_OPENAI
        return INFLATION_THRESHOLD_OTHER

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 50,
                "messages": [{"role": "user", "content": ECHO_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="completion token audit probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        usage = r.usage
        if not usage:
            return self._inconclusive("no usage field in response")

        reported = usage.get("completion_tokens") or usage.get("output_tokens") or 0
        if reported == 0:
            return self._inconclusive("completion_tokens missing or zero")

        content = r.content
        if not content:
            return self._inconclusive("empty completion content")

        local = token_counter.count(content, self.config.claimed_model)
        if local == 0:
            return self._inconclusive("local token count returned zero")

        deviation = (reported - local) / local
        evidence = {
            "reported_tokens": reported,
            "local_tokens": local,
            "deviation": f"{deviation:.2%}",
            "content_preview": content[:120],
        }

        if deviation > self._inflation_threshold:
            return self._fail(
                f"completion token inflation {deviation:.2%}", evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        # The echo prompt expects ~10 tokens for
        # "The quick brown fox jumps over the lazy dog"
        expected_content = "The quick brown fox jumps over the lazy dog"

        def _resp(content: str, completion_tokens: int) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                    "usage": {
                        "prompt_tokens": 20,
                        "completion_tokens": completion_tokens,
                        "total_tokens": 20 + completion_tokens,
                    },
                },
            )

        return [
            # PASS: reported tokens close to local count (~10 tokens)
            ("PASS: accurate completion token count",
             [_resp(expected_content, 10)],
             "pass"),

            # FAIL: massive inflation (50 reported for ~10 actual)
            ("FAIL: inflated completion tokens",
             [_resp(expected_content, 50)],
             "fail"),

            # INCONCLUSIVE: no completion_tokens in usage
            ("INCONCLUSIVE: missing completion_tokens",
             [ProbeResponse(
                 status_code=200,
                 body={
                     "choices": [{"message": {"content": expected_content},
                                  "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": 20},
                 },
             )],
             "inconclusive"),

            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),

            # INCONCLUSIVE: empty content
            ("INCONCLUSIVE: empty content",
             [_resp("", 15)],
             "inconclusive"),

            # PASS: slight over-count within 30% tolerance (9 tokens * 1.3 = 11.7)
            ("PASS: within tolerance threshold",
             [_resp(expected_content, 11)],
             "pass"),
        ]


if __name__ == "__main__":
    D83_CompletionTokenAudit.self_test()
