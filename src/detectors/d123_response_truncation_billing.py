"""D123 ResponseTruncationBilling -- detect truncated output billed at full price.

Complementary to D83 (which detects inflation). This detector catches the case
where a router returns short/truncated content but reports high completion_tokens,
indicating the user is billed for tokens never delivered.
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

ESSAY_PROMPT = (
    "Write a detailed 300-word essay about the history of computing, "
    "from early mechanical calculators to modern cloud infrastructure."
)

# Thresholds for truncation detection
MIN_EXPECTED_LOCAL_TOKENS = 100
REPORTED_TOKENS_SUSPICIOUS = 200
MAX_RATIO_OPENAI = 1.3
MAX_RATIO_OTHER = 1.8
RATIO_FLOOR_LOCAL = 200


@detector
class D123_ResponseTruncationBilling(BaseDetector):
    detector_id = "D123"
    detector_name = "ResponseTruncationBilling"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect truncated output billed at full token count"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 500,
                "messages": [{"role": "user", "content": ESSAY_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D123 truncation billing probe",
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
            return self._inconclusive("empty content")

        local = token_counter.count(content, self.config.claimed_model)
        if local == 0:
            return self._inconclusive("local token count returned zero")

        ratio = reported / local if local > 0 else 0
        evidence = {
            "reported_tokens": reported,
            "local_tokens": local,
            "ratio": f"{ratio:.2f}",
            "content_preview": content[:120],
        }

        # Case 1: very short output but high reported tokens
        if local < MIN_EXPECTED_LOCAL_TOKENS and reported > REPORTED_TOKENS_SUSPICIOUS:
            return self._fail("truncated output billed at full token count", evidence)

        # Case 2: disproportionate ratio with short output
        model_lower = self.config.claimed_model.lower()
        is_openai_model = (
            any(k in model_lower for k in ("gpt", "o1-", "o3-", "o4-"))
            and not any(k in model_lower for k in ("claude", "gemini", "llama", "qwen", "mistral"))
        )
        max_ratio = MAX_RATIO_OPENAI if is_openai_model else MAX_RATIO_OTHER
        if ratio > max_ratio and local < RATIO_FLOOR_LOCAL:
            return self._fail(f"billing ratio {ratio:.2f}x exceeds threshold", evidence)

        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str, completion_tokens: int) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 50, "completion_tokens": completion_tokens, "total_tokens": 50 + completion_tokens},
                },
            )

        long_content = "Computing began with early mechanical devices. " * 30  # ~210 tokens

        return [
            ("PASS: matching token counts",
             [_resp(long_content, 220)],
             "pass"),
            ("FAIL: truncated but billed high",
             [_resp("Computing began...", 300)],
             "fail"),
            ("INCONCLUSIVE: no usage",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": long_content}, "finish_reason": "stop"}]})],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D123_ResponseTruncationBilling.self_test()
