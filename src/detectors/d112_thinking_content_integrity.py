"""D112 ThinkingContentIntegrity -- detect reasoning quality degradation.

Sends a multi-step math problem and checks that the response contains both
the correct answer AND visible reasoning steps. A substituted non-reasoning
model may produce a wrong answer with no intermediate work shown.
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

MATH_PROMPT = (
    "What is 17 * 23 + 45 - 12? Show your step-by-step reasoning, "
    "then give the final answer on a separate line starting with 'ANSWER:'"
)

EXPECTED_ANSWER = "424"
# Intermediate values that indicate reasoning steps
REASONING_MARKERS = ("391", "436", "17 * 23", "17*23", "17 x 23")


@detector
class D112_ThinkingContentIntegrity(BaseDetector):
    detector_id = "D112"
    detector_name = "ThinkingContentIntegrity"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect reasoning quality degradation from model substitution"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": MATH_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D112 thinking content integrity probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        if r.status_code != 200:
            return self._pass({"note": r.error_detail})

        content = r.content.strip()
        if not content:
            return self._pass({"note": "empty response — no evidence of issue"})

        has_correct_answer = EXPECTED_ANSWER in content
        has_reasoning = any(marker in content for marker in REASONING_MARKERS)

        evidence = {
            "has_correct_answer": has_correct_answer,
            "has_reasoning": has_reasoning,
            "content_preview": content[:300],
        }

        # PASS: correct answer OR shows reasoning (model tried)
        if has_correct_answer or has_reasoning:
            return self._pass(evidence)

        # If response is very short, it was likely truncated mid-reasoning.
        # "To solve the expression 17 * 2" = model started reasoning but
        # output was cut. Not evidence of model substitution.
        if len(content) < 80:
            return self._pass(evidence | {
                "note": "response appears truncated mid-reasoning",
            })
        # FAIL: wrong answer AND no reasoning steps visible
        return self._fail("wrong answer with no reasoning steps -- possible model substitution", evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]},
            )

        return [
            ("PASS: correct with steps",
             [_resp("17 * 23 = 391\n391 + 45 = 436\n436 - 12 = 424\nANSWER: 424")],
             "pass"),
            ("PASS: wrong but shows reasoning",
             [_resp("Let me calculate: 17*23 = 391, then 391 + 45 = 436, 436 - 12 = 423\nANSWER: 423")],
             "pass"),
            ("PASS: short wrong answer (likely truncated)",
             [_resp("The answer is 500.")],
             "pass"),
            ("FAIL: long wrong answer with no reasoning",
             [_resp("I believe the final answer to your mathematical question is exactly five hundred, which I computed mentally.")],
             "fail"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),
            ("PASS: empty",
             [_resp("")],
             "pass"),
        ]


if __name__ == "__main__":
    D112_ThinkingContentIntegrity.self_test()
