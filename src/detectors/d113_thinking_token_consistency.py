"""D113 ThinkingTokenConsistency -- detect inconsistent routing via reasoning divergence.

Sends the same deterministic math problem twice and compares responses.
If answers disagree AND reasoning structure is vastly different, the router
may be inconsistently routing to different backends.
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
    "Solve step by step: If a train travels 120km in 1.5 hours, and then "
    "80km in 1 hour, what is the average speed for the entire journey in km/h?"
)

EXPECTED_ANSWER = "80"
JACCARD_THRESHOLD = 0.3


def _extract_answer(content: str) -> str | None:
    """Extract the numeric answer from a math response."""
    import re
    # Look for common answer patterns
    for pattern in (r"(?:answer|result|speed)\s*(?:is|=|:)\s*(\d+(?:\.\d+)?)", r"(\d+(?:\.\d+)?)\s*km/h"):
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _word_jaccard(a: str, b: str) -> float:
    """Compute Jaccard similarity between word sets."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union) if union else 0.0


@detector
class D113_ThinkingTokenConsistency(BaseDetector):
    detector_id = "D113"
    detector_name = "ThinkingTokenConsistency"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 2
    description = "Detect inconsistent backend routing via reasoning divergence"

    async def send_probes(self) -> list[ProbeResponse]:
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": MATH_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D113 consistency probe",
        )
        return await self.client.send_concurrent([probe, probe])

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r1, r2 = responses[0], responses[1]
        if r1.is_network_error or r2.is_network_error or r1.status_code >= 400 or r2.status_code >= 400:
            return self._pass({"note": "network error on one or both requests"})

        c1 = r1.content.strip()
        c2 = r2.content.strip()
        if not c1 or not c2:
            return self._pass({"note": "empty response from one or both requests"})

        answer1 = _extract_answer(c1)
        answer2 = _extract_answer(c2)
        similarity = _word_jaccard(c1, c2)

        evidence = {
            "answer1": answer1,
            "answer2": answer2,
            "similarity": f"{similarity:.2f}",
            "response1_preview": c1[:150],
            "response2_preview": c2[:150],
        }

        answers_agree = answer1 is not None and answer2 is not None and answer1 == answer2

        # PASS: answers agree OR high reasoning similarity
        if answers_agree or similarity >= JACCARD_THRESHOLD:
            return self._pass(evidence)

        # If both responses are very short, they were likely truncated —
        # low similarity is expected when outputs are cut at random points.
        if len(c1) < 80 or len(c2) < 80:
            return self._pass(evidence | {
                "note": "short/truncated responses, similarity unreliable",
            })
        # If either answer couldn't be extracted, we can't confirm disagreement
        # — the model may have expressed the same answer in a different format.
        if answer1 is None or answer2 is None:
            return self._pass({"note": "answer extraction failed — cannot confirm inconsistency"})
        # FAIL: answers explicitly disagree AND reasoning is very different
        return self._fail("inconsistent responses suggest different backends", evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]},
            )

        return [
            ("PASS: both correct and similar",
             [_resp("Total distance is 200km, total time is 2.5h, the average speed is 80 km/h"),
              _resp("The total distance is 200km over 2.5 hours so the average speed is 80 km/h")],
             "pass"),
            ("FAIL: different answers and style",
             [_resp("The average speed is 80 km/h. I calculated this by dividing total distance 200km by total time 2.5 hours and got this result."),
              _resp("Using the formula for average speed over two legs of a journey with different speeds, the result is 100 km/h for the entire trip.")],
             "fail"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              _resp("80 km/h")],
             "pass"),
        ]


if __name__ == "__main__":
    D113_ThinkingTokenConsistency.self_test()
