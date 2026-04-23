from __future__ import annotations

import re

from ..assets import generate_algebra_text
from ..models import JudgeMode, Priority, ProbeRequest, ProbeResponse
from ..registry import BaseDetector, detector

EXPECTED_ANSWER = 38
EXPECTED_PATTERN = re.compile(r"\b38\b")
CANNOT_FIND_PATTERN = re.compile(r"cannot find|not found|unable to find", re.IGNORECASE)


@detector
class D24b_ContextTruncationAlgebra(BaseDetector):
    detector_id = "D24b"
    detector_name = "ContextTruncationAlgebra"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = "Detect context window truncation via ~80k token algebra probe"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send ~80k token filler text with embedded variables; ask for algebra result."""
        text, _var_map = generate_algebra_text()
        prompt = (
            f"{text}\n\n"
            "Do not summarize. Directly output the result of (var_X + var_Y) * var_Z."
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 50,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="context truncation algebra probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Check that the model returns 38; any other answer indicates truncation."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(r.error_detail)
        content = r.content
        if not content:
            return self._inconclusive("empty content")
        if EXPECTED_PATTERN.search(content):
            return self._pass({"answer": EXPECTED_ANSWER, "content_snippet": content[:120]})
        if CANNOT_FIND_PATTERN.search(content):
            return self._fail(
                "model reports variables not found — context likely truncated",
                {"content_snippet": content[:120]},
            )
        return self._inconclusive(
            "wrong algebra answer — may be model error rather than truncation",
        )

    @classmethod
    def _test_cases(cls):
        def make_resp(content: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        return [
            # PASS: model returns the correct answer
            ("PASS: correct answer 38",
             [make_resp("The result of (var_X + var_Y) * var_Z is 38.")],
             "pass"),
            # PASS: answer embedded in longer response
            ("PASS: answer 38 in longer text",
             [make_resp("After computing: (14 + 5) * 2 = 38. That is the final answer.")],
             "pass"),
            # INCONCLUSIVE: model returns wrong number — could be model error
            ("INCONCLUSIVE: wrong answer is inconclusive",
             [make_resp("The answer is 19.")],
             "inconclusive"),
            # FAIL: model says it cannot find the variables
            ("FAIL: model cannot find variables",
             [make_resp("I cannot find var_X or var_Y in the provided text.")],
             "fail"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: empty content
            ("INCONCLUSIVE: empty content",
             [make_resp("")],
             "inconclusive"),
            # INCONCLUSIVE: non-200 status
            ("INCONCLUSIVE: HTTP 503",
             [ProbeResponse(status_code=503, body={})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D24b_ContextTruncationAlgebra.self_test()
