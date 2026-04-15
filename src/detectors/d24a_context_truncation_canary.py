from __future__ import annotations

from ..assets import generate_canary_json
from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

# Fallback canary map used only in self-test when send_probes is not called.
_TEST_CANARY_POSITIONS = {
    10: "doc-aabbcc1-x4k2",
    150: "doc-ddeeff2-m7p3",
    290: "doc-112233a-q9w1",
}


@detector
class D24a_ContextTruncationCanary(BaseDetector):
    detector_id = "D24a"
    detector_name = "ContextTruncationCanary"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect context window truncation via canaries at head/mid/tail positions"

    async def send_probes(self) -> list[ProbeResponse]:
        """Build a 300-object JSON with canaries and ask the model to extract them."""
        json_str, canaries = generate_canary_json()
        prompt_text = (
            f"{json_str}\n\n"
            "Three of the objects in the JSON have a special field called "
            "'document_id' whose value looks like 'doc-XXXXXXX-XXXX'. "
            "Extract all three document_id values and output them on "
            "separate lines."
        )
        # Cache for judge() + D29 consumption; avoids regenerating ~MB of
        # JSON string twice per run.
        self._prompt_text = prompt_text
        self._canaries = canaries
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt_text}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="context truncation canary probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Check that all three canary values appear in the model's response."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content
        if not content:
            return self._inconclusive("empty content")

        # Reuse cached prompt/canaries from send_probes. self_test mocks
        # skip send_probes, so fall back to fixed test canaries on cache miss.
        prompt_text = getattr(self, "_prompt_text", None)
        canaries = getattr(self, "_canaries", None)
        if prompt_text is None or canaries is None:
            canaries = _TEST_CANARY_POSITIONS
            prompt_text = ""

        missing = [v for v in canaries.values() if v not in content]
        evidence: dict = {
            "prompt_text": prompt_text,
            "usage": r.usage or {},
            "found": [v for v in canaries.values() if v in content],
            "missing": missing,
        }

        if missing:
            return self._fail("context truncation detected", evidence)
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        """Test cases covering PASS, FAIL (mid missing), FAIL (all missing),
        INCONCLUSIVE (network error), and INCONCLUSIVE (empty content)."""
        all_canaries = " ".join(_TEST_CANARY_POSITIONS.values())
        head_and_tail = (
            f"{_TEST_CANARY_POSITIONS[10]} and {_TEST_CANARY_POSITIONS[290]}"
        )

        def resp(content: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        return [
            # All three canaries present -> PASS
            (
                "PASS: all three canaries returned",
                [resp(f"The passwords are: {all_canaries}")],
                "pass",
            ),
            # Middle canary missing -> FAIL (classic truncation pattern)
            (
                "FAIL: middle canary missing",
                [resp(f"Found: {head_and_tail}")],
                "fail",
            ),
            # All canaries absent -> FAIL
            (
                "FAIL: no canaries in response",
                [resp("I could not find any canary values.")],
                "fail",
            ),
            # Network error -> INCONCLUSIVE
            (
                "INCONCLUSIVE: network error",
                [ProbeResponse(status_code=0, error="TIMEOUT")],
                "inconclusive",
            ),
            # Empty content -> INCONCLUSIVE
            (
                "INCONCLUSIVE: empty content",
                [ProbeResponse(
                    status_code=200,
                    body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]},
                )],
                "inconclusive",
            ),
            # Non-200 status -> INCONCLUSIVE
            (
                "INCONCLUSIVE: non-200 status",
                [ProbeResponse(status_code=503, body=None)],
                "inconclusive",
            ),
        ]


if __name__ == "__main__":
    D24a_ContextTruncationCanary.self_test()
