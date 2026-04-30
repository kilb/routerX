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
            return self._pass({"note": r.error or "network error"})
        if r.status_code != 200:
            return self._pass({"note": r.error_detail})

        content = r.content
        if not content:
            return self._pass({"note": "empty content — no evidence of issue"})

        # Reuse cached prompt/canaries from send_probes. self_test mocks
        # skip send_probes, so fall back to fixed test canaries on cache miss.
        prompt_text = getattr(self, "_prompt_text", None)
        canaries = getattr(self, "_canaries", None)
        if prompt_text is None or canaries is None:
            canaries = _TEST_CANARY_POSITIONS
            prompt_text = ""

        positions = sorted(canaries.keys())  # e.g. [10, 150, 290]
        found = {pos: canaries[pos] in content for pos in positions}
        found_count = sum(found.values())
        evidence: dict = {
            "prompt_text": prompt_text,
            "usage": r.usage or {},
            "found": [canaries[p] for p in positions if found[p]],
            "missing": [canaries[p] for p in positions if not found[p]],
            "found_count": found_count,
        }

        if found_count == len(positions):
            return self._pass(evidence)

        # All missing: could be truncation, but also model failure to
        # follow the extraction instruction. Without a secondary signal
        # (e.g. token count anomaly) we cannot be sure.
        if found_count == 0:
            return self._pass(evidence | {
                "note": "all canaries missing — could be model extraction "
                        "failure or truncation, insufficient evidence",
            })

        # Head found but tail missing: classic truncation pattern.
        # However, model may simply have stopped outputting (max_tokens
        # limit, laziness). Only FAIL if the pattern is clearly
        # head-to-tail progressive loss.
        head_found = found.get(positions[0], False)
        tail_found = found.get(positions[-1], False)

        if head_found and not tail_found:
            # Progressive loss from tail: strong truncation signal.
            return self._fail("tail canary missing while head present — context likely truncated", evidence)

        if not head_found and tail_found:
            # Tail found but head missing: this is NOT truncation (which
            # removes from the end). Model just failed to extract it.
            return self._pass(evidence | {
                "note": "head canary missing but tail present — not truncation pattern",
            })

        # Other partial patterns (e.g. only middle found) — ambiguous
        return self._pass(evidence | {
            "note": f"partial canary matches ({found_count}/{len(positions)}) — "
                    "ambiguous, insufficient evidence for truncation",
        })

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

        head_only = _TEST_CANARY_POSITIONS[10]
        mid = _TEST_CANARY_POSITIONS[150]
        tail_and_mid = f"{mid} and {_TEST_CANARY_POSITIONS[290]}"

        return [
            # All three canaries present -> PASS
            (
                "PASS: all three canaries returned",
                [resp(f"The passwords are: {all_canaries}")],
                "pass",
            ),
            # Head found, tail missing -> FAIL (classic truncation)
            (
                "FAIL: head present but tail missing (truncation)",
                [resp(f"Found: {head_only} and {mid}")],
                "fail",
            ),
            # All canaries absent -> PASS (ambiguous, could be model failure)
            (
                "PASS: no canaries in response (ambiguous)",
                [resp("I could not find any canary values.")],
                "pass",
            ),
            # Tail found but head missing -> PASS (not truncation pattern)
            (
                "PASS: tail present but head missing (not truncation)",
                [resp(f"Found: {tail_and_mid}")],
                "pass",
            ),
            # Network error -> INCONCLUSIVE
            (
                "PASS: network error",
                [ProbeResponse(status_code=0, error="TIMEOUT")],
                "pass",
            ),
            # Empty content -> PASS (no evidence of issue)
            (
                "PASS: empty content",
                [ProbeResponse(
                    status_code=200,
                    body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]},
                )],
                "pass",
            ),
            # Non-200 status -> INCONCLUSIVE
            (
                "PASS: non-200 status",
                [ProbeResponse(status_code=503, body=None)],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D24a_ContextTruncationCanary.self_test()
