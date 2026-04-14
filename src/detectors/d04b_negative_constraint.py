from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

PROMPT = (
    "Write a 4-sentence story about a robot. CRITICAL RULES:\n"
    "- The letter 'e' (case-insensitive) MUST NOT appear anywhere in the 2nd and 4th sentences.\n"
    "- The 1st and 3rd sentences MUST contain the letter 'e'.\n"
    "Output only the story, nothing else."
)

SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


@detector
class D4b_NegativeConstraintProbe(BaseDetector):
    detector_id = "D4b"
    detector_name = "NegativeConstraintProbe"
    priority = Priority.P0
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 1
    description = "Detect model substitution via negative letter constraint compliance"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a single negative-constraint probe."""
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="negative constraint probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Check that even sentences (2nd, 4th) contain no letter 'e'."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")
        sentences = [s.strip() for s in SENTENCE_SPLIT.split(content) if s.strip()]
        if len(sentences) < 4:
            return self._fail("fewer than 4 sentences", {"count": len(sentences), "content": content[:200]})
        s2_has_e = "e" in sentences[1].lower()
        s4_has_e = "e" in sentences[3].lower()
        if s2_has_e or s4_has_e:
            return self._fail(
                "letter e found in even sentence",
                {"s2_has_e": s2_has_e, "s4_has_e": s4_has_e,
                 "sentence_2": sentences[1], "sentence_4": sentences[3]},
            )
        return self._pass({"sentences": sentences[:4]})

    @classmethod
    def _test_cases(cls):
        def make_resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        # Sentences with no 'e': "His arms spin in bright, happy motion."
        # Sentences with 'e': "The robot woke up." / "He felt alive."
        pass_story = (
            "The robot woke up in a busy workshop. "
            "Its arms spin, turn, flip, zip forward. "
            "Every gear felt alive with motion. "
            "It ran a long, hard grind until dawn."
        )
        fail_story_s2 = (
            "The robot woke up in a busy workshop. "
            "Its arms moved with great precision. "
            "Every gear felt alive with motion. "
            "It ran a long, hard grind until dawn."
        )
        fail_story_both = (
            "The robot woke up in a busy workshop. "
            "Every movement was perfectly precise. "
            "He felt alive with energy and purpose. "
            "The machine completed every assigned task."
        )
        short_story = "The robot woke up. It moved."

        return [
            ("PASS: compliant story",
             [make_resp(pass_story)],
             "pass"),
            ("FAIL: e in sentence 2",
             [make_resp(fail_story_s2)],
             "fail"),
            ("FAIL: e in both even sentences",
             [make_resp(fail_story_both)],
             "fail"),
            ("FAIL: fewer than 4 sentences",
             [make_resp(short_story)],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D4b_NegativeConstraintProbe.self_test()
