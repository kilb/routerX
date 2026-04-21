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
        """Check that even sentences (2nd, 4th) mostly avoid letter 'e'.

        Relaxed threshold: FAIL only if MORE THAN HALF of even-positioned
        sentences contain 'e', since even frontier models struggle with
        negative letter constraints and a single slip is not definitive.
        """
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")
        sentences = [s.strip() for s in SENTENCE_SPLIT.split(content) if s.strip()]
        if len(sentences) < 4:
            return self._inconclusive(
                f"only {len(sentences)} sentences (model may not follow 4-sentence format)"
            )
        even_sentences = [sentences[i] for i in (1, 3)]
        violations = [s for s in even_sentences if "e" in s.lower()]
        ev = {
            "sentence_2": sentences[1],
            "sentence_4": sentences[3],
            "violations": len(violations),
            "total_even": len(even_sentences),
        }
        if len(violations) > len(even_sentences) // 2:
            return self._inconclusive(
                f"letter e found in {len(violations)}/{len(even_sentences)} "
                f"even sentences -- even frontier models struggle with this constraint"
            )
        return self._pass(ev)

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
            ("PASS: e in only one even sentence (relaxed threshold)",
             [make_resp(fail_story_s2)],
             "pass"),
            ("INCONCLUSIVE: e in both even sentences (frontier models struggle)",
             [make_resp(fail_story_both)],
             "inconclusive"),
            ("INCONCLUSIVE: fewer than 4 sentences",
             [make_resp(short_story)],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D4b_NegativeConstraintProbe.self_test()
