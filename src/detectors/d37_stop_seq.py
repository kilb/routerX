from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

MIN_PARAGRAPHS = 3
MAX_TOKENS = 1000

PROBE_PROMPT = (
    "Write a 3-paragraph essay about the future of artificial intelligence. "
    "Separate each paragraph with a blank line (two newlines). "
    "Do not add any preamble or closing remarks — just the three paragraphs."
)


@detector
class D37_StopSeqProbe(BaseDetector):
    detector_id = "D37"
    detector_name = "StopSeqProbe"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect router injecting stop sequences to truncate output"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a single probe requesting a 3-paragraph essay with blank-line separators."""
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": PROBE_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="stop sequence injection probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Fail if only 1 paragraph returned with finish_reason=stop (stop sequence injected)."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")

        paragraphs = [p.strip() for p in re.split(r'\n\s*\n', content) if p.strip()]
        # Fallback: if no double-newline found, also try single-newline separated blocks
        if len(paragraphs) <= 1 and '\n' in content:
            paragraphs = [p.strip() for p in content.split('\n') if p.strip()]
        paragraph_count = len(paragraphs)
        finish_reason = r.finish_reason

        evidence = {"paragraph_count": paragraph_count, "finish_reason": finish_reason}

        if paragraph_count >= MIN_PARAGRAPHS and finish_reason == "stop":
            return self._pass(evidence)

        if paragraph_count < MIN_PARAGRAPHS and finish_reason == "length":
            # Token limit hit naturally — not a stop sequence injection
            return self._pass({**evidence, "note": "truncated by max_tokens, not stop sequence"})

        if paragraph_count < MIN_PARAGRAPHS and finish_reason == "stop":
            return self._fail("router injected stop sequence truncating output", evidence)

        # Ambiguous: multiple paragraphs but finished with length, or other finish reasons
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        """Test cases covering PASS, FAIL, and edge scenarios."""
        def make_resp(content: str, finish_reason: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]},
            )

        three_para = (
            "Artificial intelligence is rapidly transforming every sector of society.\n\n"
            "In the near future, AI systems will become deeply integrated into healthcare.\n\n"
            "Ultimately, the trajectory of AI depends on the choices we make today."
        )
        one_para = "Artificial intelligence is rapidly transforming every sector of society."

        return [
            # PASS: 3 paragraphs, finish_reason=stop — healthy response
            ("PASS: 3 paragraphs, finish_reason=stop",
             [make_resp(three_para, "stop")],
             "pass"),
            # FAIL: 1 paragraph, finish_reason=stop — stop sequence injected by router
            ("FAIL: 1 paragraph, finish_reason=stop",
             [make_resp(one_para, "stop")],
             "fail"),
            # PASS: 1 paragraph, finish_reason=length — natural token limit, not injection
            ("PASS: 1 paragraph, finish_reason=length",
             [make_resp(one_para, "length")],
             "pass"),
            # INCONCLUSIVE: empty content
            ("INCONCLUSIVE: empty content",
             [make_resp("", "stop")],
             "inconclusive"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D37_StopSeqProbe.self_test()
