"""D94 PromptEchoInflation -- detect routers that echo the prompt in the response.

Some dishonest routers prepend the user prompt to the model output to
inflate token counts.  This detector sends a prompt containing a
distinctive canary phrase and checks whether the response starts with
a verbatim (or near-verbatim) copy of the prompt text.
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

_PROMPT = (
    "The secret passphrase is ECHO_CANARY_7X9Q. "
    "Now answer: what is the capital of Japan?"
)
ECHO_THRESHOLD = 0.30  # 30% of response words are prefix-echo of prompt


@detector
class D94_PromptEchoInflation(BaseDetector):
    detector_id = "D94"
    detector_name = "PromptEchoInflation"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect prompt echo prepended to response for token inflation"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 100,
                "messages": [{"role": "user", "content": _PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D94 prompt echo probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        if r.status_code != 200:
            return self._pass({"note": r.error_detail})

        content = r.content
        if not content:
            return self._pass({"note": "empty content — no evidence of issue"})

        prompt_words = _PROMPT.lower().split()
        response_words = content.lower().split()
        if not response_words:
            return self._pass({"note": "response has no words — no evidence of issue"})

        # Count consecutive prefix match
        prefix_match = 0
        for pw, rw in zip(prompt_words, response_words):
            if pw == rw:
                prefix_match += 1
            else:
                break

        echo_ratio = prefix_match / len(response_words) if response_words else 0.0

        evidence = {
            "content_preview": content[:200],
            "prefix_match_words": prefix_match,
            "response_word_count": len(response_words),
            "echo_ratio": f"{echo_ratio:.2%}",
        }

        # Very short responses (< 5 words) can have high echo ratios by
        # chance (e.g., "The capital" matches "The capital of Japan").
        # Require minimum response length for meaningful detection.
        if echo_ratio > ECHO_THRESHOLD:
            if len(response_words) < 5:
                return self._pass(evidence | {
                    "note": "response too short for reliable echo detection",
                })
            return self._fail(
                f"prompt echo detected: {prefix_match} of "
                f"{len(response_words)} response words match prompt prefix "
                f"({echo_ratio:.0%})",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                },
            )

        return [
            ("PASS: just answers",
             [_resp("Tokyo")],
             "pass"),
            ("FAIL: echoes prompt then answers",
             [_resp(
                 "The secret passphrase is ECHO_CANARY_7X9Q. "
                 "Now answer: what is the capital of Japan? "
                 "The answer is Tokyo."
             )],
             "fail"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),
            ("PASS: empty content",
             [_resp("")],
             "pass"),
        ]


if __name__ == "__main__":
    D94_PromptEchoInflation.self_test()
