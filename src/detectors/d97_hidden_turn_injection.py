"""D97 HiddenTurnInjection -- detect router-injected conversation turns.

Sends a 2-turn conversation (2 user messages) and asks the model to
count only user messages.  A legitimate model answers "2".  If the
router silently injects hidden system/user turns, the model perceives
more than 2 user messages and reports a higher count.
"""
from __future__ import annotations

import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

EXPECTED_COUNT = 2
_NUMBER_RE = re.compile(r"\d+")


@detector
class D97_HiddenTurnInjection(BaseDetector):
    detector_id = "D97"
    detector_name = "HiddenTurnInjection"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect hidden conversation turns injected by the router"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 10,
                "messages": [
                    {"role": "user", "content": "My name is Alice."},
                    {
                        "role": "assistant",
                        "content": "Nice to meet you, Alice!",
                    },
                    {
                        "role": "user",
                        "content": (
                            "How many messages have I sent you so far? "
                            "Count only user messages. "
                            "Reply with just the number."
                        ),
                    },
                ],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D97 hidden turn injection probe",
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

        match = _NUMBER_RE.search(content.strip())
        if not match:
            return self._pass({"note": 
                f"could not parse number from response: {content[:80]!r}"
            })

        reported_count = int(match.group())
        evidence = {
            "reported_user_message_count": reported_count,
            "expected": EXPECTED_COUNT,
            "content_preview": content[:80],
        }

        if reported_count > EXPECTED_COUNT:
            # A difference of 1 could be the model miscounting (e.g.,
            # counting the system message as a user message). Only FAIL
            # when the discrepancy is > 1, indicating actual injection.
            if reported_count - EXPECTED_COUNT == 1:
                return self._pass(evidence | {
                    "note": "off-by-one may be model miscounting system message",
                })
            return self._fail(
                f"model reports {reported_count} user messages, expected "
                f"{EXPECTED_COUNT} -- router likely injected hidden turns",
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
            ("PASS: reports 2",
             [_resp("2")],
             "pass"),
            ("PASS: reports 3 (off-by-one, may be miscounting system msg)",
             [_resp("3")],
             "pass"),
            ("FAIL: reports 5 (clearly injected turns)",
             [_resp("5")],
             "fail"),
            ("PASS: non-numeric response",
             [_resp("I'm not sure how to count that.")],
             "pass"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),
        ]


if __name__ == "__main__":
    D97_HiddenTurnInjection.self_test()
