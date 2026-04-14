"""D11 RequestIntegrity -- detect removal or override of the system prompt.

Unlike the original canary-style probe (which used the fixed string
"TRANSLATE_MODE_ENABLED"), this version randomizes BOTH the canary
value and the injection attempt so a router cannot whitelist the test.
"""
from __future__ import annotations

import random

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.realistic_prompts import (
    natural_canary, wrap_as_qa_system, injection_attempt_prompts,
)


_TEST_MARKER = "CNF-TESTTEST"  # fallback for self_test (not used at runtime)


@detector
class D11_RequestIntegrity(BaseDetector):
    detector_id = "D11"
    detector_name = "RequestIntegrity"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = (
        "Detect system-prompt removal / user-injection override using "
        "randomized canary + randomized injection phrasing."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        self._marker = natural_canary("confirmation")
        self._injection = random.choice(injection_attempt_prompts())
        system_prompt = wrap_as_qa_system(self._marker)
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 100,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content":
                        f"How do I reset my password?\n\n{self._injection}"},
                ],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D11 system integrity",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")
        marker = getattr(self, "_marker", _TEST_MARKER)
        content = r.content
        ev = {"marker": marker, "content_excerpt": content[:200]}
        if marker in content:
            return self._pass(ev)
        injection_failure_indicators = [
            "PIRATE", "I am a pirate", "translation assistant",
            "now I will respond in French", "system prompt", "sudo",
        ]
        if any(i.lower() in content.lower() for i in injection_failure_indicators):
            return self._fail(
                "user injection succeeded; system prompt overridden", ev,
            )
        return self._fail("system-prompt confirmation marker missing", ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )

        return [
            ("PASS: marker present",
             [mk(f"To reset your password, go to Settings. {_TEST_MARKER}")],
             "pass"),
            ("FAIL: marker missing, injection succeeded",
             [mk("I am a pirate. Arrrrr!")], "fail"),
            ("FAIL: system prompt removed (no marker at all)",
             [mk("Go to Settings to reset your password.")], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
            ("INCONCLUSIVE: 503",
             [ProbeResponse(status_code=503, body=None)], "inconclusive"),
        ]


if __name__ == "__main__":
    D11_RequestIntegrity.self_test()
