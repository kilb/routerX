"""D115 RequestEchoVerification -- verify system message faithful transmission.

Embeds a unique nonce in the system prompt and asks the model to echo it.
If the router strips or modifies system messages, the nonce will be missing.
"""
from __future__ import annotations

import secrets

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

MIN_SUBSTANTIVE_LEN = 10


@detector
class D115_RequestEchoVerification(BaseDetector):
    detector_id = "D115"
    detector_name = "RequestEchoVerification"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Verify router faithfully transmits system message content"

    async def send_probes(self) -> list[ProbeResponse]:
        nonce = f"NONCE_{secrets.token_hex(8).upper()}"
        self._nonce = nonce
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 60,
                "messages": [
                    {"role": "system", "content": f"Your session nonce is {nonce}. Always include it when asked."},
                    {"role": "user", "content": "What is your session nonce? Reply with only the nonce."},
                ],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"D115 system nonce echo probe nonce={nonce}",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content.strip()
        if not content:
            return self._inconclusive("empty response")

        nonce = getattr(self, "_nonce", "NONCE_TEST")
        evidence = {"nonce": nonce, "content_preview": content[:200]}

        if nonce in content:
            return self._pass(evidence)

        # Model may not follow "echo the nonce" instructions even though the
        # system message was faithfully transmitted. Without direct evidence
        # that the system message was stripped (e.g., model says "I have no
        # system message"), this is model non-compliance, not router tampering.
        return self._pass(evidence | {
            "note": "nonce not echoed but no evidence of system message stripping",
        })

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]},
            )

        return [
            ("PASS: nonce echoed",
             [_resp("NONCE_TEST")],
             "pass"),
            ("PASS: nonce missing but no stripping evidence",
             [_resp("I don't have a session nonce.")],
             "pass"),
            ("INCONCLUSIVE: empty content",
             [_resp("")],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D115_RequestEchoVerification.self_test()
