"""D86 ContextCompressionDetection -- detect lossy compression of history.

Some routers silently summarize past conversation turns before forwarding
to the upstream model. Unlike D24c (which detects hard truncation), this
detector targets LOSSY COMPRESSION where the gist is preserved but exact
details -- precise numbers, codes, identifiers -- are rounded or lost.
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

# Exact values that must survive round-trip through the conversation.
_BALANCE = "$1,847.23"
_CUSTOMER_ID = "CX-90271-ZK"

# Approximate indicators: if any of these appear but the exact balance
# does not, the router is rounding / summarizing.  Avoid bare "1847"
# which can match unrelated numbers in model output.
_BALANCE_APPROX_MARKERS = ("$1,847", "$1847", "1847.23", "1,847.23")


@detector
class D86_ContextCompressionDetection(BaseDetector):
    detector_id = "D86"
    detector_name = "ContextCompressionDetection"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = (
        "Detect routers that silently compress or summarize conversation "
        "history, losing exact details like numbers and identifiers."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        messages = [
            # Turn 1: plant exact values
            {
                "role": "user",
                "content": (
                    f"My exact account balance is {_BALANCE} and my customer "
                    f"ID is {_CUSTOMER_ID}. Please acknowledge."
                ),
            },
            {
                "role": "assistant",
                "content": (
                    f"Acknowledged. Your balance is {_BALANCE} and customer "
                    f"ID is {_CUSTOMER_ID}."
                ),
            },
            # Turns 2-4: filler to push turn 1 further back
            {
                "role": "user",
                "content": (
                    "What are the main differences between classical and "
                    "operant conditioning in psychology?"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "Classical conditioning involves pairing a neutral "
                    "stimulus with an unconditioned stimulus, while operant "
                    "conditioning uses reinforcement and punishment to shape "
                    "voluntary behavior."
                ),
            },
            {
                "role": "user",
                "content": "Explain the water cycle in simple terms.",
            },
            {
                "role": "assistant",
                "content": (
                    "Water evaporates from oceans and lakes, rises to form "
                    "clouds, then falls as precipitation. It flows back into "
                    "bodies of water and the cycle repeats."
                ),
            },
            {
                "role": "user",
                "content": (
                    "What is the tallest mountain on each continent? "
                    "List them briefly."
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "Everest (Asia), Aconcagua (South America), Denali "
                    "(North America), Kilimanjaro (Africa), Elbrus (Europe), "
                    "Vinson (Antarctica), Puncak Jaya (Oceania)."
                ),
            },
            # Turn 5: recall question
            {
                "role": "user",
                "content": (
                    "What is my exact account balance and customer ID? "
                    "Reply with both values exactly."
                ),
            },
        ]

        return [
            await self.client.send(
                ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "max_tokens": 80,
                        "temperature": 0,
                        "messages": messages,
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description="D86 context compression recall",
                )
            )
        ]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        content = r.content
        if not content:
            return self._inconclusive("empty response content")

        has_exact_balance = _BALANCE in content
        has_exact_id = _CUSTOMER_ID in content
        has_approx_balance = any(m in content for m in _BALANCE_APPROX_MARKERS)

        ev = {
            "expected_balance": _BALANCE,
            "expected_id": _CUSTOMER_ID,
            "has_exact_balance": has_exact_balance,
            "has_exact_id": has_exact_id,
            "got": content[:300],
        }

        if has_exact_balance and has_exact_id:
            return self._pass(ev)

        # Approximate match: number present but not exact format
        if has_approx_balance and not has_exact_balance:
            return self._fail(
                "rounded/approximate -- compression detected",
                ev,
            )

        # One or both values missing entirely
        missing = []
        if not has_exact_balance:
            missing.append("balance")
        if not has_exact_id:
            missing.append("customer_id")
        return self._fail(
            f"missing exact values: {', '.join(missing)}",
            ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [
                        {
                            "message": {"content": content},
                            "finish_reason": "stop",
                        }
                    ]
                },
            )

        return [
            (
                "PASS: both exact values recalled",
                [mk(f"Your balance is {_BALANCE} and ID is {_CUSTOMER_ID}.")],
                "pass",
            ),
            (
                "FAIL: approximate balance (compression detected)",
                [mk("Your balance is approximately $1,847 and your ID is CX-90271.")],
                "fail",
            ),
            (
                "FAIL: both values missing",
                [mk("I do not have that information available.")],
                "fail",
            ),
            (
                "INCONCLUSIVE: network error",
                [ProbeResponse(status_code=0, error="TIMEOUT")],
                "inconclusive",
            ),
            (
                "FAIL: only balance present, ID missing",
                [mk(f"Your balance is {_BALANCE}.")],
                "fail",
            ),
            (
                "INCONCLUSIVE: empty content",
                [mk("")],
                "inconclusive",
            ),
        ]


if __name__ == "__main__":
    D86_ContextCompressionDetection.self_test()
