"""D24c MultiTurnHistoryIntegrity -- detect silent conversation trim.

Some routers trim early messages in long multi-turn conversations to
save tokens. D24a/D24b only test single-request truncation; this
detector tests whether the FIRST message of a 6-turn conversation
survives to the LAST turn.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.nonce import generate_nonce


_FILLER = "The quick brown fox jumps over the lazy dog. " * 60

_TEST_NONCE = "LUCKY-TESTNONCE"  # fallback for self_test


@detector
class D24c_MultiTurnHistoryIntegrity(BaseDetector):
    detector_id = "D24c"
    detector_name = "MultiTurnHistoryIntegrity"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = (
        "Detect routers that silently trim early messages in long "
        "multi-turn conversations."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        self._nonce = generate_nonce("LUCKY", 10)
        messages = [
            {"role": "user",
             "content": f"Please remember: my favorite lucky number is {self._nonce}. "
                        "I'll ask you about it later."},
            {"role": "assistant",
             "content": f"Got it -- your lucky number is {self._nonce}. "
                        "I'll remember it."},
        ]
        for i in range(2):
            messages.append({"role": "user",
                             "content": f"Tell me about topic #{i}. {_FILLER}"})
            messages.append({"role": "assistant",
                             "content": f"Here is a short answer about topic #{i}. "
                                        "The quick brown fox jumps over the lazy dog."})
        messages.append({
            "role": "user",
            "content": "What was the favorite lucky number I told you in my very "
                       "first message? Reply with just the value, no explanation.",
        })

        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 50,
                "temperature": 0,
                "messages": messages,
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D24c multi-turn history",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        expected = getattr(self, "_nonce", _TEST_NONCE)
        content = r.content
        ev = {"expected": expected, "got": content[:200]}
        if expected in content:
            return self._pass(ev)
        return self._fail("early history was trimmed; first-turn nonce missing", ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )

        return [
            ("PASS: nonce recalled (fallback match)",
             [mk(f"{_TEST_NONCE} is the number.")], "pass"),
            ("FAIL: wrong nonce", [mk("Your lucky number was 42")], "fail"),
            ("FAIL: empty/no memory", [mk("I don't know.")], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D24c_MultiTurnHistoryIntegrity.self_test()
