from __future__ import annotations

from itertools import combinations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
    ProviderType,
)
from ..registry import BaseDetector, detector

PROBE_COUNT = 3
SEED = 42
TEMPERATURE = 0
PROMPT = "Write a Python function to compute the 10th Fibonacci number."


@detector
class D38_SeedReproducibility(BaseDetector):
    detector_id = "D38"
    detector_name = "SeedReproducibility"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = PROBE_COUNT
    description = "Detect routers that ignore the seed parameter, breaking determinism"
    required_provider = ProviderType.OPENAI

    async def send_probes(self) -> list[ProbeResponse]:
        """Send 3 identical seeded requests and collect responses."""
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": TEMPERATURE,
                "seed": SEED,
                "max_tokens": 100,
                "messages": [{"role": "user", "content": PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="seed reproducibility probe",
        )
        return [await self.client.send(probe) for _ in range(PROBE_COUNT)]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Pass if at least one pair of responses matches; fail if all three differ."""
        valid = [r for r in responses if not r.is_network_error and r.content]
        if len(valid) < 2:
            reason = (
                responses[0].error or "network error"
                if responses and responses[0].is_network_error
                else "insufficient valid responses"
            )
            return self._inconclusive(reason)

        contents = [r.content for r in valid]
        matched_pair = next(
            (
                (i, j)
                for i, j in combinations(range(len(contents)), 2)
                if contents[i] == contents[j]
            ),
            None,
        )

        if matched_pair is not None:
            i, j = matched_pair
            return self._pass({
                "matched_pair": [i, j],
                "valid_response_count": len(valid),
                "seed": SEED,
            })

        return self._fail(
            "seed parameter ignored: all responses differ",
            {
                "valid_response_count": len(valid),
                "seed": SEED,
                "response_previews": [c[:80] for c in contents],
            },
        )

    @classmethod
    def _test_cases(cls):
        def make_resp(content: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        identical = "def fib(n): return n if n <= 1 else fib(n-1) + fib(n-2)"
        alt1 = "def fibonacci(n):\n    a, b = 0, 1\n    for _ in range(n): a, b = b, a+b\n    return a"
        alt2 = "def fib10(): return 55"

        return [
            # PASS: all three identical (seed honoured)
            ("PASS: all three responses identical",
             [make_resp(identical), make_resp(identical), make_resp(identical)],
             "pass"),
            # PASS: only first pair matches — still passes
            ("PASS: first two match, third differs",
             [make_resp(identical), make_resp(identical), make_resp(alt1)],
             "pass"),
            # FAIL: all three differ — seed ignored
            ("FAIL: all three responses differ",
             [make_resp(identical), make_resp(alt1), make_resp(alt2)],
             "fail"),
            # INCONCLUSIVE: single valid response (two network errors)
            ("INCONCLUSIVE: only one valid response",
             [make_resp(identical), ProbeResponse(status_code=0, error="TIMEOUT"),
              ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: all network errors
            ("INCONCLUSIVE: all network errors",
             [ProbeResponse(status_code=0, error="CONNECTION_REFUSED")] * 3,
             "inconclusive"),
            # PASS: last pair matches, first differs
            ("PASS: last two match, first differs",
             [make_resp(alt1), make_resp(identical), make_resp(identical)],
             "pass"),
        ]


if __name__ == "__main__":
    D38_SeedReproducibility.self_test()
