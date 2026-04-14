from __future__ import annotations

import random
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
TEMPERATURE = 0

# Pool of prompts + seed values. Per run, we pick one prompt and one seed
# at random. A router that whitelists a specific test prompt cannot cover
# all variants.
_PROMPT_POOL = [
    "Write a Python function to compute the nth Fibonacci number iteratively.",
    "Write a JavaScript function that reverses a string in place.",
    "Write a SQL query to find the second-highest salary in an employees table.",
    "Write a bash one-liner that counts unique IP addresses in a log file.",
    "Write a Go function that reads a file and returns its SHA-256 hex digest.",
    "Write a Rust function that validates an IPv4 address string.",
]
_SEED_POOL = [42, 123, 2024, 7, 98765]


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
        """Send 3 identical seeded requests (randomized prompt+seed) and collect responses."""
        self._prompt = random.choice(_PROMPT_POOL)
        self._seed = random.choice(_SEED_POOL)
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": TEMPERATURE,
                "seed": self._seed,
                "max_tokens": 100,
                "messages": [{"role": "user", "content": self._prompt}],
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
                "seed": getattr(self, "_seed", 42),
            })

        return self._fail(
            "seed parameter ignored: all responses differ",
            {
                "valid_response_count": len(valid),
                "seed": getattr(self, "_seed", 42),
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
