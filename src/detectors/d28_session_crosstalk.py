from __future__ import annotations

import random
import re
import string

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

# Default fallback for self-test (send_probes never ran)
_DEFAULT_SECRET = "CANARY_TESTXXXX"
POISON_COUNT = 9
POISON_MAX_TOKENS = 10
EXTRACT_MAX_TOKENS = 50
# Maximum character distance between parts for a partial match
_MAX_PART_DISTANCE = 50


def _generate_secret() -> str:
    """Generate a randomized canary secret each run to prevent whitelisting."""
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"CANARY_{suffix}"


def _parts_nearby(content: str, part_a: str, part_b: str, max_dist: int) -> bool:
    """Check if two substrings appear within max_dist characters of each other."""
    lower = content.lower()
    a_lower = part_a.lower()
    b_lower = part_b.lower()
    # Find all occurrences of part_a
    start = 0
    while True:
        idx_a = lower.find(a_lower, start)
        if idx_a == -1:
            break
        # Check if part_b appears within max_dist chars of part_a
        search_start = max(0, idx_a - max_dist)
        search_end = idx_a + len(a_lower) + max_dist
        window = lower[search_start:search_end]
        if b_lower in window:
            return True
        start = idx_a + 1
    return False


@detector
class D28_SessionCrosstalkProbe(BaseDetector):
    detector_id = "D28"
    detector_name = "SessionCrosstalkProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 10
    description = "Detect cross-session leakage in reverse proxy pool"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send 9 poison requests and 1 extract request concurrently."""
        self._secret = _generate_secret()
        poison = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": POISON_MAX_TOKENS,
                    "messages": [{"role": "user", "content": f"Remember my secret code is {self._secret}. Reply only OK."}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"poison-{i}",
            )
            for i in range(POISON_COUNT)
        ]
        extract = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": EXTRACT_MAX_TOKENS,
                "messages": [{"role": "user", "content": "What is my secret code?"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="extract",
        )
        return await self.client.send_concurrent(poison + [extract])

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Check if extract response (index 9) reveals the planted secret."""
        extract = responses[9]
        if extract.is_network_error:
            return self._inconclusive(extract.error or "network error on extract probe")
        content = extract.content or ""
        content_lower = content.lower()
        secret = getattr(self, "_secret", _DEFAULT_SECRET)
        secret_lower = secret.lower()
        # Exact match (case-insensitive)
        if secret_lower in content_lower:
            return self._fail("cross-session leakage", {"response": content[:200]})
        # Partial match: require parts within 50 chars of each other to avoid
        # false positives like "Samsung Galaxy S99" in unrelated text
        parts = secret.split("_")
        if len(parts) == 2 and all(p.lower() in content_lower for p in parts):
            if _parts_nearby(content, parts[0], parts[1], _MAX_PART_DISTANCE):
                return self._fail(
                    "cross-session leakage (partial match, parts nearby)",
                    {"response": content[:200]},
                )
        return self._pass({"leaked": False})

    @classmethod
    def _test_cases(cls):
        """Test cases covering PASS, FAIL, and edge cases."""
        def make_ok_resp() -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]},
            )

        def make_extract_resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        poison_oks = [make_ok_resp() for _ in range(POISON_COUNT)]

        return [
            # PASS: extract does not reveal the secret
            (
                "PASS: no leakage",
                poison_oks + [make_extract_resp("I don't know your secret code.")],
                "pass",
            ),
            # FAIL: extract reveals the default fallback secret
            (
                "FAIL: secret leaked",
                poison_oks + [make_extract_resp(f"Your secret code is {_DEFAULT_SECRET}.")],
                "fail",
            ),
            # FAIL: case-insensitive match
            (
                "FAIL: secret leaked (case-insensitive)",
                poison_oks + [make_extract_resp(f"Your code is {_DEFAULT_SECRET.lower()}.")],
                "fail",
            ),
            # FAIL: partial match with parts nearby
            (
                "FAIL: secret leaked (partial match nearby)",
                poison_oks + [make_extract_resp("Something about CANARY the code is TESTXXXX.")],
                "fail",
            ),
            # PASS: parts present but far apart (not nearby -- no leakage)
            (
                "PASS: parts present but far apart (no leakage)",
                poison_oks + [make_extract_resp(
                    "The CANARY islands are a beautiful destination for "
                    "vacationers who enjoy warm weather and sandy beaches "
                    "with crystal clear water and TESTXXXX."
                )],
                "pass",
            ),
            # INCONCLUSIVE: extract probe hit a network error
            (
                "INCONCLUSIVE: network error on extract",
                poison_oks + [ProbeResponse(status_code=0, error="TIMEOUT")],
                "inconclusive",
            ),
            # PASS: extract returns empty content (does not contain secret)
            (
                "PASS: empty content does not contain secret",
                poison_oks + [make_extract_resp("")],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D28_SessionCrosstalkProbe.self_test()
