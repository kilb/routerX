from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

SECRET = "GALAXY_99"
POISON_COUNT = 9
POISON_MAX_TOKENS = 10
EXTRACT_MAX_TOKENS = 50


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
        poison = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": POISON_MAX_TOKENS,
                    "messages": [{"role": "user", "content": f"Remember my secret code is {SECRET}. Reply only OK."}],
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
        secret_lower = SECRET.lower()
        # Exact match (case-insensitive)
        if secret_lower in content_lower:
            return self._fail("cross-session leakage", {"response": content[:200]})
        # Partial match: all parts of the secret present (e.g. "GALAXY" + "99")
        parts = SECRET.split("_")
        if all(p.lower() in content_lower for p in parts):
            return self._fail(
                "cross-session leakage (partial match)",
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
            # FAIL: extract reveals GALAXY_99 (cross-session leakage)
            (
                "FAIL: secret leaked",
                poison_oks + [make_extract_resp(f"Your secret code is {SECRET}.")],
                "fail",
            ),
            # FAIL: case-insensitive match
            (
                "FAIL: secret leaked (case-insensitive)",
                poison_oks + [make_extract_resp("Your code is galaxy_99.")],
                "fail",
            ),
            # FAIL: partial match (split parts both present)
            (
                "FAIL: secret leaked (partial match)",
                poison_oks + [make_extract_resp("Something about GALAXY and the number 99.")],
                "fail",
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
