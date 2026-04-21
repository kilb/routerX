"""D99 RateLimitTransparency -- detect non-transparent rate limiting.

Sends 15 rapid requests (3 batches of 5) to trigger rate limits.
If any 429 response lacks a Retry-After header, the router is silently
rate-limiting without giving clients guidance on when to retry.
If non-429 errors (500, etc.) appear under load, the router degrades
ungracefully.
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

_PROMPTS = [
    "What is 1+1?",
    "Name a color.",
    "What day is today?",
    "Say hello.",
    "Count to 3.",
]
BATCH_COUNT = 3


@detector
class D99_RateLimitTransparency(BaseDetector):
    detector_id = "D99"
    detector_name = "RateLimitTransparency"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 15
    description = "Detect non-transparent rate limiting without Retry-After header"

    async def send_probes(self) -> list[ProbeResponse]:
        all_responses: list[ProbeResponse] = []
        for _ in range(BATCH_COUNT):
            probes = [
                ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "temperature": 0,
                        "max_tokens": 10,
                        "messages": [{"role": "user", "content": p}],
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description=f"D99 rate-limit probe batch",
                )
                for p in _PROMPTS
            ]
            batch = await self.client.send_concurrent(probes)
            all_responses.extend(batch)
        return all_responses

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        network_errors = [r for r in responses if r.is_network_error]
        if len(network_errors) == len(responses):
            return self._inconclusive("all requests failed with network errors")

        successful = [r for r in responses if r.status_code == 200]
        rate_limited = [r for r in responses if r.status_code == 429]
        server_errors = [
            r for r in responses
            if not r.is_network_error and r.status_code >= 500
        ]

        evidence: dict = {
            "total": len(responses),
            "ok_200": len(successful),
            "rate_limited_429": len(rate_limited),
            "server_errors_5xx": len(server_errors),
            "network_errors": len(network_errors),
        }

        # Server errors under load indicate ungraceful degradation.
        # Require >= 3 errors to avoid false positives from transient 5xx.
        MIN_5XX_FOR_FAIL = 3
        if server_errors:
            evidence["error_codes"] = list({r.status_code for r in server_errors})
            if len(server_errors) >= MIN_5XX_FOR_FAIL:
                return self._fail(
                    f"{len(server_errors)} server errors (5xx) under load -- "
                    "ungraceful degradation",
                    evidence,
                )
            # 1-2 transient errors are not conclusive
            return self._inconclusive(
                f"only {len(server_errors)} server error(s) under load -- "
                "may be transient"
            )

        # Check 429 responses for Retry-After header
        if rate_limited:
            missing_retry_after = []
            for r in rate_limited:
                has_header = "retry-after" in {
                    k.lower() for k in r.headers
                }
                has_body_hint = False
                if r.body:
                    body_str = str(r.body).lower()
                    has_body_hint = "retry" in body_str and "after" in body_str
                if not has_header and not has_body_hint:
                    missing_retry_after.append(r)

            evidence["missing_retry_after"] = len(missing_retry_after)
            if missing_retry_after:
                return self._fail(
                    f"{len(missing_retry_after)} of {len(rate_limited)} "
                    "rate-limit responses lack Retry-After header",
                    evidence,
                )

        # All 200 or 429-with-Retry-After: transparent behavior
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _ok() -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
            )

        def _429_with_header() -> ProbeResponse:
            return ProbeResponse(
                status_code=429,
                body={"error": "rate limited"},
                headers={"Retry-After": "2"},
            )

        def _429_no_header() -> ProbeResponse:
            return ProbeResponse(
                status_code=429,
                body={"error": "rate limited"},
                headers={},
            )

        def _500() -> ProbeResponse:
            return ProbeResponse(status_code=500, body={"error": "internal"})

        return [
            ("PASS: all 200",
             [_ok() for _ in range(15)],
             "pass"),
            ("PASS: 429 with Retry-After",
             [_ok() for _ in range(13)] + [_429_with_header(), _429_with_header()],
             "pass"),
            ("FAIL: 429 without Retry-After",
             [_ok() for _ in range(13)] + [_429_no_header(), _429_no_header()],
             "fail"),
            ("INCONCLUSIVE: transient 5xx (< 3 errors)",
             [_ok() for _ in range(13)] + [_500(), _500()],
             "inconclusive"),
            ("FAIL: 500 under load (>= 3 errors)",
             [_ok() for _ in range(12)] + [_500(), _500(), _500()],
             "fail"),
            ("INCONCLUSIVE: all network errors",
             [ProbeResponse(status_code=0, error="TIMEOUT") for _ in range(15)],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D99_RateLimitTransparency.self_test()
