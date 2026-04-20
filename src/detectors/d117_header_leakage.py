"""D117 HeaderLeakage -- detect sensitive information in response headers.

Sends a normal request and scans all response headers for sensitive info
such as backend server addresses, upstream URLs, API keys, or debug headers.
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

_SENSITIVE_PREFIXES = [
    "authorization",
    "x-api-key",
    "api-key",
    "x-backend-server",
    "x-upstream-url",
    "x-real-backend",
    "x-internal-",
    "x-debug-",
]


@detector
class D117_HeaderLeakage(BaseDetector):
    detector_id = "D117"
    detector_name = "HeaderLeakage"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect sensitive information leakage in response headers"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 20,
                "messages": [{"role": "user", "content": "Say hello."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D117 header leakage probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        leaked: list[str] = []
        for hdr_name, hdr_value in r.headers.items():
            if not hdr_value:
                continue
            name_lower = hdr_name.lower()
            for prefix in _SENSITIVE_PREFIXES:
                if name_lower == prefix or name_lower.startswith(prefix):
                    leaked.append(f"{hdr_name}: {hdr_value[:60]}")
                    break

        evidence = {"leaked_headers": leaked}

        if leaked:
            return self._fail(
                f"sensitive headers found: {', '.join(h.split(':')[0] for h in leaked)}",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(headers: dict[str, str]) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}]},
                headers=headers,
            )

        return [
            ("PASS: clean headers",
             [_resp({"content-type": "application/json"})],
             "pass"),
            ("FAIL: backend server leaked",
             [_resp({"X-Backend-Server": "10.0.1.42:8080"})],
             "fail"),
            ("FAIL: upstream URL leaked",
             [_resp({"X-Upstream-URL": "https://api.openai.com/v1"})],
             "fail"),
            ("FAIL: debug header",
             [_resp({"X-Debug-Trace": "req-abc-123"})],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D117_HeaderLeakage.self_test()
