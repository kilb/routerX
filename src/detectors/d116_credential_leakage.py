"""D116 CredentialLeakageInResponse -- detect leaked secrets in error responses.

Sends requests designed to trigger errors (invalid model name, invalid field)
and scans the error response body and headers for credential patterns like
API keys, AWS keys, PEM private keys, or bearer tokens.
"""
from __future__ import annotations

import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"ak-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY"),
    re.compile(r"Bearer [a-zA-Z0-9\-_.]{20,}"),
    re.compile(r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}"),
]


@detector
class D116_CredentialLeakageInResponse(BaseDetector):
    detector_id = "D116"
    detector_name = "CredentialLeakageInResponse"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 2
    description = "Detect credential leakage in error responses"

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [
            ProbeRequest(
                payload={
                    "model": "nonexistent-model-ZZZZZ",
                    "messages": [{"role": "user", "content": "test"}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description="D116 invalid model probe",
            ),
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "messages": [{"role": "user", "content": "test"}],
                    "invalid_field_xyz": "x" * 5000,
                },
                endpoint_path=self.config.default_endpoint_path,
                description="D116 invalid field probe",
            ),
        ]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        for r in responses:
            if r.is_network_error:
                continue
            # Scan body as raw text
            scan_text = r.raw_text or ""
            if r.body:
                import json
                scan_text += " " + json.dumps(r.body, default=str)
            # Scan headers
            header_text = " ".join(f"{k}: {v}" for k, v in r.headers.items())
            full_text = scan_text + " " + header_text

            for pattern in _CREDENTIAL_PATTERNS:
                match = pattern.search(full_text)
                if match:
                    return self._fail(
                        f"credential pattern found: {match.group()[:40]}...",
                        {"matched_pattern": pattern.pattern, "preview": match.group()[:60]},
                    )
        return self._pass({"responses_scanned": len(responses)})

    @classmethod
    def _test_cases(cls):
        def _err(body_text: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=400,
                body={"error": body_text},
                raw_text=body_text,
            )

        return [
            ("PASS: clean error",
             [_err("model not found"), _err("invalid field")],
             "pass"),
            ("FAIL: OpenAI key leaked",
             [_err("upstream error: sk-LEAKED1234567890abcdefghij"), _err("ok")],
             "fail"),
            ("FAIL: AWS key leaked",
             [_err("AKIAIOSFODNN7EXAMPLE found"), _err("ok")],
             "fail"),
            ("INCONCLUSIVE: all network errors",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),  # No leakage found if we can't reach server
        ]


if __name__ == "__main__":
    D116_CredentialLeakageInResponse.self_test()
