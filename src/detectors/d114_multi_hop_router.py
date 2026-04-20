"""D114 MultiHopRouterDetection -- detect requests passing through multiple proxies.

Examines response headers for signatures of more than one proxy/gateway
family. If >= 2 different proxy families are detected, the request is
being multi-hopped through chained routers, which increases attack surface.
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

_PROXY_FAMILIES = {
    "oneapi": "x-oneapi",
    "newapi": "x-new-api",
    "litellm": "x-litellm",
    "vllm": "x-vllm",
    "openrouter": "x-openrouter",
    "poe": "x-poe",
    "relay": "x-relay",
    "proxy": "x-proxy",
    "gateway": "x-gateway",
    "ai-gateway": "x-ai-gateway",
    "via": "via",
    "forwarded-by": "x-forwarded-by",
}

MIN_FAMILIES_FOR_FAIL = 2


@detector
class D114_MultiHopRouterDetection(BaseDetector):
    detector_id = "D114"
    detector_name = "MultiHopRouterDetection"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect multi-hop routing through multiple proxy families"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 20,
                "messages": [{"role": "user", "content": "Say hello."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D114 multi-hop header probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        detected_families: set[str] = set()

        for family, prefix in _PROXY_FAMILIES.items():
            for hdr_name in headers_lower:
                if hdr_name == prefix or hdr_name.startswith(prefix + "-"):
                    detected_families.add(family)
                    break

        evidence = {
            "detected_families": sorted(detected_families),
            "family_count": len(detected_families),
        }

        if len(detected_families) >= MIN_FAMILIES_FOR_FAIL:
            return self._fail(
                f"multi-hop detected: {len(detected_families)} proxy families "
                f"({', '.join(sorted(detected_families))})",
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
            ("PASS: no proxy headers",
             [_resp({})],
             "pass"),
            ("PASS: single proxy family",
             [_resp({"X-OneAPI-Version": "3.0"})],
             "pass"),
            ("FAIL: two proxy families",
             [_resp({"X-OneAPI-Version": "3.0", "X-LiteLLM-Version": "1.82"})],
             "fail"),
            ("FAIL: three families",
             [_resp({"Via": "1.1 proxy", "X-OpenRouter-Id": "abc", "X-Gateway-Req": "123"})],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D114_MultiHopRouterDetection.self_test()
