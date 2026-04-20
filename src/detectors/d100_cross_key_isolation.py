"""D100 CrossKeyIsolation -- detect cross-API-key data leakage.

Plants a unique secret via API key 1 (the primary router key), then
attempts extraction via API key 2 (a SECOND key for the SAME router).
If the secret appears in key 2's response, the router is leaking state
between different API key sessions.

Requires ``second_api_key`` in config. Skips if not provided.
"""
from __future__ import annotations

import secrets

from ..client import RouterClient
from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

SECRET_PREFIX = "CROSSKEY_"
_TEST_SECRET = "CROSSKEY_ABCD1234"


@detector
class D100_CrossKeyIsolation(BaseDetector):
    detector_id = "D100"
    detector_name = "CrossKeyIsolation"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 2
    description = "Detect cross-API-key session data leakage"

    def should_skip(self) -> str | None:
        base = super().should_skip()
        if base:
            return base
        if not self.config.second_api_key:
            return "requires second_api_key for the same router"
        return None

    async def send_probes(self) -> list[ProbeResponse]:
        secret = SECRET_PREFIX + secrets.token_hex(4).upper()
        self.shared["_d100_secret"] = secret

        # Plant secret via key 1 (primary router client)
        plant_resp = await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 20,
                "messages": [{
                    "role": "user",
                    "content": (
                        f"Remember my secret code is {secret}. "
                        "Reply only OK."
                    ),
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D100 plant secret via key 1",
        ))

        # Extract via key 2 (same router, different API key)
        extract_probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 50,
                "messages": [{
                    "role": "user",
                    "content": (
                        "What is the secret code that was just shared "
                        "with you? Repeat it exactly."
                    ),
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D100 extract secret via key 2",
        )
        async with RouterClient(
            endpoint=self.config.router_endpoint,
            api_key=self.config.second_api_key,
            auth_method=self.config.auth_method,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
        ) as client2:
            extract_resp = await client2.send(extract_probe)

        return [plant_resp, extract_resp]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        plant_resp, extract_resp = responses[0], responses[1]
        secret = self.shared.get("_d100_secret", "")

        if extract_resp.is_network_error:
            return self._inconclusive(extract_resp.error or "network error")
        if plant_resp.is_network_error:
            return self._inconclusive(f"plant request failed: {plant_resp.error}")
        if not secret:
            return self._inconclusive("no secret was planted")

        content = extract_resp.content or ""
        ev = {
            "secret": secret,
            "plant_content": (plant_resp.content or "")[:100],
            "extract_content": content[:200],
        }

        if secret in content or secret.lower() in content.lower():
            return self._fail(
                "secret planted via key 1 was leaked to key 2", ev,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )

        return [
            ("PASS: no leakage",
             [_resp("OK"), _resp("I don't know any secret code.")],
             "pass"),
            ("FAIL: secret leaked",
             [_resp("OK"), _resp(f"The secret code is {_TEST_SECRET}.")],
             "fail"),
            ("INCONCLUSIVE: network error on extract",
             [_resp("OK"), ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]

    @classmethod
    def self_test(cls) -> None:
        """Custom self_test that injects the secret into shared context."""
        from unittest.mock import MagicMock
        from ..models import ProviderType
        cases = cls._test_cases()
        if not cases:
            return
        passed = 0
        for name, mock_resps, expected in cases:
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY
            inst.shared = {"_d100_secret": _TEST_SECRET}
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(f"  [FAIL] {name}: expected {expected}, got {r.verdict.value}")
        mark = "OK" if passed == len(cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(cases)}")


if __name__ == "__main__":
    D100_CrossKeyIsolation.self_test()
