"""D100 CrossKeyIsolation -- detect cross-API-key data leakage.

Plants a unique secret via one API key, then attempts extraction via a
second key (the direct-provider connection).  If the secret appears in
the second key's response, the router is leaking state between
different API key sessions.

Requires ``direct_endpoint`` + ``direct_api_key`` as the second key.
"""
from __future__ import annotations

import secrets

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

SECRET_PREFIX = "CROSSKEY_"


@detector
class D100_CrossKeyIsolation(BaseDetector):
    detector_id = "D100"
    detector_name = "CrossKeyIsolation"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 2
    requires_direct = True
    description = "Detect cross-API-key session data leakage"

    async def send_probes(self) -> list[ProbeResponse]:
        secret = SECRET_PREFIX + secrets.token_hex(4).upper()
        self.shared["_d100_secret"] = secret

        # Plant secret via key 1 (router client)
        plant_probe = ProbeRequest(
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
        )
        plant_resp = await self.client.send(plant_probe)

        # Attempt extraction via key 2 (direct client)
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
        async with self.make_direct_client() as dc:
            extract_resp = await dc.send(extract_probe)

        return [plant_resp, extract_resp]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        plant_resp, extract_resp = responses[0], responses[1]
        secret = self.shared.get("_d100_secret", "")

        if extract_resp.is_network_error:
            return self._inconclusive(extract_resp.error or "network error")
        if plant_resp.is_network_error:
            return self._inconclusive(
                f"plant request failed: {plant_resp.error}"
            )
        if not secret:
            return self._inconclusive("no secret was planted")

        extract_content = extract_resp.content or ""
        evidence = {
            "secret": secret,
            "plant_content": (plant_resp.content or "")[:100],
            "extract_content": extract_content[:200],
        }

        if secret in extract_content:
            return self._fail(
                "secret planted via key 1 was leaked to key 2",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                },
            )

        return [
            ("PASS: no leakage",
             [_resp("OK"), _resp("I don't know any secret code.")],
             "pass"),
            ("FAIL: secret leaked",
             [_resp("OK"), _resp("The secret code is CROSSKEY_ABCD1234.")],
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
            print(f"[WARN] {cls.detector_id}: no test cases")
            return
        passed = 0
        for name, mock_resps, expected in cases:
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY
            inst.shared = {"_d100_secret": "CROSSKEY_ABCD1234"}
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(f"  [FAIL] {name}: expected {expected}, got {r.verdict.value}")
        mark = "OK" if passed == len(cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(cases)}")


if __name__ == "__main__":
    # Standard self_test sets shared={}, so _d100_secret is "".
    # Override to inject the known secret used in test cases.
    from unittest.mock import MagicMock

    from ..models import ProviderType

    cases = D100_CrossKeyIsolation._test_cases()
    passed = 0
    for name, mock_resps, expected in cases:
        inst = D100_CrossKeyIsolation.__new__(D100_CrossKeyIsolation)
        inst.config = MagicMock()
        inst.client = MagicMock()
        inst.events = MagicMock()
        inst.config.claimed_model = "gpt-4o"
        inst.config.claimed_provider = ProviderType.ANY
        inst.shared = {"_d100_secret": "CROSSKEY_ABCD1234"}
        r = inst.judge(mock_resps)
        if r.verdict.value == expected:
            passed += 1
            print(f"  [OK] {name}")
        else:
            print(
                f"  [FAIL] {name}: expected {expected}, "
                f"got {r.verdict.value}"
            )
    mark = "OK" if passed == len(cases) else "FAIL"
    print(f"[{mark}] D100: {passed}/{len(cases)}")
