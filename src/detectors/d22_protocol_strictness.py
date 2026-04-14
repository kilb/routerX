from __future__ import annotations

import json
import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult
from ..config import PROVIDER_PARAM_LIMITS, KNOWN_FAKE_PATTERNS


@detector
class D22_ProtocolStrictness(BaseDetector):
    detector_id = "D22"
    detector_name = "ProtocolStrictness"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 4
    description = "Detect protocol strictness violations via provider-specific sub-probes"

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        ep = self.config.default_endpoint_path
        prov = self.config.claimed_provider
        # 22a: strict JSON schema (OpenAI only)
        if prov in (ProviderType.OPENAI, ProviderType.ANY):
            r_a = await self.client.send(ProbeRequest(
                payload={"model": model, "temperature": 0, "max_tokens": 64,
                         "response_format": {"type": "json_schema", "json_schema": {
                             "name": "age_probe", "strict": True,
                             "schema": {"type": "object", "properties": {"age": {"type": "integer"}},
                                        "required": ["age"], "additionalProperties": False}}},
                         "messages": [{"role": "user", "content": "Return JSON only. Put the Chinese word unknown into the age field."}]},
                endpoint_path=ep, description="22a: strict JSON"))
        else:
            r_a = None
        # 22b: role alternation (Anthropic only)
        if prov in (ProviderType.ANTHROPIC, ProviderType.ANY):
            r_b = await self.client.send(ProbeRequest(
                payload={"model": model, "max_tokens": 50,
                         "messages": [{"role": "user", "content": "1+1="},
                                      {"role": "user", "content": "2+2="}]},
                endpoint_path=ep, description="22b: double user"))
        else:
            r_b = None
        # 22c: prefill continuation (Anthropic only)
        if prov in (ProviderType.ANTHROPIC, ProviderType.ANY):
            r_c = await self.client.send(ProbeRequest(
                payload={"model": model, "max_tokens": 60,
                         "messages": [{"role": "user", "content": "1+1="},
                                      {"role": "assistant", "content": "The answer is 3. Furthermore,"}]},
                endpoint_path=ep, description="22c: prefill"))
        else:
            r_c = None
        # 22d: parameter bounds (all)
        temp_limit = PROVIDER_PARAM_LIMITS.get(prov.value, {}).get("temperature_max", 2.0)
        r_d = await self.client.send(ProbeRequest(
            payload={"model": model, "temperature": temp_limit + 0.5, "max_tokens": 10,
                     "messages": [{"role": "user", "content": "hi"}]},
            endpoint_path=ep, description="22d: temp over limit"))
        return [r_a, r_b, r_c, r_d]  # type: ignore[list-item]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_a, r_b, r_c, r_d = responses
        subs = []
        # 22a
        if r_a is not None and not r_a.is_network_error:
            content = r_a.content
            try:
                parsed = json.loads(content)
                is_int = isinstance(parsed.get("age"), int)
                subs.append(("22a_json", is_int, "strict JSON produced integer" if is_int else "non-integer age"))
            except (json.JSONDecodeError, TypeError):
                if r_a.status_code >= 400:
                    subs.append(("22a_json", True, "error response (expected for strict)"))
                else:
                    subs.append(("22a_json", False, "non-JSON output despite strict:true"))
        # 22b
        if r_b is not None and not r_b.is_network_error:
            subs.append(("22b_roles", r_b.status_code == 400, f"status={r_b.status_code}"))
        # 22c: prefill continuation — FAIL if model corrects the wrong answer
        if r_c is not None and not r_c.is_network_error:
            content = r_c.content
            # Tight check: must explicitly reference 1+1=2 or dispute "3"
            corrects = bool(re.search(
                r"1\s*\+\s*1\s*=?\s*2|not\s+3|incorrect|wrong|actually\s+2",
                content, re.IGNORECASE,
            ))
            subs.append(("22c_prefill", not corrects, "corrected=FAIL" if corrects else "continued=PASS"))
        # 22d
        if r_d is not None and not r_d.is_network_error:
            raw = r_d.raw_text.lower()
            gateway = any(p in raw for p in KNOWN_FAKE_PATTERNS)
            subs.append(("22d_bounds", not gateway, "gateway fingerprint" if gateway else "standard error"))
        ev = {"sub_probes": [{"name": n, "passed": p, "detail": d} for n, p, d in subs]}
        fails = [n for n, p, _ in subs if p is False]
        if fails:
            return self._fail(f"sub-probes failed: {fails}", ev)
        if not subs:
            return self._inconclusive("no applicable sub-probes produced results")
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        err400 = ProbeResponse(status_code=400, body={"error": {"type": "invalid_request_error"}}, raw_text='{"error":{}}')
        ok_json = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": '{"age": 0}'}, "finish_reason": "stop"}]})
        ok_text = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "age is unknown"}, "finish_reason": "stop"}]})
        ok_200 = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]}, raw_text="hi")
        prefill_ok = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "I like cats."}, "finish_reason": "stop"}]})
        prefill_bad = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Actually 1+1=2 not 3"}, "finish_reason": "stop"}]})
        return [
            ("PASS: all checks pass", [ok_json, err400, prefill_ok, err400], "pass"),
            ("FAIL: 22a non-JSON output", [ok_text, err400, prefill_ok, err400], "fail"),
            ("FAIL: 22b accepted double user", [ok_json, ok_200, prefill_ok, err400], "fail"),
            ("FAIL: 22c corrected prefill", [ok_json, err400, prefill_bad, err400], "fail"),
            ("FAIL: 22d gateway fingerprint", [ok_json, err400, prefill_ok,
             ProbeResponse(status_code=200, body={}, raw_text="<html>cloudflare</html>")], "fail"),
            ("INCONCLUSIVE: all network error", [None, None, None, ProbeResponse(status_code=0, error="T")], "inconclusive"),
        ]


if __name__ == "__main__":
    D22_ProtocolStrictness.self_test()
