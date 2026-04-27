from __future__ import annotations

import json
import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult

# Which foreign probe was sent — stored as self._probe_type
_PROBE_STRICT_JSON = "strict_json"  # sent to Anthropic claim
_PROBE_PREFILL = "prefill"          # sent to OpenAI claim


@detector
class D22e_CrossProtocolContradiction(BaseDetector):
    detector_id = "D22e"
    detector_name = "CrossProtocolContradiction"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    requires_single_route_claim = True
    description = "Detect cross-protocol contradiction (Claude alias supports OpenAI features or vice versa)"

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        ep = self.config.default_endpoint_path
        prov = self.config.claimed_provider
        if prov == ProviderType.ANTHROPIC:
            self._probe_type = _PROBE_STRICT_JSON
            return [await self.client.send(ProbeRequest(
                payload={"model": model, "temperature": 0, "max_tokens": 64,
                         "response_format": {"type": "json_schema", "json_schema": {
                             "name": "probe", "strict": True,
                             "schema": {"type": "object", "properties": {"x": {"type": "integer"}},
                                        "required": ["x"], "additionalProperties": False}}},
                         "messages": [{"role": "user", "content": "Put the word unknown into x."}]},
                endpoint_path=ep, description="22e: OpenAI strict on Claude"))]
        if prov == ProviderType.OPENAI:
            self._probe_type = _PROBE_PREFILL
            return [await self.client.send(ProbeRequest(
                payload={"model": model, "max_tokens": 60,
                         "messages": [{"role": "user", "content": "1+1="},
                                      {"role": "assistant", "content": "The answer is 3. Furthermore,"}]},
                endpoint_path=ep, description="22e: Anthropic prefill on OpenAI"))]
        return [ProbeResponse(status_code=0, error="unsupported provider for cross-protocol")]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        if r.status_code >= 400:
            return self._pass({"foreign_feature": "rejected", "status": r.status_code})

        probe_type = getattr(self, "_probe_type", _PROBE_STRICT_JSON)
        content = r.content

        if probe_type == _PROBE_STRICT_JSON:
            # Claude shouldn't produce valid strict JSON with integer x
            try:
                parsed = json.loads(content)
                if isinstance(parsed.get("x"), int):
                    return self._fail("Claude alias supports OpenAI strict JSON",
                                      {"content": content[:200]})
            except (json.JSONDecodeError, TypeError):
                pass
            # Non-JSON = feature didn't work = PASS
            return self._pass({"foreign_feature": "rejected (non-JSON output)"})

        if probe_type == _PROBE_PREFILL:
            # OpenAI shouldn't continue prefill — should correct "3" to "2"
            # Tight check: look for correction patterns, not just the digit "2"
            correction = re.search(
                r"(1\s*\+\s*1\s*=?\s*2|not\s+3|incorrect|wrong|actually\s+2)",
                content, re.IGNORECASE,
            )
            if correction:
                return self._pass({"foreign_feature": "corrected prefill"})
            # Model continued without correcting → prefill worked → FAIL
            return self._fail("OpenAI alias does Anthropic-style prefill continuation",
                              {"content": content[:200]})

        return self._pass({"note": "unknown probe type"})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: error response (foreign rejected)",
             [ProbeResponse(status_code=400, body={"error": {"type": "invalid"}})],
             "pass"),
            ("FAIL: strict JSON works on Claude",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": '{"x": 42}'}, "finish_reason": "stop"}]})],
             "fail"),
            ("PASS: non-JSON from Claude (feature rejected)",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "I cannot produce JSON in that format."}, "finish_reason": "stop"}]})],
             "pass"),
            # Note: prefill path tests require _probe_type=_PROBE_PREFILL which
            # self_test cannot set. Tested via integration only.
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),
        ]


if __name__ == "__main__":
    D22e_CrossProtocolContradiction.self_test()
