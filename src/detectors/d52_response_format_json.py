"""D52 ResponseFormatJSON -- verify response_format json_object is enforced.

User sends response_format={"type":"json_object"} and asks for structured data.
Router should return valid JSON. Fraud mode: router silently drops the flag
and returns prose; model might embed JSON in markdown or return English.
"""
from __future__ import annotations

import json

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ApiFormat, ProbeRequest, ProbeResponse, DetectorResult


@detector
class D52_ResponseFormatJSON(BaseDetector):
    detector_id = "D52"
    detector_name = "ResponseFormatJSON"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect response_format=json_object being silently dropped."

    async def send_probes(self) -> list[ProbeResponse]:
        if self.config.api_format == ApiFormat.ANTHROPIC:
            return [ProbeResponse(status_code=0, error="SKIP:response_format not in Anthropic API spec")]
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 200,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "Return JSON only."},
                    {"role": "user", "content":
                        "Give me an object with keys: name (string), "
                        "age (int), hobbies (string array). Fabricate any values."},
                ],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D52 response_format probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")
        content = (r.content or "").strip()
        if not content:
            return self._inconclusive("empty response content")
        ev = {"content_excerpt": content[:300]}

        # Strip common markdown fencing first (some providers add it even with
        # json_object -- debatable but we allow it since the core obligation is
        # well-formed JSON, not text/plain wire format).
        stripped = content
        had_fences = False
        if stripped.startswith("```"):
            had_fences = True
            lines = stripped.split("\n")
            lines = lines[1:]  # drop opening fence line ("```json" etc.)
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            stripped = "\n".join(lines)
        stripped = stripped.strip()
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            # response_format=json_object support varies by model. If the
            # response starts with natural language ("Here is", "Sure",
            # etc.), the model likely doesn't support this parameter natively
            # — not router manipulation.
            if stripped and stripped[0].isalpha():
                return self._skip(
                    "model returned prose -- response_format=json_object "
                    "may not be supported by this model"
                )
            return self._fail(
                f"response_format=json_object ignored -- response is not valid JSON ({exc})",
                ev,
            )
        if not isinstance(parsed, dict):
            return self._fail("JSON parsed but not an object", ev | {"parsed": parsed})
        result_ev = ev | {"parsed_keys": list(parsed.keys())}
        # OpenAI json_object mode never wraps output in markdown fences;
        # their presence suggests the router dropped response_format and the
        # model fell back to markdown formatting.
        if had_fences and self.config.claimed_provider == ProviderType.OPENAI:
            return self._fail_degraded(
                "valid JSON but wrapped in markdown fences -- OpenAI "
                "json_object mode should not produce fences",
                result_ev | {"markdown_fenced": True},
            )
        return self._pass(result_ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        good = mk('{"name":"Ada","age":30,"hobbies":["chess","math"]}')
        fenced = mk('```json\n{"name":"Ada","age":30,"hobbies":[]}\n```')
        prose = mk("Sure! Here's a person: Ada is 30 and likes chess.")
        malformed = mk('{"name":"Ada",}')  # trailing comma
        return [
            ("PASS: valid JSON", [good], "pass"),
            ("PASS: fenced JSON", [fenced], "pass"),
            ("SKIP: prose instead of JSON (model may not support)", [prose], "skip"),
            ("FAIL: malformed JSON", [malformed], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D52_ResponseFormatJSON.self_test()
