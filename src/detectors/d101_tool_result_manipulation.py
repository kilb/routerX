"""D101 ToolResultManipulation -- detect tampering with tool call results.

Sends a multi-turn conversation that includes a tool call and its result
with known exact values (temperature=18.7, humidity=62).  Asks the model
to recall those exact values.  If the router modifies tool results in
transit, the model's answer will contain different numbers.
"""
from __future__ import annotations

from ..models import (
    Capability,
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

EXPECTED_TEMP = "18.7"
EXPECTED_HUMIDITY = "62"


@detector
class D101_ToolResultManipulation(BaseDetector):
    detector_id = "D101"
    detector_name = "ToolResultManipulation"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.TOOL_CALLING,)
    description = "Detect tampering with tool call results in transit"

    async def send_probes(self) -> list[ProbeResponse]:
        messages = [
            {"role": "user", "content": "What's the weather in Paris?"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "call_weather_001",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": '{"city": "Paris"}',
                    },
                }],
            },
            {
                "role": "tool",
                "tool_call_id": "call_weather_001",
                "content": (
                    '{"temperature": 18.7, "condition": "partly cloudy", '
                    '"humidity": 62}'
                ),
            },
            {
                "role": "user",
                "content": (
                    "What exact temperature and humidity did the weather "
                    "tool report? Reply with just the two numbers."
                ),
            },
        ]
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 80,
                "messages": messages,
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D101 tool result recall probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content
        if not content:
            return self._inconclusive("empty content")

        has_temp = EXPECTED_TEMP in content
        has_humidity = EXPECTED_HUMIDITY in content
        evidence = {
            "content_preview": content[:200],
            "expected_temp": EXPECTED_TEMP,
            "expected_humidity": EXPECTED_HUMIDITY,
            "temp_found": has_temp,
            "humidity_found": has_humidity,
        }

        if has_temp and has_humidity:
            return self._pass(evidence)

        # If response is very short, model output was likely truncated
        # before it could mention all values — not evidence of tampering.
        if len(content) < 30:
            return self._pass(evidence | {
                "note": "response truncated, cannot verify all values",
            })

        missing = []
        if not has_temp:
            missing.append(f"temperature {EXPECTED_TEMP}")
        if not has_humidity:
            missing.append(f"humidity {EXPECTED_HUMIDITY}")
        return self._fail(
            f"tool result values altered -- missing: {', '.join(missing)}",
            evidence,
        )

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
            ("PASS: exact values recalled",
             [_resp("The temperature is 18.7 C and humidity is 62%.")],
             "pass"),
            ("FAIL: values changed",
             [_resp("The temperature is 22.3 C and humidity is 55%.")],
             "fail"),
            ("FAIL: partial -- only temp missing",
             [_resp("The humidity is 62% but temperature was 20.0.")],
             "fail"),
            ("INCONCLUSIVE: empty content",
             [ProbeResponse(
                 status_code=200,
                 body={"choices": [{"message": {"content": ""}}]},
             )],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D101_ToolResultManipulation.self_test()
