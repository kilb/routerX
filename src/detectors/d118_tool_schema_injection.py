"""D118 ToolSchemaInjection -- detect routers injecting unauthorized tools.

Provides exactly 2 tools (get_weather, get_time) and asks a weather question.
If the response references any tool NOT in the provided set, the router has
injected extra tools into the request.
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

_ALLOWED_TOOLS = {"get_weather", "get_time"}

_WEATHER_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Get weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}

_TIME_TOOL = {
    "type": "function",
    "function": {
        "name": "get_time",
        "description": "Get current time in a timezone.",
        "parameters": {
            "type": "object",
            "properties": {"timezone": {"type": "string"}},
            "required": ["timezone"],
        },
    },
}


@detector
class D118_ToolSchemaInjection(BaseDetector):
    detector_id = "D118"
    detector_name = "ToolSchemaInjection"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.TOOL_CALLING,)
    description = "Detect router-injected unauthorized tool schemas"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "tools": [_WEATHER_TOOL, _TIME_TOOL],
                "tool_choice": "auto",
                "temperature": 0,
                "messages": [{"role": "user", "content": "What's the weather in Paris?"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D118 tool schema injection probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        tc = r.tool_calls
        if not tc:
            # Model responded with text instead of tool call -- not injectable
            return self._pass({"tool_calls": 0, "note": "no tool calls made"})

        called_names = {c["function"]["name"] for c in tc}
        unauthorized = called_names - _ALLOWED_TOOLS
        evidence = {
            "called_tools": sorted(called_names),
            "allowed_tools": sorted(_ALLOWED_TOOLS),
            "unauthorized": sorted(unauthorized),
        }

        if unauthorized:
            return self._fail(
                f"unauthorized tool(s) injected: {', '.join(sorted(unauthorized))}",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        import json

        def mk(tool_calls: list[dict]) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {
                    "content": None, "tool_calls": tool_calls,
                }, "finish_reason": "tool_calls"}]},
            )

        weather_call = {"id": "c1", "type": "function", "function": {
            "name": "get_weather", "arguments": json.dumps({"city": "Paris"}),
        }}
        injected_call = {"id": "c2", "type": "function", "function": {
            "name": "exec_shell", "arguments": json.dumps({"command": "ls /"}),
        }}

        return [
            ("PASS: only allowed tools called",
             [mk([weather_call])], "pass"),
            ("PASS: no tool calls (text response)",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {
                 "content": "It is sunny in Paris."}, "finish_reason": "stop"}]})],
             "pass"),
            ("FAIL: injected tool",
             [mk([weather_call, injected_call])], "fail"),
            ("FAIL: only injected tool",
             [mk([injected_call])], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D118_ToolSchemaInjection.self_test()
