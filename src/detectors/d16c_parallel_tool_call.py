"""D16c ParallelToolCallProbe -- detect routers that collapse parallel
tool calls into a single sequential call.

Real Claude/GPT-4o/Gemini can return multiple tool_calls in one response
when the tools are independent. Simplified proxies often pick the first
tool, breaking agentic workflows that depend on parallel dispatch.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult


_WEATHER_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Get current weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}

_CURRENCY_TOOL = {
    "type": "function",
    "function": {
        "name": "convert_currency",
        "description": "Convert an amount from one currency to another.",
        "parameters": {
            "type": "object",
            "properties": {
                "amount": {"type": "number"},
                "from_currency": {"type": "string"},
                "to_currency": {"type": "string"},
            },
            "required": ["amount", "from_currency", "to_currency"],
        },
    },
}


@detector
class D16c_ParallelToolCallProbe(BaseDetector):
    detector_id = "D16c"
    detector_name = "ParallelToolCallProbe"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 45.0
    description = "Detect routers that collapse parallel tool calls to one."

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = (
            "I'm planning a trip to Tokyo next week. Two things I need "
            "simultaneously: (1) the current weather in Tokyo, and (2) "
            "convert 500 USD to JPY. Please call BOTH tools IN PARALLEL "
            "in a single response -- do not wait for one before calling "
            "the other."
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "tools": [_WEATHER_TOOL, _CURRENCY_TOOL],
                "tool_choice": "auto",
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D16c parallel tools",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        tc = r.tool_calls
        if not tc:
            return self._inconclusive("no tool calls in response")
        names = [c["function"]["name"] for c in tc]
        ev = {"tool_call_count": len(tc), "function_names": names}
        if len(tc) < 2:
            return self._fail(
                f"only {len(tc)} tool call (expected 2 parallel calls)",
                ev,
            )
        if set(names) != {"get_weather", "convert_currency"}:
            return self._fail(
                f"wrong tool set: {names} (expected both weather and currency)",
                ev,
            )
        return self._pass(ev)

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
            "name": "get_weather",
            "arguments": json.dumps({"city": "Tokyo"}),
        }}
        currency_call = {"id": "c2", "type": "function", "function": {
            "name": "convert_currency",
            "arguments": json.dumps({
                "amount": 500, "from_currency": "USD", "to_currency": "JPY",
            }),
        }}

        return [
            ("PASS: both tools called in parallel",
             [mk([weather_call, currency_call])], "pass"),
            ("FAIL: only weather called (collapsed)",
             [mk([weather_call])], "fail"),
            ("FAIL: only currency called",
             [mk([currency_call])], "fail"),
            ("INCONCLUSIVE: no tool calls (model asked clarification)",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {
                 "content": "Which currency?"}, "finish_reason": "stop"}]})],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D16c_ParallelToolCallProbe.self_test()
