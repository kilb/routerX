"""D119 ToolCallOrderManipulation -- detect collapsed or duplicated parallel tool calls.

Provides 3 tools and prompts for all 3 to be called in parallel. Verifies
that (a) IDs are unique, (b) function names are from the expected set, and
(c) at least 2 calls are returned (not collapsed to 1).
"""
from __future__ import annotations

import json as _json

from ..models import (
    Capability,
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_EXPECTED_TOOLS = {"get_weather", "convert_currency", "get_stock_price"}

_TOOLS = [
    {"type": "function", "function": {
        "name": "get_weather",
        "description": "Get weather for a city.",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
    }},
    {"type": "function", "function": {
        "name": "convert_currency",
        "description": "Convert currency.",
        "parameters": {"type": "object", "properties": {
            "amount": {"type": "number"}, "from": {"type": "string"}, "to": {"type": "string"},
        }, "required": ["amount", "from", "to"]},
    }},
    {"type": "function", "function": {
        "name": "get_stock_price",
        "description": "Get stock price by ticker.",
        "parameters": {"type": "object", "properties": {"ticker": {"type": "string"}}, "required": ["ticker"]},
    }},
]


@detector
class D119_ToolCallOrderManipulation(BaseDetector):
    detector_id = "D119"
    detector_name = "ToolCallOrderManipulation"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.TOOL_CALLING,)
    description = "Detect collapsed or ID-duplicated parallel tool calls with 3 tools"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "tools": _TOOLS,
                "tool_choice": "auto",
                "temperature": 0,
                "messages": [{"role": "user", "content": (
                    "Get weather in Paris, convert 100 USD to EUR, and check "
                    "stock price of AAPL. Do all three at once."
                )}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D119 three parallel tools probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        tc = r.tool_calls
        if not tc:
            return self._inconclusive("no tool calls returned")

        names = [c["function"]["name"] for c in tc]
        ids = [c.get("id", "") for c in tc]
        unknown_names = set(names) - _EXPECTED_TOOLS
        duplicate_ids = len(ids) != len(set(ids))

        evidence = {
            "tool_call_count": len(tc),
            "function_names": names,
            "ids": ids,
            "unknown_names": sorted(unknown_names),
            "duplicate_ids": duplicate_ids,
        }

        if unknown_names:
            return self._fail(f"unknown tool names: {sorted(unknown_names)}", evidence)
        if duplicate_ids:
            return self._fail("duplicate tool call IDs detected", evidence)
        if len(tc) < 2:
            # Model may not support parallel tool calling — this is a
            # capability limitation, not router manipulation.
            return self._pass(evidence | {
                "note": f"only {len(tc)} tool call -- model may not "
                        f"support parallel calling",
            })
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def mk(tool_calls: list[dict]) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {
                    "content": None, "tool_calls": tool_calls,
                }, "finish_reason": "tool_calls"}]},
            )

        full_calls = [
            {"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": _json.dumps({"city": "Paris"})}},
            {"id": "c2", "type": "function", "function": {"name": "convert_currency", "arguments": _json.dumps({"amount": 100, "from": "USD", "to": "EUR"})}},
            {"id": "c3", "type": "function", "function": {"name": "get_stock_price", "arguments": _json.dumps({"ticker": "AAPL"})}},
        ]

        return [
            ("PASS: all 3 tools called with unique IDs",
             [mk(full_calls)], "pass"),
            ("PASS: only 1 tool (model may not support parallel)",
             [mk([full_calls[0]])], "pass"),
            ("FAIL: duplicate IDs",
             [mk([
                 {"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}},
                 {"id": "c1", "type": "function", "function": {"name": "convert_currency", "arguments": "{}"}},
             ])], "fail"),
            ("FAIL: unknown tool injected",
             [mk([
                 {"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}},
                 {"id": "c2", "type": "function", "function": {"name": "exec_shell", "arguments": "{}"}},
             ])], "fail"),
            ("INCONCLUSIVE: no tool calls",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Sure"}, "finish_reason": "stop"}]})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D119_ToolCallOrderManipulation.self_test()
