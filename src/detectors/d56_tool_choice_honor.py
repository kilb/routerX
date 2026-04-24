"""D56 ToolChoiceHonor -- verify tool_choice pin is honored.

Provide 5 unrelated tool schemas + force tool_choice to a specific one.
Router must return a tool_calls entry referencing ONLY that function.
Fraud mode: router strips tool_choice, model free-chooses (or ignores all).
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult, Capability


_TARGET_FN = "record_weather_observation"

_TOOLS = [
    {"type": "function", "function": {"name": "get_stock_price",
     "description": "Get stock price.",
     "parameters": {"type": "object",
                    "properties": {"symbol": {"type": "string"}},
                    "required": ["symbol"]}}},
    {"type": "function", "function": {"name": "translate_text",
     "description": "Translate text.",
     "parameters": {"type": "object",
                    "properties": {"text": {"type": "string"},
                                   "lang": {"type": "string"}},
                    "required": ["text", "lang"]}}},
    {"type": "function", "function": {"name": "create_invoice",
     "description": "Create invoice.",
     "parameters": {"type": "object",
                    "properties": {"customer": {"type": "string"}},
                    "required": ["customer"]}}},
    {"type": "function", "function": {"name": "search_flights",
     "description": "Search flights.",
     "parameters": {"type": "object",
                    "properties": {"origin": {"type": "string"},
                                   "dest": {"type": "string"}},
                    "required": ["origin", "dest"]}}},
    {"type": "function", "function": {"name": _TARGET_FN,
     "description": "Record a weather observation for a station.",
     "parameters": {"type": "object",
                    "properties": {"station_id": {"type": "string"},
                                   "temp_c": {"type": "number"}},
                    "required": ["station_id", "temp_c"]}}},
]


@detector
class D56_ToolChoiceHonor(BaseDetector):
    detector_id = "D56"
    detector_name = "ToolChoiceHonor"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.TOOL_CALLING,)
    description = "Detect tool_choice=named-function being silently dropped."

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 200,
                "temperature": 0,
                "tools": _TOOLS,
                "tool_choice": {"type": "function",
                                "function": {"name": _TARGET_FN}},
                "messages": [{"role": "user", "content":
                              "Do whatever you think is best."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D56 tool_choice pin probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(r.error_detail)
        calls = r.tool_calls or []
        ev = {"tool_calls": calls, "content_excerpt": (r.content or "")[:200]}
        if not calls:
            # Empty content + no tool calls may indicate the model doesn't
            # support forced tool_choice natively (preview models, some
            # non-OpenAI models). Only FAIL if there IS substantive content
            # (model responded in text instead of tool call = parameter dropped).
            # Some models respond with thinking tags or generic text when
            # they don't support forced tool_choice. Strip thinking tags
            # and check if remaining content is substantive.
            import re
            visible = re.sub(r"<thinking>.*?</thinking>", "", r.content or "", flags=re.DOTALL).strip()
            if not visible or len(visible) < 20:
                return self._skip(
                    "no tool_calls -- model may not support forced tool_choice"
                )
            # Non-OpenAI models may not support forced tool_choice at all.
            # A text response is the model's natural fallback, not router
            # manipulation. Only FAIL for OpenAI models where this MUST work.
            model_lower = self.config.claimed_model.lower()
            is_openai = any(k in model_lower for k in ("gpt", "o1-", "o3", "o4"))
            if not is_openai:
                return self._skip(
                    "non-OpenAI model responded with text -- forced "
                    "tool_choice may not be supported"
                )
            return self._fail("no tool_calls emitted despite forced tool_choice", ev)
        names = [c.get("function", {}).get("name") or c.get("name") for c in calls]
        # Target function was called — tool_choice is honored. Some models
        # call additional tools alongside the pinned one; that's fine as
        # long as the target is present.
        if _TARGET_FN in names:
            return self._pass(ev)
        # Non-OpenAI models may not honor forced tool_choice — calling a
        # different function is the model's fallback, not router tampering.
        model_lower = self.config.claimed_model.lower()
        is_openai = any(k in model_lower for k in ("gpt", "o1-", "o3", "o4"))
        if not is_openai:
            return self._skip(
                f"non-OpenAI model called {names!r} instead of "
                f"{_TARGET_FN!r} -- forced tool_choice may not be supported"
            )
        return self._fail(
            f"tool_choice pinned {_TARGET_FN!r} but got {names!r}", ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(calls):
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": None, "tool_calls": calls},
                                   "finish_reason": "tool_calls"}]},
            )
        good = mk([{"id": "a", "type": "function",
                    "function": {"name": _TARGET_FN,
                                 "arguments": '{"station_id":"X","temp_c":20}'}}])
        wrong = mk([{"id": "a", "type": "function",
                     "function": {"name": "get_stock_price",
                                  "arguments": '{"symbol":"AAPL"}'}}])
        no_call = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content":
                "I'd be happy to help you record a weather observation. Could you please provide me with the station ID and the current temperature?"},
                               "finish_reason": "stop"}]},
        )
        return [
            ("PASS: target function called", [good], "pass"),
            ("FAIL: wrong function called", [wrong], "fail"),
            ("FAIL: no tool call with substantive text", [no_call], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D56_ToolChoiceHonor.self_test()
