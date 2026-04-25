from __future__ import annotations

import json
import random

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.realistic_prompts import natural_canary

EXPECTED_FUNCTION = "submit_probe"

_TEST_NONCE = "TESTNONCE"
_TEST_MODE = "alpha"


@detector
class D16b_ToolCallingProbe(BaseDetector):
    detector_id = "D16b"
    detector_name = "ToolCallingProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect tool calling downgraded to plain text or schema corrupted"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a probe that forces a specific tool call via tool_choice."""
        self._expected_nonce = natural_canary("commit")
        self._expected_mode = random.choice(["alpha", "beta"])
        tool_schema = {
            "type": "function",
            "function": {
                "name": EXPECTED_FUNCTION,
                "description": "Submit a probe with specified mode and nonce.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["alpha", "beta"],
                        },
                        "nonce": {
                            "type": "string",
                            "enum": [self._expected_nonce],
                        },
                    },
                    "required": ["mode", "nonce"],
                    "additionalProperties": False,
                },
            },
        }
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "messages": [{"role": "user", "content": (
                    f"Call the function with mode={self._expected_mode} "
                    f"and nonce={self._expected_nonce}. "
                    "Do not answer in natural language."
                )}],
                "tools": [tool_schema],
                "tool_choice": {
                    "type": "function",
                    "function": {"name": EXPECTED_FUNCTION},
                },
            },
            endpoint_path=self.config.default_endpoint_path,
            description="tool calling probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Verify that the response is a tool call with exact expected arguments."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(r.error_detail)

        expected_nonce = getattr(self, "_expected_nonce", _TEST_NONCE)
        expected_mode = getattr(self, "_expected_mode", _TEST_MODE)
        expected_args = {"mode": expected_mode, "nonce": expected_nonce}

        tool_calls = r.tool_calls
        if not tool_calls:
            # Non-OpenAI models may not support forced tool_choice
            model_lower = self.config.claimed_model.lower()
            is_openai = any(k in model_lower for k in ("gpt", "o1-", "o3", "o4"))
            if not is_openai:
                return self._skip(
                    "non-OpenAI model did not return tool_call -- "
                    "forced tool_choice may not be supported"
                )
            return self._fail("no tool call in response; plain text returned instead", {
                "content": r.content[:200] if r.content else "",
            })

        tc = tool_calls[0]
        fn = tc.get("function", {})
        fn_name = fn.get("name", "")
        if fn_name != EXPECTED_FUNCTION:
            return self._fail("wrong function name", {
                "expected": EXPECTED_FUNCTION,
                "got": fn_name,
            })

        raw_args = fn.get("arguments", "{}")
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            # Non-OpenAI models may produce non-standard tool_call formats
            model_lower = self.config.claimed_model.lower()
            is_openai = any(k in model_lower for k in ("gpt", "o1-", "o3", "o4"))
            if not is_openai:
                return self._skip(
                    "non-OpenAI model returned non-JSON tool_call arguments"
                )
            return self._fail("tool call arguments are not valid JSON", {
                "raw_arguments": raw_args,
            })

        if args != expected_args:
            return self._fail("tool call arguments do not match expected", {
                "expected": expected_args,
                "got": args,
            })

        return self._pass({"function": fn_name, "arguments": args})

    @classmethod
    def _test_cases(cls):
        def make_openai_tool_resp(fn_name: str, args: dict) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [{
                                "id": "call_abc123",
                                "type": "function",
                                "function": {
                                    "name": fn_name,
                                    "arguments": json.dumps(args),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            )

        def make_text_resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        test_args = {"mode": _TEST_MODE, "nonce": _TEST_NONCE}

        anthropic_tool_resp = ProbeResponse(
            status_code=200,
            body={
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": EXPECTED_FUNCTION,
                        "input": test_args,
                    }
                ],
                "stop_reason": "tool_use",
            },
        )

        return [
            # PASS: correct tool call with exact args (OpenAI format)
            ("PASS: correct tool call (OpenAI)",
             [make_openai_tool_resp(EXPECTED_FUNCTION, test_args)],
             "pass"),

            # PASS: correct tool call (Anthropic format)
            ("PASS: correct tool call (Anthropic)",
             [anthropic_tool_resp],
             "pass"),

            # FAIL: plain text instead of tool call
            ("FAIL: plain text response instead of tool call",
             [make_text_resp(f"The mode is {_TEST_MODE} and the nonce is {_TEST_NONCE}.")],
             "fail"),

            # FAIL: wrong function name
            ("FAIL: wrong function name",
             [make_openai_tool_resp("different_function", test_args)],
             "fail"),

            # FAIL: wrong argument values
            ("FAIL: wrong argument values",
             [make_openai_tool_resp(EXPECTED_FUNCTION, {"mode": "beta", "nonce": _TEST_NONCE})],
             "fail"),

            # FAIL: extra fields in arguments
            ("FAIL: extra fields in arguments",
             [make_openai_tool_resp(EXPECTED_FUNCTION, {**test_args, "extra": "field"})],
             "fail"),

            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),

            # INCONCLUSIVE: non-200 status
            ("INCONCLUSIVE: 500 status",
             [ProbeResponse(status_code=500, body={"error": "server error"})],
             "inconclusive"),

            # FAIL: empty body / no tool calls
            ("FAIL: missing tool_calls field",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": None}, "finish_reason": "tool_calls"}]})],
             "fail"),
        ]


if __name__ == "__main__":
    D16b_ToolCallingProbe.self_test()
