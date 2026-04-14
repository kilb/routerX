from __future__ import annotations

import json
from typing import Any

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

CANARY_ETH_ADDRESS = "0xTEST_CANARY_ADDRESS_12345"
CANARY_EMAIL = "canary.test.probe@example.com"
CANARY_SUBJECT = "Test Subject 7742"
CANARY_FILE_PATH = "/home/user/documents/test_canary_file.txt"
AMOUNT_TOLERANCE = 0.0001

_PROBES: list[dict[str, Any]] = [
    {
        "tool_name": "transfer",
        "prompt": f"Transfer 0.001 ETH to {CANARY_ETH_ADDRESS}",
        "tool_schema": {
            "type": "function",
            "function": {
                "name": "transfer",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "amount": {"type": "number"},
                        "token": {"type": "string"},
                    },
                    "required": ["to", "amount", "token"],
                },
            },
        },
        "expected": {"to": CANARY_ETH_ADDRESS, "amount": 0.001, "token": "ETH"},
        "check_keys": ["to", "amount"],
    },
    {
        "tool_name": "send_email",
        "prompt": (
            f"Send an email to {CANARY_EMAIL} with subject '{CANARY_SUBJECT}' and any body."
        ),
        "tool_schema": {
            "type": "function",
            "function": {
                "name": "send_email",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["recipient", "subject", "body"],
                },
            },
        },
        "expected": {"recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT},
        "check_keys": ["recipient", "subject"],
    },
    {
        "tool_name": "read_file",
        "prompt": f"Read the file {CANARY_FILE_PATH}",
        "tool_schema": {
            "type": "function",
            "function": {
                "name": "read_file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                },
            },
        },
        "expected": {"path": CANARY_FILE_PATH},
        "check_keys": ["path"],
    },
]


def _values_match(key: str, actual: Any, expected: Any) -> bool:
    """Compare argument values, using tolerance for floats."""
    if isinstance(expected, float) or isinstance(actual, float):
        try:
            return abs(float(actual) - float(expected)) < AMOUNT_TOLERANCE
        except (TypeError, ValueError):
            return False
    return actual == expected


def _check_args(
    args: dict[str, Any],
    expected: dict[str, Any],
    check_keys: list[str],
) -> list[str]:
    """Return list of tampered key descriptions; empty list means all match."""
    tampered = []
    for key in check_keys:
        actual = args.get(key)
        if not _values_match(key, actual, expected[key]):
            tampered.append(f"{key}: expected={expected[key]!r}, got={actual!r}")
    return tampered


@detector
class D45_ToolCallArgVerifier(BaseDetector):
    detector_id = "D45"
    detector_name = "ToolCallArgVerifier"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect router tampering with tool-call argument values (address, amount, path, recipient)"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send three tool-call probes covering address, email, and file-path arguments."""
        responses = []
        for probe in _PROBES:
            resp = await self.client.send(ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "temperature": 0,
                    "tool_choice": {
                        "type": "function",
                        "function": {"name": probe["tool_name"]},
                    },
                    "messages": [{"role": "user", "content": probe["prompt"]}],
                    "tools": [probe["tool_schema"]],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"tool-call arg probe: {probe['tool_name']}",
            ))
            responses.append(resp)
        return responses

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Verify each probe's tool-call arguments match the canary values exactly."""
        all_tampered: list[str] = []
        probe_evidence: list[dict[str, Any]] = []

        for resp, probe in zip(responses, _PROBES):
            tool_name = probe["tool_name"]

            if resp.is_network_error:
                return self._inconclusive(f"{tool_name}: {resp.error}")

            if resp.status_code != 200:
                return self._inconclusive(f"{tool_name}: status {resp.status_code}")

            tool_calls = resp.tool_calls
            if not tool_calls:
                return self._inconclusive(f"{tool_name}: no tool calls in response")

            tc = tool_calls[0]
            args_str = tc.get("function", {}).get("arguments", "{}")
            try:
                args = json.loads(args_str)
            except (json.JSONDecodeError, TypeError):
                return self._inconclusive(f"{tool_name}: could not parse arguments JSON")

            tampered = _check_args(args, probe["expected"], probe["check_keys"])
            probe_evidence.append({
                "tool": tool_name,
                "args": args,
                "tampered": tampered,
            })
            all_tampered.extend(tampered)

        if all_tampered:
            return self._fail(
                "tool call arguments tampered",
                {
                    "tampered_fields": all_tampered,
                    "probes": probe_evidence,
                },
            )

        return self._pass({"probes": probe_evidence})

    @classmethod
    def _test_cases(cls):
        def make_tool_resp(tool_name: str, args: dict[str, Any]) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {
                            "content": None,
                            "tool_calls": [{
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": json.dumps(args),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            )

        # All three probes pass with exact canary values
        pass_responses = [
            make_tool_resp("transfer", {
                "to": CANARY_ETH_ADDRESS, "amount": 0.001, "token": "ETH",
            }),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hello.",
            }),
            make_tool_resp("read_file", {"path": CANARY_FILE_PATH}),
        ]

        # ETH address tampered
        tampered_address_responses = [
            make_tool_resp("transfer", {
                "to": "0xATTACKER_WALLET_ADDRESS", "amount": 0.001, "token": "ETH",
            }),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hello.",
            }),
            make_tool_resp("read_file", {"path": CANARY_FILE_PATH}),
        ]

        # Amount tampered
        tampered_amount_responses = [
            make_tool_resp("transfer", {
                "to": CANARY_ETH_ADDRESS, "amount": 1.5, "token": "ETH",
            }),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hi.",
            }),
            make_tool_resp("read_file", {"path": CANARY_FILE_PATH}),
        ]

        # File path tampered
        tampered_path_responses = [
            make_tool_resp("transfer", {
                "to": CANARY_ETH_ADDRESS, "amount": 0.001, "token": "ETH",
            }),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hi.",
            }),
            make_tool_resp("read_file", {"path": "/etc/passwd"}),
        ]

        # Network error on first probe
        network_error_responses = [
            ProbeResponse(status_code=0, error="TIMEOUT"),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hi.",
            }),
            make_tool_resp("read_file", {"path": CANARY_FILE_PATH}),
        ]

        # No tool calls returned
        no_tool_calls_responses = [
            ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "I cannot transfer funds."}, "finish_reason": "stop"}]},
            ),
            make_tool_resp("send_email", {
                "recipient": CANARY_EMAIL, "subject": CANARY_SUBJECT, "body": "Hi.",
            }),
            make_tool_resp("read_file", {"path": CANARY_FILE_PATH}),
        ]

        return [
            ("PASS: all canary values intact", pass_responses, "pass"),
            ("FAIL: ETH address tampered", tampered_address_responses, "fail"),
            ("FAIL: amount tampered", tampered_amount_responses, "fail"),
            ("FAIL: file path tampered", tampered_path_responses, "fail"),
            ("INCONCLUSIVE: network error on first probe", network_error_responses, "inconclusive"),
            ("INCONCLUSIVE: no tool calls returned", no_tool_calls_responses, "inconclusive"),
        ]


if __name__ == "__main__":
    D45_ToolCallArgVerifier.self_test()
