"""D102 FunctionSchemaFidelity -- verify nested tool schemas are preserved.

Provides a deeply nested tool schema (customer.address, items[].sku) and
forces the model to call it.  If the router flattens nested schemas to
reduce token cost, the returned arguments will lack nesting depth.
"""
from __future__ import annotations

import json

from ..models import (
    Capability,
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_TOOL = {
    "type": "function",
    "function": {
        "name": "create_order",
        "description": "Create a product order",
        "parameters": {
            "type": "object",
            "properties": {
                "customer": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {
                            "type": "object",
                            "properties": {
                                "street": {"type": "string"},
                                "city": {"type": "string"},
                                "zip": {"type": "string"},
                            },
                            "required": ["street", "city"],
                        },
                    },
                    "required": ["name", "address"],
                },
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sku": {"type": "string"},
                            "quantity": {"type": "integer"},
                        },
                        "required": ["sku", "quantity"],
                    },
                },
            },
            "required": ["customer", "items"],
        },
    },
}


@detector
class D102_FunctionSchemaFidelity(BaseDetector):
    detector_id = "D102"
    detector_name = "FunctionSchemaFidelity"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.TOOL_CALLING,)
    description = "Detect flattening of nested tool call schemas"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 300,
                "tools": [_TOOL],
                "tool_choice": {
                    "type": "function",
                    "function": {"name": "create_order"},
                },
                "messages": [{
                    "role": "user",
                    "content": (
                        "Create an order for Alice at 123 Main St, "
                        "Springfield, zip 62701. "
                        "Order 2 units of SKU-A100."
                    ),
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D102 nested schema probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        calls = r.tool_calls
        if not calls:
            content = r.content or ""
            # Empty/very short content + no tool_calls = model may not
            # support forced tool_choice (preview models, etc.)
            if len(content.strip()) < 10:
                return self._skip(
                    "no tool_calls and empty content -- model may not "
                    "support forced tool_choice"
                )
            return self._fail(
                "no tool_calls returned despite forced tool_choice",
                {"content_preview": content[:200]},
            )

        # Parse arguments from first tool call
        raw_args = calls[0].get("function", {}).get("arguments", "")
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except (json.JSONDecodeError, TypeError):
            return self._fail(
                "tool_call arguments are not valid JSON",
                {"raw_arguments": str(raw_args)[:300]},
            )

        evidence = {"parsed_args": _truncate_dict(args)}

        # Check nested customer.address.street
        customer = args.get("customer")
        if not isinstance(customer, dict):
            return self._fail(
                "customer field is not a nested object -- schema flattened",
                evidence,
            )

        address = customer.get("address")
        if not isinstance(address, dict):
            return self._fail(
                "customer.address is not a nested object -- schema flattened",
                evidence,
            )

        if "street" not in address:
            return self._fail(
                "customer.address.street missing -- nested fields lost",
                evidence,
            )

        # Check items is an array with nested objects
        items = args.get("items")
        if not isinstance(items, list) or not items:
            return self._fail(
                "items field is not a non-empty array -- schema flattened",
                evidence,
            )

        first_item = items[0]
        if not isinstance(first_item, dict) or "sku" not in first_item:
            return self._fail(
                "items[0].sku missing -- array item schema lost",
                evidence,
            )

        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _tool_resp(args_dict: dict) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{
                    "message": {
                        "content": None,
                        "tool_calls": [{
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "create_order",
                                "arguments": json.dumps(args_dict),
                            },
                        }],
                    },
                    "finish_reason": "tool_calls",
                }]},
            )

        good_args = {
            "customer": {
                "name": "Alice",
                "address": {
                    "street": "123 Main St",
                    "city": "Springfield",
                    "zip": "62701",
                },
            },
            "items": [{"sku": "SKU-A100", "quantity": 2}],
        }
        flat_args = {
            "name": "Alice",
            "street": "123 Main St",
            "sku": "SKU-A100",
            "quantity": 2,
        }
        no_call = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "I'll create that order."}, "finish_reason": "stop"}]},
        )

        return [
            ("PASS: full nested structure", [_tool_resp(good_args)], "pass"),
            ("FAIL: flattened args", [_tool_resp(flat_args)], "fail"),
            ("FAIL: no tool call", [no_call], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
        ]


def _truncate_dict(d: dict, max_str: int = 80) -> dict:
    """Truncate string values in a dict for evidence display."""
    out = {}
    for k, v in d.items():
        if isinstance(v, str) and len(v) > max_str:
            out[k] = v[:max_str] + "..."
        elif isinstance(v, dict):
            out[k] = _truncate_dict(v, max_str)
        elif isinstance(v, list):
            out[k] = v[:5]
        else:
            out[k] = v
    return out


if __name__ == "__main__":
    D102_FunctionSchemaFidelity.self_test()
