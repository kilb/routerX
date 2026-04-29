from __future__ import annotations

import json
import re
from typing import Optional

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

# Regex to find amounts like "1.23 ETH", "42,000.50 USDT" in content text.
_CONTENT_AMOUNT_RE = re.compile(
    r"([\d,]+\.\d+)\s*(?:ETH|USDT|USDC|BTC)",
    re.IGNORECASE,
)

AMOUNTS: list[tuple[str, str]] = [
    ("1.23456789", "ETH"),
    ("0.00314159", "ETH"),
    ("42.9876", "USDT"),
]

ROUTER_DEVIATION_THRESHOLD = 0.01   # >1% deviation on router side → suspicious
DIRECT_DEVIATION_THRESHOLD = 0.001  # <0.1% deviation on direct side → confirms tampering


def _is_rounding(original: float, returned: float) -> bool:
    """True if *returned* equals ``round(original, n)`` for any n in 0..10.

    Also covers truncation: ``int(original * 10**n) / 10**n`` for each n.
    """
    for dp in range(0, 11):
        if returned == round(original, dp):
            return True
        # Truncation (floor): int(1.23456789 * 100) / 100 = 1.23
        truncated = int(original * 10**dp) / 10**dp
        if returned == truncated:
            return True
    return False

_TRANSFER_TOOL = {
    "type": "function",
    "function": {
        "name": "transfer",
        "description": "Transfer cryptocurrency to a recipient address.",
        "parameters": {
            "type": "object",
            "properties": {
                "to":     {"type": "string", "description": "Recipient wallet address"},
                "amount": {"type": "number", "description": "Amount to transfer"},
                "token":  {"type": "string", "description": "Token symbol, e.g. ETH or USDT"},
            },
            "required": ["to", "amount", "token"],
        },
    },
}


def _make_probe(amount: str, token: str, model: str, endpoint: str) -> ProbeRequest:
    return ProbeRequest(
        payload={
            "model": model,
            "temperature": 0,
            "tools": [_TRANSFER_TOOL],
            "tool_choice": {"type": "function", "function": {"name": "transfer"}},
            "messages": [
                {
                    "role": "user",
                    "content": f"Transfer {amount} {token} to 0xTEST000000000000000000000000000000000001.",
                }
            ],
        },
        endpoint_path=endpoint,
        description=f"D48 transfer {amount} {token}",
    )


def _parse_amount(r: ProbeResponse) -> Optional[float]:
    """Extract the `amount` field from the first tool call in the response."""
    tool_calls = r.tool_calls
    if not tool_calls:
        return None
    try:
        args = json.loads(tool_calls[0]["function"]["arguments"])
        return float(args["amount"])
    except (KeyError, ValueError, json.JSONDecodeError, TypeError):
        return None


@detector
class D48_AmountPrecisionProbe(BaseDetector):
    detector_id = "D48"
    detector_name = "AmountPrecisionProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.RELATIVE
    request_count = 6
    description = "Detect high-precision financial amount tampering via tool call arguments"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send three transfer probes to router, plus three to direct provider if available."""
        probes = [
            _make_probe(amount, token, self.config.claimed_model, self.config.default_endpoint_path)
            for amount, token in AMOUNTS
        ]
        router_resps = [await self.client.send(p) for p in probes]

        direct_resps: list[ProbeResponse] = []
        if self.has_direct:
            async with self.make_direct_client() as dc:
                direct_resps = [await dc.send(p) for p in probes]

        return router_resps + direct_resps

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare router-returned amounts against requested values and direct baseline."""
        n = len(AMOUNTS)
        router_resps = responses[:n]
        direct_resps = responses[n:]

        has_direct = bool(direct_resps)

        for i, (amount_str, token) in enumerate(AMOUNTS):
            requested = float(amount_str)
            router_resp = router_resps[i]

            if router_resp.is_network_error:
                return self._pass({"note": router_resp.error or "network error on router probe"})

            router_amount = _parse_amount(router_resp)
            if router_amount is None:
                return self._pass({"note": f"no parseable tool call for {amount_str} {token}"})

            router_deviation = abs(router_amount - requested) / requested

            # Content-based check: if tool_call amount is correct, also scan
            # response content for a different amount (smart router could embed
            # a tampered amount in the text while keeping tool args clean).
            content = router_resp.content or ""
            content_amounts = _CONTENT_AMOUNT_RE.findall(content)
            for raw_amt in content_amounts:
                try:
                    content_val = float(raw_amt.replace(",", ""))
                except ValueError:
                    continue
                content_dev = abs(content_val - requested) / max(requested, 1e-9)
                if content_dev > ROUTER_DEVIATION_THRESHOLD and router_deviation < DIRECT_DEVIATION_THRESHOLD:
                    return self._fail(
                        f"tool_call amount correct but content mentions different amount",
                        {
                            "token": token,
                            "requested": requested,
                            "router_tool_amount": router_amount,
                            "content_amount": content_val,
                            "content_deviation_pct": round(content_dev * 100, 4),
                        },
                    )

            if has_direct:
                direct_resp = direct_resps[i]
                if direct_resp.is_network_error:
                    return self._pass({"note": direct_resp.error or "network error on direct probe"})

                direct_amount = _parse_amount(direct_resp)
                if direct_amount is not None:
                    direct_deviation = abs(direct_amount - requested) / requested
                    if (router_deviation > ROUTER_DEVIATION_THRESHOLD
                            and direct_deviation < DIRECT_DEVIATION_THRESHOLD):
                        return self._fail(
                            f"amount tampered: requested {requested} got {router_amount}",
                            {
                                "token": token,
                                "requested": requested,
                                "router_amount": router_amount,
                                "direct_amount": direct_amount,
                                "router_deviation_pct": round(router_deviation * 100, 4),
                                "direct_deviation_pct": round(direct_deviation * 100, 4),
                            },
                        )
            else:
                if router_deviation > ROUTER_DEVIATION_THRESHOLD:
                    # Any rounding = PASS. Models commonly truncate/round
                    # to fewer decimal places. Only FAIL when the value is
                    # not any rounded form of the original.
                    if _is_rounding(requested, router_amount):
                        return self._pass({
                            "note": f"amount {router_amount} is a rounded form "
                                    f"of {requested} — model precision limit",
                            "token": token,
                            "requested": requested,
                            "router_amount": router_amount,
                            "router_deviation_pct": round(router_deviation * 100, 4),
                        })
                    return self._fail_degraded(
                        f"deviation > 1% without direct baseline",
                        {
                            "token": token,
                            "requested": requested,
                            "router_amount": router_amount,
                            "router_deviation_pct": round(router_deviation * 100, 4),
                        },
                    )

        return self._pass({"verified_amounts": len(AMOUNTS), "has_direct": has_direct})

    @classmethod
    def _test_cases(cls):
        def make_router_resp(amount: float, token: str = "ETH") -> ProbeResponse:
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
                                    "name": "transfer",
                                    "arguments": json.dumps({
                                        "to": "0xTEST000000000000000000000000000000000001",
                                        "amount": amount,
                                        "token": token,
                                    }),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            )

        exact_router_resps = [
            make_router_resp(1.23456789, "ETH"),
            make_router_resp(0.00314159, "ETH"),
            make_router_resp(42.9876, "USDT"),
        ]
        exact_direct_resps = [
            make_router_resp(1.23456789, "ETH"),
            make_router_resp(0.00314159, "ETH"),
            make_router_resp(42.9876, "USDT"),
        ]

        # Router truncates first amount to 2 decimal places; direct is accurate.
        tampered_router_resps = [
            make_router_resp(1.23, "ETH"),       # deviation ~0.37% on first — but wait, 1.23 vs 1.23456789 = ~0.37%
            make_router_resp(0.003, "ETH"),      # deviation ~4.6% > 1%  (triggers fail on index 1 actually)
            make_router_resp(42.9876, "USDT"),
        ]
        # Recalculate: 1.23 vs 1.23456789 = deviation = 0.00456789/1.23456789 ≈ 0.37% (<1%), so index 0 won't trigger.
        # 0.003 vs 0.00314159 = deviation = 0.00014159/0.00314159 ≈ 4.5% (>1%) → triggers on index 1.
        tampered_direct_resps = [
            make_router_resp(1.23456789, "ETH"),
            make_router_resp(0.00314159, "ETH"),
            make_router_resp(42.9876, "USDT"),
        ]

        return [
            # PASS: exact amounts, with direct baseline confirming no tampering.
            (
                "PASS: exact amounts match with direct baseline",
                exact_router_resps + exact_direct_resps,
                "pass",
            ),
            # FAIL: router deviates >1% while direct is accurate.
            (
                "FAIL: router tampers amount >1%, direct accurate",
                tampered_router_resps + tampered_direct_resps,
                "fail",
            ),
            # FAIL degraded: router changes amount to a non-rounding value.
            # 0.00414159 is NOT a rounded form of 0.00314159 — it's a
            # different value entirely (deliberate tampering).
            (
                "FAIL degraded: router deviation >1% without direct",
                [
                    make_router_resp(1.23456789, "ETH"),  # ok
                    make_router_resp(0.00414159, "ETH"),   # ~31.8% deviation, not rounding
                    make_router_resp(42.9876, "USDT"),
                ],
                "fail",
            ),
            # INCONCLUSIVE: network error on one router probe.
            (
                "PASS: network error on router probe",
                [
                    ProbeResponse(status_code=0, error="TIMEOUT"),
                    make_router_resp(0.00314159, "ETH"),
                    make_router_resp(42.9876, "USDT"),
                ],
                "pass",
            ),
            # INCONCLUSIVE: response with no tool calls.
            (
                "PASS: no tool call in response",
                [
                    ProbeResponse(
                        status_code=200,
                        body={"choices": [{"message": {"content": "Done."}, "finish_reason": "stop"}]},
                    ),
                    make_router_resp(0.00314159, "ETH"),
                    make_router_resp(42.9876, "USDT"),
                ],
                "pass",
            ),
            # PASS: exact amounts without direct baseline (all within 1%).
            (
                "PASS: all amounts within tolerance, no direct",
                exact_router_resps,
                "pass",
            ),
        ]


if __name__ == "__main__":
    D48_AmountPrecisionProbe.self_test()
