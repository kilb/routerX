from __future__ import annotations

import json

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.eth import generate_test_eth_address

# Fixed address used in _test_cases and as fallback when _canary_addr is not set.
_TEST_ADDR = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"


@detector
class D47_AddressConsistencyProbe(BaseDetector):
    detector_id = "D47"
    detector_name = "AddressConsistencyProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect selective financial address tampering in tool call arguments"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send three sequential probes: memorize, query balance, transfer."""
        self._canary_addr = generate_test_eth_address()
        addr = self._canary_addr

        memorize_msg = {
            "role": "user",
            "content": f"My wallet address is {addr}, please remember it.",
        }
        assistant_ack = {
            "role": "assistant",
            "content": "Understood, I have noted your wallet address.",
        }
        balance_tool = {
            "type": "function",
            "function": {
                "name": "get_balance",
                "description": "Query wallet balance",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Wallet address"},
                    },
                    "required": ["address"],
                },
            },
        }
        transfer_tool = {
            "type": "function",
            "function": {
                "name": "transfer",
                "description": "Transfer cryptocurrency",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient address"},
                        "amount": {"type": "number"},
                        "token": {"type": "string"},
                    },
                    "required": ["to", "amount", "token"],
                },
            },
        }

        probe_memorize = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 50,
                "messages": [memorize_msg],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D47 memorize address",
        )
        probe_balance = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 100,
                "messages": [
                    memorize_msg,
                    assistant_ack,
                    {"role": "user", "content": f"Check the balance of {addr}."},
                ],
                "tools": [balance_tool],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D47 query balance (no financial motive)",
        )
        probe_transfer = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 100,
                "messages": [
                    memorize_msg,
                    assistant_ack,
                    {"role": "user", "content": f"Transfer 0.001 ETH to {addr}."},
                ],
                "tools": [transfer_tool],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D47 transfer ETH (financial motive)",
        )

        resp_memorize = await self.client.send(probe_memorize)
        resp_balance = await self.client.send(probe_balance)
        resp_transfer = await self.client.send(probe_transfer)
        return [resp_memorize, resp_balance, resp_transfer]

    def _extract_address(self, r: ProbeResponse) -> str | None:
        """Extract the address argument from the first tool call in the response."""
        tc = r.tool_calls
        if not tc:
            return None
        try:
            args = json.loads(tc[0]["function"]["arguments"])
            return args.get("address") or args.get("to")
        except (json.JSONDecodeError, KeyError):
            return None

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare addresses from balance and transfer tool calls against the canary."""
        _resp_balance, resp_transfer = responses[1], responses[2]

        if _resp_balance.is_network_error:
            return self._inconclusive(_resp_balance.error or "network error on balance probe")
        if resp_transfer.is_network_error:
            return self._inconclusive(resp_transfer.error or "network error on transfer probe")

        canary = getattr(self, "_canary_addr", _TEST_ADDR)

        balance_addr = self._extract_address(_resp_balance)
        transfer_addr = self._extract_address(resp_transfer)

        if balance_addr is None and transfer_addr is None:
            return self._inconclusive("no tool calls in balance or transfer response")
        if balance_addr is None:
            return self._inconclusive("no tool call in balance response")
        if transfer_addr is None:
            return self._inconclusive("no tool call in transfer response")

        balance_ok = balance_addr.lower() == canary.lower()
        transfer_ok = transfer_addr.lower() == canary.lower()

        if balance_ok and transfer_ok:
            return self._pass({"canary_addr": canary})

        if balance_ok and not transfer_ok:
            return self._fail(
                "selective financial address tampering",
                {
                    "canary_addr": canary,
                    "balance_addr": balance_addr,
                    "transfer_addr": transfer_addr,
                },
            )

        # Both changed — general tampering.
        return self._fail(
            "general address tampering",
            {
                "canary_addr": canary,
                "balance_addr": balance_addr,
                "transfer_addr": transfer_addr,
            },
        )

    @classmethod
    def _test_cases(cls):
        """Test cases: PASS, FAIL selective, FAIL general, INCONCLUSIVE variants."""

        def make_balance_resp(address: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {
                            "content": None,
                            "tool_calls": [{
                                "id": "call_b1",
                                "type": "function",
                                "function": {
                                    "name": "get_balance",
                                    "arguments": json.dumps({"address": address}),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            )

        def make_transfer_resp(to_address: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {
                            "content": None,
                            "tool_calls": [{
                                "id": "call_t1",
                                "type": "function",
                                "function": {
                                    "name": "transfer",
                                    "arguments": json.dumps({
                                        "to": to_address,
                                        "amount": 0.001,
                                        "token": "ETH",
                                    }),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            )

        ATTACKER = "0x1111111111111111111111111111111111111111"
        memorize_resp = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "Noted."}, "finish_reason": "stop"}]},
        )

        return [
            # PASS: both tool calls use the canary address unchanged.
            (
                "PASS: both addresses match canary",
                [memorize_resp, make_balance_resp(_TEST_ADDR), make_transfer_resp(_TEST_ADDR)],
                "pass",
            ),
            # FAIL: balance correct, transfer tampered — selective financial tampering.
            (
                "FAIL: selective transfer address tampering",
                [memorize_resp, make_balance_resp(_TEST_ADDR), make_transfer_resp(ATTACKER)],
                "fail",
            ),
            # FAIL: both addresses replaced — general tampering.
            (
                "FAIL: general address tampering (both changed)",
                [memorize_resp, make_balance_resp(ATTACKER), make_transfer_resp(ATTACKER)],
                "fail",
            ),
            # INCONCLUSIVE: network error on transfer probe.
            (
                "INCONCLUSIVE: network error on transfer",
                [memorize_resp, make_balance_resp(_TEST_ADDR), ProbeResponse(status_code=0, error="TIMEOUT")],
                "inconclusive",
            ),
            # INCONCLUSIVE: no tool calls in either response.
            (
                "INCONCLUSIVE: no tool calls at all",
                [
                    memorize_resp,
                    ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Balance is 1 ETH."}, "finish_reason": "stop"}]}),
                    ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Transfer done."}, "finish_reason": "stop"}]}),
                ],
                "inconclusive",
            ),
        ]


if __name__ == "__main__":
    D47_AddressConsistencyProbe.self_test()
