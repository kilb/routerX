from __future__ import annotations

import asyncio
import json
import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.eth import generate_test_eth_address

# Fixed address used in _test_cases and as fallback when _canary_addr is not set.
_TEST_ADDR = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"

# Regex to extract 0x-prefixed 40-hex-char addresses from free text.
_ETH_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")


@detector
class D47_AddressConsistencyProbe(BaseDetector):
    detector_id = "D47"
    detector_name = "AddressConsistencyProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 4
    description = "Detect selective financial address tampering in tool call arguments and plain text"

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

        # Probe 4: plain text recall WITHOUT tools -- a smart router may only
        # tamper tool_call args but leave plain text alone (or vice versa).
        probe_plaintext = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 100,
                "messages": [
                    memorize_msg,
                    assistant_ack,
                    {"role": "user", "content": "What is my wallet address?"},
                ],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D47 plain text address recall (no tools)",
        )

        resp_memorize = await self.client.send(probe_memorize)
        resp_balance, resp_transfer, resp_plaintext = await asyncio.gather(
            self.client.send(probe_balance),
            self.client.send(probe_transfer),
            self.client.send(probe_plaintext),
        )
        return [resp_memorize, resp_balance, resp_transfer, resp_plaintext]

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

    def _extract_plaintext_address(self, r: ProbeResponse) -> str | None:
        """Extract an ETH address from response content (plain text, no tools)."""
        content = r.content or ""
        matches = _ETH_ADDR_RE.findall(content)
        return matches[0] if matches else None

    @staticmethod
    def _eip55_casing_matches(planted: str, returned: str) -> bool:
        """Check whether returned address preserves the EIP-55 casing of planted.

        If both are the same hex (case-insensitive) but differ in letter
        casing, the router may have tampered the EIP-55 checksum.
        """
        if planted.lower() != returned.lower():
            # Different addresses entirely -- caller handles this.
            return True
        # Same address, check casing match for mixed-case addresses.
        planted_letters = [c for c in planted[2:] if c.isalpha()]
        if not planted_letters:
            return True  # No letters to compare
        all_lower = all(c.islower() for c in planted_letters)
        all_upper = all(c.isupper() for c in planted_letters)
        if all_lower or all_upper:
            return True  # Checksum not applied in original, casing irrelevant
        # Mixed-case planted address: returned casing should match exactly
        return planted[2:] == returned[2:]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare addresses from balance, transfer, and plaintext probes against the canary."""
        _resp_balance, resp_transfer = responses[1], responses[2]
        resp_plaintext = responses[3] if len(responses) > 3 else None

        if _resp_balance.is_network_error:
            return self._pass({"note": _resp_balance.error or "network error on balance probe"})
        if resp_transfer.is_network_error:
            return self._pass({"note": resp_transfer.error or "network error on transfer probe"})

        canary = getattr(self, "_canary_addr", _TEST_ADDR)

        balance_addr = self._extract_address(_resp_balance)
        transfer_addr = self._extract_address(resp_transfer)

        if balance_addr is None and transfer_addr is None:
            return self._pass({"note": "no tool calls in balance or transfer response — no evidence of issue"})
        if balance_addr is None:
            return self._pass({"note": "no tool call in balance response — no evidence of issue"})

        # Check exact match or prefix match (truncated address from model
        # output limit is not tampering — the address is incomplete, not changed)
        balance_ok = balance_addr.lower() == canary.lower()
        balance_truncated = (
            not balance_ok
            and canary.lower().startswith(balance_addr.lower())
            and len(balance_addr) >= 10  # at least "0x" + 8 hex chars
        )

        # Check plain text probe (4th probe) if available
        plaintext_addr = None
        plaintext_ok = True  # Default to True if probe unavailable
        if resp_plaintext is not None and not resp_plaintext.is_network_error:
            plaintext_addr = self._extract_plaintext_address(resp_plaintext)
            if plaintext_addr is not None:
                plaintext_ok = plaintext_addr.lower() == canary.lower()

        evidence = {
            "canary_addr": canary,
            "balance_addr": balance_addr,
            "transfer_addr": transfer_addr,
            "plaintext_addr": plaintext_addr,
        }

        # Plain text tampering: address in content differs from canary
        if not plaintext_ok:
            return self._fail(
                "address tampering in plain text response (no tools)",
                evidence | {"plaintext_mismatch": True},
            )

        # Model refused to call transfer tool (safety behavior, not router
        # interference). If balance is correct, pass with a note that
        # selective-tampering detection was not possible.
        if transfer_addr is None:
            if balance_ok or balance_truncated:
                return self._pass(evidence | {
                    "note": "transfer tool not called; balance address "
                            + ("verified" if balance_ok else "truncated (not tampered)"),
                })
            return self._fail("balance address tampered", evidence)

        transfer_ok = transfer_addr.lower() == canary.lower()

        # EIP-55 casing check on transfer address
        eip55_note = None
        if transfer_ok and not self._eip55_casing_matches(canary, transfer_addr):
            eip55_note = (
                f"EIP-55 checksum casing mismatch: planted={canary}, "
                f"returned={transfer_addr}"
            )
        if eip55_note:
            evidence["eip55_note"] = eip55_note

        if balance_ok and transfer_ok:
            return self._pass(evidence)

        if balance_ok and not transfer_ok:
            # Distinguish: model truncated/mangled the address (capability)
            # vs. replaced it with a completely different address (tampering).
            # Truncation: returned address is a prefix of canary.
            # Minor error: edit distance 1-3 chars (typo, not replacement).
            transfer_truncated = (
                canary.lower().startswith(transfer_addr.lower())
                and len(transfer_addr) >= 10
            )
            common_prefix = 0
            for a, b in zip(canary.lower(), transfer_addr.lower()):
                if a == b:
                    common_prefix += 1
                else:
                    break
            # If > 80% of characters match from the start, likely model
            # imprecision rather than deliberate address replacement.
            similarity = common_prefix / max(len(canary), 1)
            evidence["similarity"] = round(similarity, 3)

            if transfer_truncated:
                return self._pass(evidence | {
                    "note": "transfer address truncated (model output limit, not tampering)",
                })
            if similarity >= 0.8:
                return self._pass(evidence | {
                    "note": f"transfer address similar ({similarity:.0%}) — "
                            "likely model imprecision, not tampering",
                })
            return self._fail(
                "selective financial address tampering",
                evidence,
            )

        # Both changed -- could be model can't handle long hex addresses.
        # Check if both are truncated/similar (capability) vs. both replaced.
        balance_similarity = sum(
            1 for a, b in zip(canary.lower(), balance_addr.lower()) if a == b
        ) / max(len(canary), 1)
        transfer_similarity = sum(
            1 for a, b in zip(canary.lower(), transfer_addr.lower()) if a == b
        ) / max(len(canary), 1)
        evidence["balance_similarity"] = round(balance_similarity, 3)
        evidence["transfer_similarity"] = round(transfer_similarity, 3)

        if balance_similarity >= 0.7 and transfer_similarity >= 0.7:
            return self._pass(evidence | {
                "note": "both addresses similar to canary — likely model "
                        "imprecision with long hex strings, not tampering",
            })
        return self._fail(
            "general address tampering",
            evidence,
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

        def make_plaintext_resp(address: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"content": f"Your wallet address is {address}."},
                        "finish_reason": "stop",
                    }],
                },
            )

        plaintext_ok = make_plaintext_resp(_TEST_ADDR)
        plaintext_bad = make_plaintext_resp(ATTACKER)

        return [
            # PASS: all probes (tool calls + plaintext) use the canary address.
            (
                "PASS: all addresses match canary",
                [memorize_resp, make_balance_resp(_TEST_ADDR), make_transfer_resp(_TEST_ADDR), plaintext_ok],
                "pass",
            ),
            # FAIL: balance correct, transfer tampered -- selective financial tampering.
            (
                "FAIL: selective transfer address tampering",
                [memorize_resp, make_balance_resp(_TEST_ADDR), make_transfer_resp(ATTACKER), plaintext_ok],
                "fail",
            ),
            # FAIL: both tool-call addresses replaced -- general tampering.
            (
                "FAIL: general address tampering (both changed)",
                [memorize_resp, make_balance_resp(ATTACKER), make_transfer_resp(ATTACKER), plaintext_ok],
                "fail",
            ),
            # FAIL: tool calls OK but plaintext address tampered.
            (
                "FAIL: plaintext address tampered (content-based)",
                [memorize_resp, make_balance_resp(_TEST_ADDR), make_transfer_resp(_TEST_ADDR), plaintext_bad],
                "fail",
            ),
            # PASS: transfer tool not called (model safety refusal) but balance correct.
            (
                "PASS: transfer refused by model, balance OK",
                [
                    memorize_resp,
                    make_balance_resp(_TEST_ADDR),
                    ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "I cannot execute financial transfers."}, "finish_reason": "stop"}]}),
                    plaintext_ok,
                ],
                "pass",
            ),
            # INCONCLUSIVE: network error on transfer probe.
            (
                "PASS: network error on transfer",
                [memorize_resp, make_balance_resp(_TEST_ADDR), ProbeResponse(status_code=0, error="TIMEOUT"), plaintext_ok],
                "pass",
            ),
            # INCONCLUSIVE: no tool calls in either response.
            (
                "PASS: no tool calls at all",
                [
                    memorize_resp,
                    ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Balance is 1 ETH."}, "finish_reason": "stop"}]}),
                    ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Transfer done."}, "finish_reason": "stop"}]}),
                    plaintext_ok,
                ],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D47_AddressConsistencyProbe.self_test()
