"""D45 ToolCallArgVerifier -- realistic financial tool-call integrity probes.

Replaces the original three canary-string probes (clearly test-labeled)
with five **realistic** scenarios whose prompts and tool schemas are
indistinguishable from real user requests. Each probe has ONE target
field the attacker would want to tamper, and chaff fields that a naive
attacker might overlook. The nonce values (addresses, amounts) are
generated per-run so a sophisticated router cannot memoize them.

Attack surfaces covered:
  1. EVM mainnet transfer via Foundry ``cast send``
  2. Uniswap v3 swap (token + recipient + slippage)
  3. Bitcoin Core ``bitcoin-cli sendtoaddress``
  4. Solana SPL token transfer
  5. Stripe Connect charge (destination account)

Any single tampering -> S0 FAIL.

Also scans response *content* (not just tool_call args) for suspicious
URL patterns -- a smart router could inject replacement URLs in plain text.
"""
from __future__ import annotations

import json
import re
import random
import string
from typing import Callable

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.eth import generate_test_eth_address


# --- per-run canary generators ----------------------------------------

def _rand_btc_bech32() -> str:
    """Generate a syntactically valid bech32-shaped P2WPKH address.

    Checksum validity is not required — we only need the router to
    preserve the exact string across transport.
    """
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return "bc1q" + "".join(random.choices(alphabet, k=38))


def _rand_sol_pubkey() -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "".join(random.choices(alphabet, k=44))


def _rand_stripe_acct() -> str:
    return "acct_" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=16)
    )


def _rand_amount(scale: float, precision: int = 8) -> str:
    low, high = scale * 0.1, scale * 10
    v = random.uniform(low, high)
    return f"{v:.{precision}f}"


# Known immutable mainnet contracts — a router that tampers these is
# rerouting funds through scam tokens.
USDC_ETH_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
WETH_ETH_MAINNET = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDC_SOL_MINT    = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


# --- tool schemas (real-looking) --------------------------------------

def _shell_tool(description: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": "exec_shell",
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "working_directory": {"type": "string"},
                },
                "required": ["command"],
            },
        },
    }


_TOOL_CAST_SEND     = _shell_tool("Execute a shell command in the user's local terminal.")
_TOOL_BITCOIN_CLI   = _shell_tool("Execute a shell command against the local bitcoin-cli node.")
_TOOL_SPL_TRANSFER  = _shell_tool("Execute a Solana CLI shell command.")

_TOOL_UNISWAP_SWAP = {
    "type": "function",
    "function": {
        "name": "uniswap_v3_swap",
        "description": "Execute a Uniswap v3 exactInputSingle swap.",
        "parameters": {
            "type": "object",
            "properties": {
                "tokenIn":     {"type": "string", "description": "ERC-20 contract (hex)"},
                "tokenOut":    {"type": "string", "description": "ERC-20 contract (hex)"},
                "amountIn":    {"type": "string"},
                "recipient":   {"type": "string", "description": "EOA or smart-contract wallet"},
                "slippageBps": {"type": "integer", "description": "slippage in basis points"},
                "deadline":    {"type": "integer"},
            },
            "required": ["tokenIn", "tokenOut", "amountIn", "recipient", "slippageBps"],
        },
    },
}

_TOOL_STRIPE_CHARGE = {
    "type": "function",
    "function": {
        "name": "stripe_create_charge",
        "description": "Create a charge against a Stripe customer.",
        "parameters": {
            "type": "object",
            "properties": {
                "customer":    {"type": "string", "description": "cus_xxx"},
                "amount":      {"type": "integer", "description": "in cents"},
                "currency":    {"type": "string"},
                "destination": {"type": "string", "description": "Stripe Connect acct_xxx"},
                "description": {"type": "string"},
            },
            "required": ["customer", "amount", "currency", "destination"],
        },
    },
}


# --- per-probe builder functions --------------------------------------

def _probe_cast_send(state: dict) -> dict:
    addr = generate_test_eth_address()
    amount = _rand_amount(0.05, 5)
    state["cast_addr"] = addr
    state["cast_amount"] = amount
    return {
        "tools": [_TOOL_CAST_SEND],
        "tool_choice": {"type": "function", "function": {"name": "exec_shell"}},
        "messages": [{
            "role": "user",
            "content": (
                f"Yesterday I promised Mike some ETH for splitting the Uber. "
                f"Send him {amount} ETH using Foundry's cast send on mainnet. "
                f"His address is {addr}. Use my PRIVATE_KEY env var. "
                f"RPC: https://eth.llamarpc.com"
            ),
        }],
        "temperature": 0,
    }


def _probe_uniswap(state: dict) -> dict:
    recipient = generate_test_eth_address()
    amount_in = _rand_amount(1.0, 4)
    state["uniswap_recipient"] = recipient
    state["uniswap_tokenOut"] = USDC_ETH_MAINNET
    state["uniswap_amountIn"] = amount_in
    state["uniswap_slippage"] = 30
    return {
        "tools": [_TOOL_UNISWAP_SWAP],
        "tool_choice": {"type": "function", "function": {"name": "uniswap_v3_swap"}},
        "messages": [{
            "role": "user",
            "content": (
                f"I want to swap {amount_in} WETH for USDC on Uniswap v3. "
                f"Send the USDC to {recipient}. Use 0.3% slippage. Deadline 20 minutes. "
                f"WETH: {WETH_ETH_MAINNET}, USDC: {USDC_ETH_MAINNET}."
            ),
        }],
        "temperature": 0,
    }


def _probe_bitcoin(state: dict) -> dict:
    addr = _rand_btc_bech32()
    amount = _rand_amount(0.01, 5)
    state["btc_addr"] = addr
    state["btc_amount"] = amount
    return {
        "tools": [_TOOL_BITCOIN_CLI],
        "tool_choice": {"type": "function", "function": {"name": "exec_shell"}},
        "messages": [{
            "role": "user",
            "content": (
                f"Use my local bitcoin-cli (Bitcoin Core v25) to send {amount} BTC "
                f"to {addr}. Fee rate should be 8 sat/vB -- the mempool is light today."
            ),
        }],
        "temperature": 0,
    }


def _probe_solana(state: dict) -> dict:
    recipient = _rand_sol_pubkey()
    amount = _rand_amount(50, 4)
    state["sol_recipient"] = recipient
    state["sol_amount"] = amount
    state["sol_mint"] = USDC_SOL_MINT
    return {
        "tools": [_TOOL_SPL_TRANSFER],
        "tool_choice": {"type": "function", "function": {"name": "exec_shell"}},
        "messages": [{
            "role": "user",
            "content": (
                f"Transfer {amount} USDC on Solana to {recipient} using the "
                f"spl-token CLI. USDC mint is {USDC_SOL_MINT}. "
                f"Use my current `solana config` keypair."
            ),
        }],
        "temperature": 0,
    }


def _probe_stripe(state: dict) -> dict:
    acct = _rand_stripe_acct()
    customer = "cus_" + "".join(
        random.choices(string.ascii_letters + string.digits, k=14)
    )
    amount_cents = random.randint(5000, 50000)
    state["stripe_destination"] = acct
    state["stripe_amount"] = amount_cents
    state["stripe_customer"] = customer
    return {
        "tools": [_TOOL_STRIPE_CHARGE],
        "tool_choice": {"type": "function", "function": {"name": "stripe_create_charge"}},
        "messages": [{
            "role": "user",
            "content": (
                f"Charge customer {customer} ${amount_cents/100:.2f} USD for their "
                f"latest order. Route the payout via Stripe Connect to our "
                f"marketplace seller account {acct}."
            ),
        }],
        "temperature": 0,
    }


# Suspicious URL patterns that indicate content-level tampering.
# A smart router may leave tool_call args intact but inject malicious URLs
# in the response content text.
_SUSPICIOUS_URL_PATTERNS: list[str] = [
    "evil.io", "attacker.com", "malicious.xyz", "scam-wallet.com",
    "drainer.io", "phish.me", "steal.eth", "fake-rpc.com",
    "hijack.dev", "rogue-api.net",
]
_SUSPICIOUS_URL_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in _SUSPICIOUS_URL_PATTERNS) + r")\b",
    re.IGNORECASE,
)


_PROBES: list[tuple[str, Callable[[dict], dict]]] = [
    ("cast_send",   _probe_cast_send),
    ("uniswap",     _probe_uniswap),
    ("bitcoin",     _probe_bitcoin),
    ("solana",      _probe_solana),
    ("stripe",      _probe_stripe),
]


@detector
class D45_ToolCallArgVerifier(BaseDetector):
    detector_id = "D45"
    detector_name = "ToolCallArgVerifier"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = len(_PROBES)
    detector_timeout = 90.0  # Claude Opus + tool_choice is slow; was 30.0
    description = (
        "Detect tampering of realistic financial tool-call arguments "
        "(EVM/Uniswap/Bitcoin/Solana/Stripe)."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        self._state: dict = {}
        probes = []
        for name, builder in _PROBES:
            p = builder(self._state)
            p["model"] = self.config.claimed_model
            probes.append(ProbeRequest(
                payload=p,
                endpoint_path=self.config.default_endpoint_path,
                description=f"D45 {name}",
            ))
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        state = getattr(self, "_state", {})
        tampered: list[dict] = []
        inconclusive_probes: list[str] = []

        for (name, _builder), resp in zip(_PROBES, responses):
            if resp.is_network_error:
                return self._inconclusive(f"{name}: {resp.error}")
            check = _JUDGES[name](resp, state)
            if check is None:
                # Tool-call args OK -- also scan content for suspicious URLs
                content = resp.content or ""
                url_match = _SUSPICIOUS_URL_RE.search(content)
                if url_match:
                    tampered.append({
                        "probe": name,
                        "field": "content_url",
                        "reason": "suspicious URL in response content",
                        "matched": url_match.group(0),
                        "content_snippet": content[:200],
                    })
                continue
            if check.get("inconclusive"):
                inconclusive_probes.append(
                    f"{name}: {check.get('reason', 'parse failure')}"
                )
                continue
            tampered.append({"probe": name, **check})

        if tampered:
            return self._fail(
                f"{len(tampered)}/{len(_PROBES)} probes show argument tampering",
                {"tampered": tampered, "inconclusive_probes": inconclusive_probes},
            )
        # All probes either passed or were inconclusive. If every probe
        # was inconclusive, surface that rather than a false PASS.
        if len(inconclusive_probes) == len(_PROBES):
            return self._inconclusive(
                f"all {len(_PROBES)} probes unparseable: {inconclusive_probes}"
            )
        return self._pass({
            "verified_probes": [
                n for (n, _), _ in zip(_PROBES, responses)
                if n not in {p.split(":")[0] for p in inconclusive_probes}
            ],
            "inconclusive_probes": inconclusive_probes,
        })

    @classmethod
    def _test_cases(cls):
        clean_cast = _mk_tool_resp("exec_shell", {
            "command": (
                "cast send 0xABCDEF0123456789ABCDEF0123456789ABCDEF01 "
                "--value 0.05ether --rpc-url https://eth.llamarpc.com"
            ),
        })
        clean_uni = _mk_tool_resp("uniswap_v3_swap", {
            "tokenIn": WETH_ETH_MAINNET, "tokenOut": USDC_ETH_MAINNET,
            "amountIn": "1.5",
            "recipient": "0x1234567890123456789012345678901234567890",
            "slippageBps": 30, "deadline": 1700000000,
        })
        clean_btc = _mk_tool_resp("exec_shell", {
            "command": (
                "bitcoin-cli sendtoaddress "
                "bc1qtest111111111111111111111111111111111111 0.01"
            ),
        })
        clean_sol = _mk_tool_resp("exec_shell", {
            "command": (
                f"spl-token transfer {USDC_SOL_MINT} 50 "
                "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK"
            ),
        })
        clean_stripe = _mk_tool_resp("stripe_create_charge", {
            "customer": "cus_test", "amount": 5000, "currency": "usd",
            "destination": "acct_test1234567890ab",
        })
        state_pass = {
            "cast_addr":         "0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "cast_amount":       "0.05",
            "uniswap_recipient": "0x1234567890123456789012345678901234567890",
            "uniswap_tokenOut":  USDC_ETH_MAINNET,
            "uniswap_amountIn":  "1.5",
            "uniswap_slippage":  30,
            "btc_addr":          "bc1qtest111111111111111111111111111111111111",
            "btc_amount":        "0.01",
            "sol_recipient":     "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK",
            "sol_amount":        "50",
            "sol_mint":          USDC_SOL_MINT,
            "stripe_destination": "acct_test1234567890ab",
            "stripe_amount":     5000,
            "stripe_customer":   "cus_test",
        }

        return [
            ("PASS: all canonical", None, "pass", state_pass,
             [clean_cast, clean_uni, clean_btc, clean_sol, clean_stripe]),
            ("FAIL: cast_send address swapped", None, "fail", state_pass,
             [
                 _mk_tool_resp("exec_shell", {"command":
                     "cast send 0xDeadBeefCafe00000000000000000000DeadBeef "
                     "--value 0.05ether"}),
                 clean_uni, clean_btc, clean_sol, clean_stripe,
             ]),
            ("FAIL: uniswap tokenOut swapped (scam USDC)", None, "fail", state_pass,
             [
                 clean_cast,
                 _mk_tool_resp("uniswap_v3_swap", {
                     "tokenIn": WETH_ETH_MAINNET,
                     "tokenOut": "0xDEADBEEF00000000000000000000000000000001",
                     "amountIn": "1.5",
                     "recipient": "0x1234567890123456789012345678901234567890",
                     "slippageBps": 30, "deadline": 1700000000,
                 }),
                 clean_btc, clean_sol, clean_stripe,
             ]),
            ("FAIL: uniswap recipient swapped", None, "fail", state_pass,
             [clean_cast,
              _mk_tool_resp("uniswap_v3_swap", {
                  "tokenIn": WETH_ETH_MAINNET, "tokenOut": USDC_ETH_MAINNET,
                  "amountIn": "1.5",
                  "recipient": "0xATTACKER000000000000000000000000000000001",
                  "slippageBps": 30, "deadline": 1700000000,
              }),
              clean_btc, clean_sol, clean_stripe]),
            ("FAIL: solana recipient swapped", None, "fail", state_pass,
             [clean_cast, clean_uni, clean_btc,
              _mk_tool_resp("exec_shell", {
                  "command": (
                      f"spl-token transfer {USDC_SOL_MINT} 50 "
                      "ATTACKERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                  ),
              }),
              clean_stripe]),
            ("FAIL: stripe destination replaced", None, "fail", state_pass,
             [clean_cast, clean_uni, clean_btc, clean_sol,
              _mk_tool_resp("stripe_create_charge", {
                  "customer": "cus_test", "amount": 5000, "currency": "usd",
                  "destination": "acct_attackerxxxxxxx",
              })]),
            ("INCONCLUSIVE: network error on probe 1", None, "inconclusive", state_pass,
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              clean_uni, clean_btc, clean_sol, clean_stripe]),
            ("INCONCLUSIVE: all probes unparseable", None, "inconclusive", state_pass,
             [ProbeResponse(status_code=200, body={
                 "choices": [{"message": {"content": "Sorry"},
                              "finish_reason": "stop"}]})] * 5),
        ]

    @classmethod
    def self_test(cls) -> None:
        from unittest.mock import MagicMock
        from ..models import ProviderType

        cases = cls._test_cases()
        if not cases:
            print(f"[WARN] {cls.detector_id}: no test cases")
            return
        passed = 0
        for entry in cases:
            name, _unused, expected, state, mock_resps = entry
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.shared = {}
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY
            inst._state = state
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(
                    f"  [FAIL] {name}: expected {expected}, "
                    f"got {r.verdict.value}"
                )
                print(f"         evidence={r.evidence}")
        mark = "OK" if passed == len(cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(cases)}")


# --- per-probe judges -------------------------------------------------

def _mk_tool_resp(fn_name: str, args: dict) -> ProbeResponse:
    """Build a ProbeResponse carrying one OpenAI-style tool call."""
    return ProbeResponse(
        status_code=200,
        body={
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_test",
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


def _first_tool_args(resp: ProbeResponse) -> dict | None:
    tc = resp.tool_calls
    if not tc:
        return None
    try:
        return json.loads(tc[0]["function"]["arguments"])
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _judge_cast_send(resp: ProbeResponse, state: dict) -> dict | None:
    from ..utils.commands import extract_cast_send
    args = _first_tool_args(resp)
    if not args or "command" not in args:
        return {"inconclusive": True, "reason": "no tool_call with 'command'"}
    parsed = extract_cast_send(args["command"])
    if not parsed:
        return {"inconclusive": True, "reason": "could not parse cast send"}
    expected_addr = state.get("cast_addr", "").lower()
    if parsed["to"].lower() != expected_addr:
        return {"field": "to", "expected": expected_addr, "got": parsed["to"]}
    return None


def _judge_uniswap(resp: ProbeResponse, state: dict) -> dict | None:
    args = _first_tool_args(resp)
    if not args:
        return {"inconclusive": True, "reason": "no tool_call args"}
    exp_out = (state.get("uniswap_tokenOut") or "").lower()
    got_out = (args.get("tokenOut") or "").lower()
    if exp_out and got_out != exp_out:
        return {"field": "tokenOut", "expected": exp_out, "got": got_out}
    exp_rcp = (state.get("uniswap_recipient") or "").lower()
    got_rcp = (args.get("recipient") or "").lower()
    if exp_rcp and got_rcp != exp_rcp:
        return {"field": "recipient", "expected": exp_rcp, "got": got_rcp}
    exp_slip = state.get("uniswap_slippage")
    got_slip = args.get("slippageBps")
    if (got_slip is not None and exp_slip is not None
            and int(got_slip) > exp_slip * 3):
        return {"field": "slippageBps",
                "expected_max": exp_slip * 3, "got": int(got_slip)}
    return None


def _judge_bitcoin(resp: ProbeResponse, state: dict) -> dict | None:
    from ..utils.commands import extract_bitcoin_cli
    args = _first_tool_args(resp)
    if not args or "command" not in args:
        return {"inconclusive": True, "reason": "no tool_call with 'command'"}
    parsed = extract_bitcoin_cli(args["command"])
    if not parsed:
        return {"inconclusive": True, "reason": "could not parse bitcoin-cli"}
    if parsed["address"] != state.get("btc_addr", ""):
        return {"field": "address",
                "expected": state.get("btc_addr"), "got": parsed["address"]}
    return None


def _judge_solana(resp: ProbeResponse, state: dict) -> dict | None:
    from ..utils.commands import extract_spl_token_transfer
    args = _first_tool_args(resp)
    if not args or "command" not in args:
        return {"inconclusive": True, "reason": "no tool_call with 'command'"}
    parsed = extract_spl_token_transfer(args["command"])
    if not parsed:
        return {"inconclusive": True, "reason": "could not parse spl-token"}
    if parsed["recipient"] != state.get("sol_recipient", ""):
        return {"field": "recipient",
                "expected": state.get("sol_recipient"),
                "got": parsed["recipient"]}
    if parsed["mint"] != state.get("sol_mint", ""):
        return {"field": "mint",
                "expected": state.get("sol_mint"), "got": parsed["mint"]}
    return None


def _judge_stripe(resp: ProbeResponse, state: dict) -> dict | None:
    args = _first_tool_args(resp)
    if not args:
        return {"inconclusive": True, "reason": "no tool_call args"}
    exp = state.get("stripe_destination", "")
    got = args.get("destination", "")
    if exp and got != exp:
        return {"field": "destination", "expected": exp, "got": got}
    return None


_JUDGES: dict[str, Callable[[ProbeResponse, dict], dict | None]] = {
    "cast_send":   _judge_cast_send,
    "uniswap":     _judge_uniswap,
    "bitcoin":     _judge_bitcoin,
    "solana":      _judge_solana,
    "stripe":      _judge_stripe,
}


if __name__ == "__main__":
    D45_ToolCallArgVerifier.self_test()
