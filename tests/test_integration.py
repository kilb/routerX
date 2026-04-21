"""Integration tests: route the runner through the in-process mock server
and verify each detector catches the behavior it's designed for."""
from __future__ import annotations

import socket
import threading
import time

import pytest

import src.detectors  # noqa: F401 — trigger auto-scan

from src.models import Capability, TestConfig, Verdict
from src.runner import TestRunner


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def mock_server():
    """Start tests/mock_server.py on an ephemeral port."""
    import uvicorn

    from tests.mock_server import app

    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(40):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "mock server failed to start"

    yield port

    server.should_exit = True
    thread.join(timeout=3.0)


def _run_detector(port: int, detector_id: str, behavior: str) -> Verdict:
    """Run a single detector against the mock server with the given behavior header."""
    import asyncio

    config = TestConfig(
        router_endpoint=f"http://127.0.0.1:{port}/v1",
        api_key="test-key",
        extra_headers={"X-Mock-Behavior": behavior},
        capabilities=[Capability.TEXT, Capability.TOOL_CALLING],
        timeout=10.0,
        min_request_interval=0.0,
    )
    runner = TestRunner(config, only=[detector_id])
    report = asyncio.run(runner.run_all())
    matching = [r for r in report.results if r.detector_id == detector_id]
    assert matching, f"no result for {detector_id}"
    return matching[0].verdict


# Test matrix notes:
# - "honest" mock echoes the prompt; many detectors FAIL because the echo
#   lacks the expected format (e.g., D25 needs 800 BETAs, D11 needs the
#   canary nonce). This correctly shows what a non-compliant-but-naive
#   router would produce. True PASS requires a real LLM backing.
# - Attack behaviors (cap_output, inject_system, etc.) should always FAIL.
@pytest.mark.parametrize("behavior,detector_id,expected", [
    # D25 — BETA count: mock echo has < 400 BETAs
    ("honest", "D25", Verdict.FAIL),          # echo lacks 800 BETAs
    ("cap_output", "D25", Verdict.FAIL),      # explicit cap
    # D11 — canary nonce integrity
    ("honest", "D11", Verdict.INCONCLUSIVE),  # echo lacks nonce but no injection → inconclusive
    ("inject_system", "D11", Verdict.FAIL),   # prompt injection succeeds
    # D15 — guardrail
    ("honest", "D15", Verdict.INCONCLUSIVE),  # marker missing + no SQL → inconclusive
    ("bypass_safety", "D15", Verdict.FAIL),   # SQL produced
    # D28 — session crosstalk (no leakage in honest, leakage in attack)
    ("honest", "D28", Verdict.PASS),          # echoes don't leak GALAXY_99
    ("session_crosstalk", "D28", Verdict.FAIL),
])
def test_detector_vs_mock_behavior(mock_server, behavior, detector_id, expected):
    assert _run_detector(mock_server, detector_id, behavior) == expected


@pytest.mark.parametrize("behavior,detector_id,expected", [
    # --- financial / S0 ---
    ("swap_address", "D47", Verdict.FAIL),        # address consistency
    # --- supply chain / S0 ---
    ("tamper_pip_typosquat", "D45b", Verdict.FAIL),   # pip install pyyyaml
    ("tamper_npm_typosquat", "D45b", Verdict.FAIL),   # npm install loadash
    ("tamper_installer_url", "D45c", Verdict.FAIL),   # rust/homebrew/cert-mgr/git-clone redirected
    # --- P0 severe ---
    ("bare_model_no_safety", "D40", Verdict.FAIL),  # bare open-source model, no safety layer
    ("low_entropy_digits", "D41", Verdict.FAIL),  # bare model mode collapse
    ("gateway_error", "D30", Verdict.FAIL),       # Cloudflare fingerprint + CF-RAY
    ("collapse_parallel_tools", "D16c", Verdict.FAIL),  # parallel tool calls collapsed
    ("inject_hidden_system", "D81", Verdict.FAIL),  # router-injected hidden system prompt
    # --- P1 quality ---
    ("trim_context", "D42", Verdict.FAIL),
    ("drop_json_format", "D52", Verdict.FAIL),
    ("ignore_tool_choice", "D56", Verdict.FAIL),
    ("pre_2023_model", "D59", Verdict.FAIL),
    ("truncate_mid", "D24a", Verdict.FAIL),       # middle canary dropped
    ("trim_history", "D24c", Verdict.FAIL),       # multi-turn history trimmed
    ("fake_usage", "D29", Verdict.FAIL),          # yin-yang ledger
    ("inflate_reasoning_tokens", "D82", Verdict.FAIL),  # hidden thinking token inflation
    ("inflate_completion_tokens", "D83", Verdict.FAIL),  # output token inflation
    ("fake_stream", "D32a", Verdict.FAIL),        # 2-chunk streaming
    ("chunky_stream", "D64", Verdict.FAIL),
    ("drop_logprobs", "D62", Verdict.FAIL),  # OpenAI format should support logprobs
    ("drop_logit_bias", "D70", Verdict.FAIL),
    ("inject_zero_width", "D84", Verdict.FAIL),
    ("compress_context", "D86", Verdict.FAIL),
    ("pad_response", "D93", Verdict.FAIL),
    ("echo_prompt", "D94", Verdict.FAIL),
    ("dedup_cache", "D95", Verdict.FAIL),
    ("inject_hidden_turn", "D97", Verdict.FAIL),
    # --- P2 warnings ---
    ("clamp_max_tokens", "D43", Verdict.FAIL),
    ("drop_top_p", "D44", Verdict.FAIL),
    ("drop_temperature", "D61", Verdict.FAIL),
    ("drop_stop_seq", "D51", Verdict.FAIL),
    ("fixed_response_id", "D57", Verdict.FAIL),
    ("style_mismatch", "D65", Verdict.FAIL),
    ("inject_stop_seq", "D37", Verdict.FAIL),     # truncated at first \n\n
    ("drop_frequency_penalty", "D68", Verdict.FAIL),
    ("wrong_model_field", "D87", Verdict.FAIL),
    ("strip_unicode", "D96", Verdict.FAIL),
    ("artificial_delay", "D91", Verdict.FAIL),
    # --- New detectors ---
    ("tamper_stream", "D110", Verdict.FAIL),      # stream content diverges from non-stream
    ("premature_stream", "D111", Verdict.FAIL),   # premature stream termination
    ("multi_hop", "D114", Verdict.FAIL),          # multi-hop proxy headers
    ("leak_credentials", "D116", Verdict.FAIL),   # credential leak in error response
    ("leak_headers", "D117", Verdict.FAIL),       # sensitive headers leaked
    ("inject_tool", "D118", Verdict.FAIL),        # unauthorized tool injected
    ("reorder_tools", "D119", Verdict.FAIL),      # collapsed parallel tools + dup IDs
    ("rewrite_response", "D122", Verdict.FAIL),   # response rewritten with branding
    # --- D115/D123/D112/D113 new detectors ---
    ("strip_system_nonce", "D115", Verdict.FAIL),  # system message stripped
    ("truncate_bill", "D123", Verdict.FAIL),       # truncated output billed high
    ("bad_reasoning", "D112", Verdict.FAIL),       # wrong answer, no reasoning
    ("inconsistent_reasoning", "D113", Verdict.FAIL),  # inconsistent backend routing
])
def test_attack_vector_matrix(mock_server, behavior, detector_id, expected):
    """Full detection matrix: each attack behavior caught by its targeted detector."""
    assert _run_detector(mock_server, detector_id, behavior) == expected
