from __future__ import annotations

"""D50 SemanticNegation — detect verdict flip on smart contract security audit.

Send a classic reentrancy-vulnerable contract to the router and (optionally) to
a direct provider endpoint.  The contract is objectively UNSAFE; if the router
returns SAFE while the direct provider returns UNSAFE, the router is suppressing
or inverting the security verdict.

Without direct access, verify only that the response contains a well-formed
VERDICT field.
"""

import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

# The classic reentrancy pattern: balance is decremented AFTER the external
# call, allowing recursive withdraw() calls before the state is updated.
_VULNERABLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // External call BEFORE state update — reentrancy vulnerability.
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER the external call.
        balances[msg.sender] = 0;
    }
}
"""

_AUDIT_PROMPT = (
    "You are a smart contract security auditor. "
    "Analyze the following Solidity contract for security vulnerabilities.\n\n"
    f"```solidity\n{_VULNERABLE_CONTRACT}```\n\n"
    "End your response with exactly these two lines:\n"
    "VERDICT: [SAFE|UNSAFE]\n"
    "CONFIDENCE: [HIGH|MEDIUM|LOW]"
)

_VERDICT_RE = re.compile(r"VERDICT:\s*(SAFE|UNSAFE)", re.IGNORECASE)

MAX_TOKENS = 512


def _extract_verdict(content: str) -> str | None:
    """Return 'SAFE' or 'UNSAFE' from response content, or None if absent."""
    m = _VERDICT_RE.search(content)
    return m.group(1).upper() if m else None


@detector
class D50_SemanticNegation(BaseDetector):
    detector_id = "D50"
    detector_name = "SemanticNegation"
    priority = Priority.P0
    judge_mode = JudgeMode.RELATIVE
    request_count = 2
    description = "Detect verdict flip on a known-UNSAFE smart contract audit"

    def _build_probe(self, description: str) -> ProbeRequest:
        return ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": _AUDIT_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=description,
        )

    async def send_probes(self) -> list[ProbeResponse]:
        """Send audit probe to the router; optionally also to the direct provider."""
        router_resp = await self.client.send(self._build_probe("D50 router audit"))
        direct_resps: list[ProbeResponse] = []
        if self.has_direct:
            async with self.make_direct_client() as dc:
                direct_resps.append(await dc.send(self._build_probe("D50 direct audit")))
        return [router_resp] + direct_resps

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare router verdict against direct verdict, or validate structure only."""
        router_resp = responses[0]

        if router_resp.is_network_error:
            return self._inconclusive(router_resp.error or "network error on router probe")

        router_content = router_resp.content
        if not router_content:
            return self._inconclusive("empty content from router")

        router_verdict = _extract_verdict(router_content)

        has_direct_resp = len(responses) > 1
        if has_direct_resp:
            return self._judge_with_direct(router_verdict, router_content, responses[1])
        return self._judge_without_direct(router_verdict, router_content)

    def _judge_with_direct(
        self,
        router_verdict: str | None,
        router_content: str,
        direct_resp: ProbeResponse,
    ) -> DetectorResult:
        """Compare router and direct verdicts; flag if router flips UNSAFE to SAFE."""
        if direct_resp.is_network_error:
            # Fall back to structure-only check when direct call fails.
            return self._judge_without_direct(router_verdict, router_content)

        direct_content = direct_resp.content
        if not direct_content:
            return self._judge_without_direct(router_verdict, router_content)

        direct_verdict = _extract_verdict(direct_content)

        if router_verdict is None:
            return self._inconclusive("router response missing VERDICT field")
        if direct_verdict is None:
            return self._inconclusive("direct response missing VERDICT field")

        evidence = {
            "router_verdict": router_verdict,
            "direct_verdict": direct_verdict,
            "router_snippet": router_content[:300],
            "direct_snippet": direct_content[:300],
        }

        if router_verdict != direct_verdict:
            return self._fail(
                f"verdict flip: router={router_verdict}, direct={direct_verdict}",
                evidence,
            )
        return self._pass(evidence)

    def _judge_without_direct(
        self, router_verdict: str | None, router_content: str
    ) -> DetectorResult:
        """Without direct access, accept any well-formed VERDICT as PASS."""
        if router_verdict is None:
            return self._inconclusive(
                "router response missing VERDICT field; cannot assess without direct"
            )
        return self._pass({
            "router_verdict": router_verdict,
            "note": "no direct endpoint; structure-only check passed",
            "router_snippet": router_content[:300],
        })

    @classmethod
    def _test_cases(cls):
        def make_resp(verdict: str, confidence: str = "HIGH") -> ProbeResponse:
            content = (
                f"This contract has a reentrancy vulnerability in withdraw().\n"
                f"VERDICT: {verdict}\nCONFIDENCE: {confidence}"
            )
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
            )

        no_verdict_resp = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "Looks fine to me."}, "finish_reason": "stop"}]},
        )
        network_err = ProbeResponse(status_code=0, error="TIMEOUT")

        return [
            # PASS with direct: both agree on UNSAFE.
            (
                "PASS: router and direct both UNSAFE",
                [make_resp("UNSAFE"), make_resp("UNSAFE")],
                "pass",
            ),
            # FAIL: router flips UNSAFE to SAFE.
            (
                "FAIL: router says SAFE, direct says UNSAFE",
                [make_resp("SAFE"), make_resp("UNSAFE")],
                "fail",
            ),
            # PASS without direct: router has a valid VERDICT.
            (
                "PASS: no direct, router returns valid VERDICT",
                [make_resp("UNSAFE")],
                "pass",
            ),
            # INCONCLUSIVE: router returns no VERDICT field (with direct that also fails).
            (
                "INCONCLUSIVE: router missing VERDICT, no direct",
                [no_verdict_resp],
                "inconclusive",
            ),
            # INCONCLUSIVE: router network error.
            (
                "INCONCLUSIVE: router network error",
                [network_err],
                "inconclusive",
            ),
            # PASS: direct network error falls back to structure-only — router has VERDICT.
            (
                "PASS: direct network error, router has valid VERDICT",
                [make_resp("UNSAFE"), network_err],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D50_SemanticNegation.self_test()
