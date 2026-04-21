from __future__ import annotations

"""D50 SemanticNegation — detect verdict flip on smart contract security audit.

Send a classic reentrancy-vulnerable contract to the router and (optionally) to
a direct provider endpoint.  The contract is objectively UNSAFE; if the router
returns SAFE while the direct provider returns UNSAFE, the router is suppressing
or inverting the security verdict.

Without direct access, verify only that the response contains a well-formed
VERDICT field.
"""

import random
import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector


# Pool of known-UNSAFE contract templates. Each is parameterized with
# random identifier names per run so a router cannot whitelist the
# specific source code by hash/prefix.
def _reentrancy(contract_name: str, mapping_name: str,
                deposit_fn: str, withdraw_fn: str) -> str:
    return f"""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract_name} {{
    mapping(address => uint256) public {mapping_name};

    function {deposit_fn}() public payable {{
        {mapping_name}[msg.sender] += msg.value;
    }}

    function {withdraw_fn}() public {{
        uint256 amount = {mapping_name}[msg.sender];
        require(amount > 0, "No balance");

        (bool success, ) = msg.sender.call{{value: amount}}("");
        require(success, "Transfer failed");

        {mapping_name}[msg.sender] = 0;
    }}
}}
"""


def _unchecked_call(contract_name: str, target_fn: str) -> str:
    return f"""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract_name} {{
    address payable public recipient;

    constructor(address payable _recipient) {{
        recipient = _recipient;
    }}

    function {target_fn}(uint256 amount) public {{
        // Low-level call's success value is ignored.
        recipient.call{{value: amount}}("");
    }}
}}
"""


def _tx_origin_auth(contract_name: str, auth_fn: str) -> str:
    return f"""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {contract_name} {{
    address public owner;

    constructor() {{ owner = msg.sender; }}

    function {auth_fn}(address newOwner) public {{
        // tx.origin allows phishing via intermediate contract.
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }}
}}
"""


_VULN_POOL = [
    ("reentrancy", _reentrancy),
    ("unchecked_low_level_call", _unchecked_call),
    ("tx_origin_auth", _tx_origin_auth),
]


def _random_identifier(prefix: str) -> str:
    suffix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=4))
    return f"{prefix}_{suffix}"


def _build_vulnerable_contract() -> tuple[str, str]:
    """Return (rendered_source, vulnerability_label)."""
    label, builder = random.choice(_VULN_POOL)
    if label == "reentrancy":
        src = builder(
            _random_identifier("Vault").title().replace("_", ""),
            _random_identifier("bal"),
            _random_identifier("dep"),
            _random_identifier("wd"),
        )
    elif label == "unchecked_low_level_call":
        src = builder(
            _random_identifier("Forward").title().replace("_", ""),
            _random_identifier("sendTo"),
        )
    else:  # tx_origin_auth
        src = builder(
            _random_identifier("Admin").title().replace("_", ""),
            _random_identifier("setOwner"),
        )
    return src, label


_VERDICT_RE = re.compile(r"VERDICT:\s*(SAFE|UNSAFE)", re.IGNORECASE)
# Fallback patterns for models that don't follow exact format
_VERDICT_FALLBACK_UNSAFE = re.compile(
    r"(?:verdict|conclusion|assessment|overall)[:\s]*(?:is\s+)?(?:NOT\s+SAFE|UNSAFE|VULNERABLE|INSECURE)",
    re.IGNORECASE,
)
_VERDICT_FALLBACK_SAFE = re.compile(
    r"(?:verdict|conclusion|assessment|overall)[:\s]*(?:is\s+)?(?:SAFE|SECURE)\b(?!\s*\.?\s*(?:UNSAFE|NOT|VULNERAB))",
    re.IGNORECASE,
)

MAX_TOKENS = 512

# Keywords that would appear in a genuine vulnerability analysis of a
# known-UNSAFE contract.  Used for cross-checking when no direct endpoint
# is available: a SAFE verdict with multiple vulnerability keywords
# present is self-contradictory.
_UNSAFE_KEYWORDS: list[str] = [
    "reentrancy", "reentrant", "tx.origin", "unchecked call",
    "low-level call", "vulnerab", "unsafe", "attack vector",
    "exploit", "checks-effects-interactions", "phishing",
]

_MIN_KEYWORD_HITS = 2  # Must find at least this many to flag contradiction


def _extract_verdict(content: str) -> str | None:
    """Return 'SAFE' or 'UNSAFE' from response content, or None if absent."""
    # Primary: exact VERDICT: format
    m = _VERDICT_RE.search(content)
    if m:
        return m.group(1).upper()
    # Fallback: semantic extraction from conclusion/assessment sentences
    if _VERDICT_FALLBACK_UNSAFE.search(content):
        return "UNSAFE"
    if _VERDICT_FALLBACK_SAFE.search(content):
        return "SAFE"
    # Last resort: count vulnerability keywords — if many appear, content
    # strongly implies UNSAFE even without explicit verdict
    content_lower = content.lower()
    hits = sum(1 for kw in _UNSAFE_KEYWORDS if kw in content_lower)
    if hits >= 3:
        return "UNSAFE"
    return None


@detector
class D50_SemanticNegation(BaseDetector):
    detector_id = "D50"
    detector_name = "SemanticNegation"
    priority = Priority.P0
    judge_mode = JudgeMode.RELATIVE
    request_count = 2
    description = "Detect verdict flip on a known-UNSAFE smart contract audit"

    def _build_probe(self, description: str, contract_src: str) -> ProbeRequest:
        prompt = (
            "You are a smart contract security auditor. "
            "Analyze the following Solidity contract for security vulnerabilities.\n\n"
            f"```solidity\n{contract_src}```\n\n"
            "End your response with exactly these two lines:\n"
            "VERDICT: [SAFE|UNSAFE]\n"
            "CONFIDENCE: [HIGH|MEDIUM|LOW]"
        )
        return ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=description,
        )

    async def send_probes(self) -> list[ProbeResponse]:
        """Send audit probe to the router; optionally also to the direct provider.

        Contract source is randomized per run (vuln class + identifier names)
        so a router cannot whitelist the specific source code.
        """
        contract_src, self._vuln_label = _build_vulnerable_contract()
        router_resp = await self.client.send(
            self._build_probe("D50 router audit", contract_src)
        )
        direct_resps: list[ProbeResponse] = []
        if self.has_direct:
            async with self.make_direct_client() as dc:
                direct_resps.append(
                    await dc.send(self._build_probe("D50 direct audit", contract_src))
                )
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
        """Without direct access, cross-check VERDICT against content keywords.

        The contract is known-UNSAFE.  If the router says SAFE but the
        response body discusses vulnerabilities, the verdict contradicts
        the content -- evidence of suppression.  If SAFE with zero
        vulnerability keywords, the analysis itself is suspect (a truly
        UNSAFE contract should mention *something*), so flag as SUSPICIOUS.
        """
        if router_verdict is None:
            return self._inconclusive(
                "router response missing VERDICT field; cannot assess without direct"
            )

        if router_verdict == "UNSAFE":
            return self._pass({
                "router_verdict": router_verdict,
                "note": "UNSAFE verdict matches known-vulnerable contract",
                "router_snippet": router_content[:300],
            })

        # router_verdict == "SAFE" -- cross-check with keyword analysis
        content_lower = router_content.lower()
        matched_keywords = [
            kw for kw in _UNSAFE_KEYWORDS if kw in content_lower
        ]

        evidence = {
            "router_verdict": router_verdict,
            "matched_unsafe_keywords": matched_keywords,
            "keyword_count": len(matched_keywords),
            "router_snippet": router_content[:300],
        }

        if len(matched_keywords) >= _MIN_KEYWORD_HITS:
            return self._fail(
                "VERDICT contradicts content analysis: SAFE verdict but "
                f"{len(matched_keywords)} vulnerability keywords found",
                evidence,
            )

        # SAFE verdict with no vulnerability keywords -- suspicious because
        # the contract IS objectively vulnerable.
        return self._fail_degraded(
            "SAFE verdict on known-UNSAFE contract; no direct baseline to confirm",
            evidence,
        )

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

        # SAFE verdict with vulnerability keywords in content -- contradicts
        safe_with_vuln_keywords = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": (
                "The contract has no issues.\n"
                "Note: reentrancy patterns and unchecked call usage were reviewed.\n"
                "VERDICT: SAFE\nCONFIDENCE: HIGH"
            )}, "finish_reason": "stop"}]},
        )
        # SAFE verdict with clean content (no vuln keywords) -- still suspicious
        safe_clean = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": (
                "The contract looks perfectly fine and well-written.\n"
                "VERDICT: SAFE\nCONFIDENCE: HIGH"
            )}, "finish_reason": "stop"}]},
        )

        return [
            # PASS with direct: both agree on UNSAFE.
            (
                "PASS: router and direct both UNSAFE",
                [make_resp("UNSAFE"), make_resp("UNSAFE")],
                "pass",
            ),
            # PASS with direct: both agree on SAFE -- same verdict means no flip.
            (
                "PASS: router and direct both SAFE",
                [make_resp("SAFE"), make_resp("SAFE")],
                "pass",
            ),
            # FAIL: router flips UNSAFE to SAFE.
            (
                "FAIL: router says SAFE, direct says UNSAFE",
                [make_resp("SAFE"), make_resp("UNSAFE")],
                "fail",
            ),
            # PASS without direct: router says UNSAFE (correct for known-vulnerable).
            (
                "PASS: no direct, router returns UNSAFE VERDICT",
                [make_resp("UNSAFE")],
                "pass",
            ),
            # FAIL: no direct, SAFE verdict contradicts vulnerability keywords in content.
            (
                "FAIL: no direct, SAFE verdict contradicts content keywords",
                [safe_with_vuln_keywords],
                "fail",
            ),
            # FAIL (degraded): no direct, SAFE verdict on known-UNSAFE contract,
            # no keywords (clean SAFE is still wrong for a known-vulnerable contract).
            (
                "FAIL: no direct, SAFE verdict on known-UNSAFE contract (degraded)",
                [safe_clean],
                "fail",
            ),
            # INCONCLUSIVE: router returns no VERDICT field.
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
            # PASS: direct network error falls back; router says UNSAFE (correct).
            (
                "PASS: direct network error, router has UNSAFE VERDICT",
                [make_resp("UNSAFE"), network_err],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D50_SemanticNegation.self_test()
