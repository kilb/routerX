from __future__ import annotations

"""D53 MetadataCompleteness — detect stripped or fabricated usage metadata.

With direct access: compare router usage fields and system_fingerprint against
a real provider baseline. Missing fields in the router response → FAIL.

Without direct access (degraded): verify that the router at minimum returns
prompt_tokens and completion_tokens as distinct values (not collapsed into a
single total_tokens-only blob).
"""

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

PROBE_PROMPT = (
    "What are the latest AI safety research developments in 2026? "
    "Please cite sources."
)
MAX_TOKENS = 256

# Fields a well-behaved OpenAI-compatible provider must return in usage.
REQUIRED_USAGE_FIELDS: frozenset[str] = frozenset({"prompt_tokens", "completion_tokens"})


def _missing_usage_fields(usage: dict | None) -> list[str]:
    """Return list of REQUIRED_USAGE_FIELDS absent from usage dict."""
    if not usage:
        return list(REQUIRED_USAGE_FIELDS)
    return [f for f in REQUIRED_USAGE_FIELDS if f not in usage]


def _usage_is_collapsed(usage: dict) -> bool:
    """Return True when prompt_tokens equals total_tokens (collapsed billing)."""
    prompt = usage.get("prompt_tokens")
    total = usage.get("total_tokens")
    if prompt is None or total is None:
        return False
    return prompt == total and usage.get("completion_tokens") is None


@detector
class D53_MetadataCompleteness(BaseDetector):
    detector_id = "D53"
    detector_name = "MetadataCompleteness"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 2
    description = "Detect missing or stripped usage metadata fields in router responses"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send one probe through the router and optionally one through direct."""
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": PROBE_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D53 metadata completeness probe",
        )
        router_resp = await self.client.send(probe)
        if not self.has_direct:
            return [router_resp]

        async with self.make_direct_client() as dc:
            direct_resp = await dc.send(probe)
        return [router_resp, direct_resp]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare metadata fields; degrade gracefully when no direct baseline."""
        router_resp = responses[0]

        if router_resp.is_network_error:
            return self._inconclusive(router_resp.error or "network error")
        if router_resp.status_code != 200:
            return self._inconclusive(f"unexpected status {router_resp.status_code}")

        router_usage = router_resp.usage

        # Without direct baseline: check that the minimal required fields exist.
        if len(responses) < 2:
            return self._judge_degraded(router_usage, router_resp)

        direct_resp = responses[1]
        return self._judge_with_direct(router_usage, router_resp, direct_resp)

    # ---------- private helpers ----------

    def _judge_degraded(
        self, router_usage: dict | None, router_resp: ProbeResponse,
    ) -> DetectorResult:
        """Check minimum field presence without a direct baseline."""
        missing = _missing_usage_fields(router_usage)
        if missing:
            return self._fail_degraded(
                "missing required usage fields",
                {
                    "missing_fields": missing,
                    "router_usage": router_usage,
                    "mode": "degraded",
                },
            )
        assert router_usage is not None  # narrowing: missing would have triggered above
        if _usage_is_collapsed(router_usage):
            return self._fail_degraded(
                "usage fields collapsed: prompt_tokens equals total_tokens",
                {"router_usage": router_usage, "mode": "degraded"},
            )
        return self._pass({"router_usage": router_usage, "mode": "degraded"})

    def _judge_with_direct(
        self,
        router_usage: dict | None,
        router_resp: ProbeResponse,
        direct_resp: ProbeResponse,
    ) -> DetectorResult:
        """Compare router metadata against direct-provider baseline."""
        if direct_resp.is_network_error:
            # Fall back to degraded check when direct call fails.
            return self._judge_degraded(router_usage, router_resp)

        direct_usage = direct_resp.usage
        missing = _missing_usage_fields(router_usage)
        if missing:
            return self._fail(
                "router stripped required usage fields",
                {
                    "missing_fields": missing,
                    "router_usage": router_usage,
                    "direct_usage": direct_usage,
                },
            )

        # Check system_fingerprint presence: if direct has it, router must too.
        direct_has_fingerprint = bool(
            direct_resp.body and direct_resp.body.get("system_fingerprint")
        )
        router_has_fingerprint = bool(
            router_resp.body and router_resp.body.get("system_fingerprint")
        )
        if direct_has_fingerprint and not router_has_fingerprint:
            return self._fail(
                "router stripped system_fingerprint",
                {
                    "direct_system_fingerprint": direct_resp.body.get("system_fingerprint"),
                    "router_usage": router_usage,
                    "direct_usage": direct_usage,
                },
            )

        return self._pass(
            {
                "router_usage": router_usage,
                "direct_usage": direct_usage,
                "router_has_fingerprint": router_has_fingerprint,
            }
        )

    @classmethod
    def _test_cases(cls):
        """Self-test cases covering PASS, FAIL, degraded, and edge scenarios.

        Note: self_test() uses MagicMock for config, so has_direct is always
        True during tests. Test cases therefore supply two responses each.
        Direct-only degraded logic is exercised via direct_resp with network error.
        """
        def make_router(usage: dict | None, fingerprint: str | None = None) -> ProbeResponse:
            body: dict = {
                "choices": [{"message": {"content": "AI safety in 2026..."}, "finish_reason": "stop"}],
            }
            if usage is not None:
                body["usage"] = usage
            if fingerprint is not None:
                body["system_fingerprint"] = fingerprint
            return ProbeResponse(status_code=200, body=body)

        def make_direct(usage: dict | None, fingerprint: str | None = "fp-abc") -> ProbeResponse:
            body: dict = {
                "choices": [{"message": {"content": "AI safety baseline..."}, "finish_reason": "stop"}],
            }
            if usage is not None:
                body["usage"] = usage
            if fingerprint is not None:
                body["system_fingerprint"] = fingerprint
            return ProbeResponse(status_code=200, body=body)

        full_usage = {"prompt_tokens": 42, "completion_tokens": 80, "total_tokens": 122}
        no_prompt = {"completion_tokens": 80, "total_tokens": 80}
        no_completion = {"prompt_tokens": 42, "total_tokens": 42}
        no_usage: dict | None = None
        direct_network_err = ProbeResponse(status_code=0, error="TIMEOUT")

        return [
            # PASS: router has all required fields and direct baseline matches.
            (
                "PASS: full usage present with direct",
                [make_router(full_usage, "fp-xyz"), make_direct(full_usage)],
                "pass",
            ),
            # FAIL: router missing prompt_tokens compared to direct baseline.
            (
                "FAIL: router missing prompt_tokens",
                [make_router(no_prompt), make_direct(full_usage)],
                "fail",
            ),
            # FAIL: router missing completion_tokens compared to direct baseline.
            (
                "FAIL: router missing completion_tokens",
                [make_router(no_completion), make_direct(full_usage)],
                "fail",
            ),
            # FAIL: router has no usage at all while direct does.
            (
                "FAIL: router returns no usage dict",
                [make_router(no_usage), make_direct(full_usage)],
                "fail",
            ),
            # FAIL: direct has system_fingerprint but router stripped it.
            (
                "FAIL: router stripped system_fingerprint",
                [make_router(full_usage, None), make_direct(full_usage, "fp-abc")],
                "fail",
            ),
            # PASS (degraded): direct times out but router has full usage.
            (
                "PASS degraded: direct unavailable, router usage complete",
                [make_router(full_usage), direct_network_err],
                "pass",
            ),
            # FAIL (degraded): direct times out and router usage missing fields.
            (
                "FAIL degraded: direct unavailable, router missing prompt_tokens",
                [make_router(no_prompt), direct_network_err],
                "fail",
            ),
            # INCONCLUSIVE: router itself returns network error.
            (
                "INCONCLUSIVE: router network error",
                [ProbeResponse(status_code=0, error="TIMEOUT"), make_direct(full_usage)],
                "inconclusive",
            ),
            # INCONCLUSIVE: router returns non-200 status.
            (
                "INCONCLUSIVE: router 503",
                [ProbeResponse(status_code=503, body=None), make_direct(full_usage)],
                "inconclusive",
            ),
        ]


if __name__ == "__main__":
    D53_MetadataCompleteness.self_test()
