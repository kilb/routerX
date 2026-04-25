from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..config import KNOWN_FAKE_PATTERNS, KNOWN_PROVIDER_HEADERS

# Non-standard gateway header names that indicate middleware interception.
# Only includes headers from known proxy/gateway frameworks (oneapi / new-api /
# Poe). CDN headers (Cloudflare CF-RAY, Akamai, CloudFront, Fastly) are
# deliberately EXCLUDED: legitimate providers like Anthropic and OpenAI
# themselves sit behind CDNs, so these headers are expected in normal traffic.
GATEWAY_HEADER_INDICATORS: frozenset[str] = frozenset({
    "x-oneapi-version",
    "x-new-api-version",
    "x-forwarded-by-oneapi",
    "x-poe-ray-id",
    "x-litellm-version",
    "x-litellm-model",
    "x-vllm-version",
    "x-ai-gateway",
    "x-gateway-provider",
    "x-relay-id",
    "x-proxy-by",
    "x-openrouter-model",
    "x-openai-proxy",
})

# Models used in probes: use well-known names that legitimate providers will
# accept or reject with a standard error (not a gateway-level interception).
PROBE_MODEL_OVERFLOW = "claude-sonnet-4-20250514"
PROBE_MODEL_FAKE = "claude-3-opus-20240229-beta-internal-test"


def _find_gateway_fingerprint(raw: str) -> str | None:
    """Return the first matching fake-error pattern found in raw, or None."""
    lowered = raw.lower()
    return next(
        (pattern for pattern in KNOWN_FAKE_PATTERNS if pattern in lowered),
        None,
    )


def _find_nonstandard_header(headers: dict[str, str]) -> str | None:
    """Return the first non-standard gateway header key found, or None."""
    lowered_keys = {k.lower() for k in headers}
    match = lowered_keys & GATEWAY_HEADER_INDICATORS
    return next(iter(match), None)


def _is_standard_error_body(body: dict | None) -> bool:
    """Return True if body looks like a standard provider error response."""
    if not body:
        return False
    # OpenAI: {"error": {"type": "...", ...}}
    if "error" in body and isinstance(body["error"], dict):
        return True
    # Anthropic: {"type": "error", "error": {...}}
    if body.get("type") == "error" and "error" in body:
        return True
    # AWS Bedrock: {"__type": "ValidationException", ...}
    if "__type" in body:
        return True
    return False


@detector
class D30_ErrorPathForensics(BaseDetector):
    detector_id = "D30"
    detector_name = "ErrorPathForensics"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect web-gateway fingerprints in error-path responses"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send three deliberately invalid requests and capture their error responses."""
        probe_30a = ProbeRequest(
            payload={
                "model": PROBE_MODEL_OVERFLOW,
                "temperature": 2.5,
                "messages": [{"role": "user", "content": "hi"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="30a: temperature overflow (above all provider limits)",
        )
        probe_30b = ProbeRequest(
            payload={
                "model": PROBE_MODEL_FAKE,
                "messages": [{"role": "user", "content": "hi"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="30b: non-existent model name",
        )
        probe_30c = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": -1,
                "messages": [{"role": "user", "content": "hi"}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="30c: negative max_tokens",
        )
        responses = []
        for probe in (probe_30a, probe_30b, probe_30c):
            responses.append(await self.client.send(probe))
        return responses

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Inspect each error response for gateway fingerprints."""
        probe_labels = ("30a", "30b", "30c")
        evidence: dict = {"probes": {}}

        for label, r in zip(probe_labels, responses):
            if r.is_network_error:
                evidence["probes"][label] = {"result": "network_error", "error": r.error}
                continue

            # Check raw body text for known fake-error patterns.
            fingerprint = _find_gateway_fingerprint(r.raw_text)
            if fingerprint:
                return self._fail(
                    f"gateway fingerprint detected: {fingerprint}",
                    {
                        "probe": label,
                        "fingerprint": fingerprint,
                        "status_code": r.status_code,
                        "raw_snippet": r.raw_text[:300],
                    },
                )

            # Check response headers for non-standard gateway keys.
            bad_header = _find_nonstandard_header(r.headers)
            if bad_header:
                return self._fail(
                    f"non-standard gateway header detected: {bad_header}",
                    {
                        "probe": label,
                        "header": bad_header,
                        "status_code": r.status_code,
                    },
                )

            is_standard = _is_standard_error_body(r.body)
            evidence["probes"][label] = {
                "status_code": r.status_code,
                "standard_error_format": is_standard,
                "body_snippet": r.raw_text[:200] if r.raw_text else "",
            }

        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def make_openai_error(status: int = 400) -> ProbeResponse:
            return ProbeResponse(
                status_code=status,
                body={"error": {"type": "invalid_request_error", "message": "bad param"}},
                raw_text='{"error": {"type": "invalid_request_error", "message": "bad param"}}',
                headers={"x-request-id": "req-abc123"},
            )

        def make_anthropic_error(status: int = 400) -> ProbeResponse:
            return ProbeResponse(
                status_code=status,
                body={"type": "error", "error": {"type": "invalid_request_error", "message": "bad param"}},
                raw_text='{"type": "error", "error": {"type": "invalid_request_error", "message": "bad param"}}',
                headers={"request-id": "req-xyz"},
            )

        def make_html_response() -> ProbeResponse:
            html = "<html><body>Cloudflare Ray ID: 1234abc</body></html>"
            return ProbeResponse(
                status_code=403,
                body=None,
                raw_text=html,
                headers={"content-type": "text/html"},
            )

        def make_oneapi_response() -> ProbeResponse:
            body = '{"error": {"type": "new_api_error", "message": "quota exceeded"}}'
            return ProbeResponse(
                status_code=429,
                body={"error": {"type": "new_api_error", "message": "quota exceeded"}},
                raw_text=body,
                headers={"content-type": "application/json"},
            )

        def make_gateway_header_response() -> ProbeResponse:
            return ProbeResponse(
                status_code=400,
                body={"error": {"type": "invalid_request_error", "message": "bad param"}},
                raw_text='{"error": {"type": "invalid_request_error", "message": "bad param"}}',
                headers={"x-oneapi-version": "3.0.0", "content-type": "application/json"},
            )

        def make_network_error() -> ProbeResponse:
            return ProbeResponse(status_code=0, error="TIMEOUT")

        return [
            # PASS: all three probes return standard OpenAI error format
            ("PASS: standard OpenAI error responses",
             [make_openai_error(), make_openai_error(404), make_openai_error(422)],
             "pass"),

            # PASS: standard Anthropic error format
            ("PASS: standard Anthropic error responses",
             [make_anthropic_error(), make_anthropic_error(), make_anthropic_error()],
             "pass"),

            # FAIL: first probe returns HTML (web-gateway fingerprint)
            ("FAIL: HTML in first probe response",
             [make_html_response(), make_openai_error(), make_openai_error()],
             "fail"),

            # FAIL: second probe returns new_api_error fingerprint
            ("FAIL: new_api_error fingerprint in second probe",
             [make_openai_error(), make_oneapi_response(), make_openai_error()],
             "fail"),

            # FAIL: third probe returns cloudflare fingerprint
            ("FAIL: cloudflare fingerprint in third probe",
             [make_openai_error(), make_openai_error(),
              ProbeResponse(
                  status_code=403,
                  raw_text="Error 403: cloudflare blocked your request. Ray ID: abc",
                  headers={},
              )],
             "fail"),

            # FAIL: non-standard gateway header detected
            ("FAIL: x-oneapi-version header present",
             [make_gateway_header_response(), make_openai_error(), make_openai_error()],
             "fail"),

            # INCONCLUSIVE: all probes are network errors (handled by base class,
            # but verify judge handles individual network errors gracefully)
            ("PASS: network errors treated as inconclusive probe data",
             [make_network_error(), make_openai_error(), make_openai_error()],
             "pass"),
        ]


if __name__ == "__main__":
    D30_ErrorPathForensics.self_test()
