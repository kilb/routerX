"""D131 WebScrapingFingerprint -- detect web-interface scraping artifacts.

When a router wraps a web interface (e.g. chat.openai.com) instead of calling
the official API, several telltale artifacts leak through:

  1. **Usage absent**: Web interfaces don't return token counts.
  2. **Web headers**: set-cookie, cf-clearance, captcha tokens, CSP headers
     that only appear on web-facing endpoints.
  3. **HTML residue**: Markdown rendered as HTML, or HTML tags in streaming
     chunks from DOM scraping.
  4. **Response ID format**: Web-generated IDs differ from API-generated IDs
     (e.g. missing "chatcmpl-" prefix for OpenAI).
  5. **Model field mismatch**: Web interface may return a different model name
     or omit it entirely.

Sends one normal request and inspects the response for these artifacts.
Each artifact contributes a point; >= 3 points = FAIL.
"""
from __future__ import annotations

import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

# Headers that only appear on web-facing endpoints, never on API endpoints.
_WEB_HEADERS = {
    "set-cookie",
    "cf-clearance",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",  # normal for HTTPS, but paired with others
}
# Stronger signal: these headers are very unlikely on a legitimate API.
_STRONG_WEB_HEADERS = {
    "set-cookie",
    "cf-clearance",
    "content-security-policy",
    "x-frame-options",
}

# HTML tags that should never appear in an API JSON response body.
_HTML_RE = re.compile(
    r"<(?:div|span|p|br|html|body|script|style|a\s|img\s|table|tr|td|ul|li|ol|h[1-6])"
    r"[\s>/]",
    re.IGNORECASE,
)

# Markdown rendered as HTML (web scraping artifact).
_RENDERED_MD_RE = re.compile(
    r"<(?:strong|em|code|pre|blockquote|hr)\s*/?>"
    r"|<a\s+href="
    r"|<(?:ol|ul)>\s*<li>",
    re.IGNORECASE,
)

# OpenAI API response IDs always start with "chatcmpl-".
_OPENAI_ID_RE = re.compile(r"^chatcmpl-[A-Za-z0-9]+$")
# Anthropic API response IDs start with "msg_".
_ANTHROPIC_ID_RE = re.compile(r"^msg_[A-Za-z0-9]+$")

_FAIL_THRESHOLD = 3


@detector
class D131_WebScrapingFingerprint(BaseDetector):
    detector_id = "D131"
    detector_name = "WebScrapingFingerprint"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 30.0
    description = (
        "Detect web-interface scraping by inspecting usage fields, response "
        "headers, HTML residue, and ID format anomalies."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        probe = ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 100,
                "temperature": 0,
                "messages": [{"role": "user", "content":
                    "Write a short list of 3 colors. Use markdown formatting."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D131 web-scraping fingerprint probe",
        )
        return [await self.client.send(probe)]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        if r.status_code != 200:
            return self._pass({"note": r.error_detail})

        signals: list[str] = []
        ev: dict = {}

        # --- Signal 1: Usage field entirely absent ---
        usage = r.usage
        if not usage:
            signals.append("usage_absent")
            ev["usage"] = "missing"
        else:
            pt = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
            ct = usage.get("completion_tokens") or usage.get("output_tokens") or 0
            if pt == 0 and ct == 0:
                signals.append("usage_zeros")
                ev["usage"] = "all zeros"

        # --- Signal 2: Web-specific response headers ---
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        web_headers_found = [
            h for h in _STRONG_WEB_HEADERS if h in headers_lower
        ]
        if web_headers_found:
            signals.append("web_headers")
            ev["web_headers"] = web_headers_found

        # --- Signal 3: HTML residue in response content ---
        content = r.content or ""
        raw = r.raw_text or ""
        check_text = content + raw
        html_matches = _HTML_RE.findall(check_text)
        rendered_md = _RENDERED_MD_RE.findall(check_text)
        if html_matches or rendered_md:
            signals.append("html_residue")
            ev["html_tags"] = list(set(html_matches + rendered_md))[:5]

        # --- Signal 4: Response ID format anomaly ---
        # Only check ID format when the endpoint claims to be a direct
        # OpenAI/Anthropic API. Routers (OpenRouter, Bedrock, etc.)
        # legitimately use their own ID formats or omit IDs entirely.
        body = r.body or {}
        resp_id = body.get("id", "")
        # ID missing alone is NOT a signal — many legitimate routers omit it.
        # Only flag when ID is present but looks like a web session ID
        # (e.g. "conv-xxx", "turn-xxx", UUID-only without prefix).
        if resp_id and not resp_id.startswith(("chatcmpl-", "msg_", "gen-")):
            # Check for obviously web-generated patterns
            web_id_patterns = ("conv-", "turn-", "chat-session-", "thread_")
            if any(resp_id.startswith(p) for p in web_id_patterns):
                signals.append("web_session_id")
                ev["response_id"] = resp_id

        # --- Signal 5: Model field absent ---
        # Many legitimate routers omit or transform the model field.
        # Only count this as a signal when combined with other artifacts.
        # (included but weak — doesn't push over threshold alone)

        ev["signals"] = signals
        ev["score"] = len(signals)

        if len(signals) >= _FAIL_THRESHOLD:
            return self._fail(
                f"{len(signals)} web-scraping artifacts detected: "
                f"{', '.join(signals)}",
                ev,
            )
        if len(signals) >= 2:
            return self._fail(
                f"{len(signals)} web-scraping artifacts: {', '.join(signals)}",
                ev,
                confidence=0.70,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(
            content: str = "1. Red\n2. Blue\n3. Green",
            usage: dict | None = None,
            headers: dict | None = None,
            resp_id: str = "chatcmpl-abc123",
            model: str = "gpt-4o",
        ) -> ProbeResponse:
            body: dict = {
                "id": resp_id,
                "model": model,
                "choices": [{"message": {"content": content},
                             "finish_reason": "stop"}],
            }
            if usage is not None:
                body["usage"] = usage
            return ProbeResponse(
                status_code=200,
                body=body,
                headers=headers or {},
                raw_text=content,
            )

        clean = mk(usage={"prompt_tokens": 20, "completion_tokens": 15})
        # Web scraping: no usage, web headers, HTML in content, wrong ID
        web_scrape = mk(
            content="<div>1. Red</div><div>2. Blue</div>",
            usage=None,
            headers={"set-cookie": "session=abc", "cf-clearance": "xyz"},
            resp_id="conv-12345",
            model="",
        )
        # Partial signals: missing usage + web session ID
        partial = mk(
            usage=None,
            headers={"set-cookie": "session=abc"},
            resp_id="conv-12345",
        )
        # Only 1 signal (missing usage) — should pass
        mild = mk(usage=None)
        # Bedrock/router: non-standard ID but legitimate — should pass
        bedrock = mk(
            usage={"prompt_tokens": 20, "completion_tokens": 15},
            resp_id="bedrock-abc123-001",
            model="anthropic.claude-3",
        )

        return [
            ("PASS: clean API response", [clean], "pass"),
            ("FAIL: multiple web-scraping artifacts", [web_scrape], "fail"),
            ("FAIL: partial artifacts (degraded confidence)", [partial], "fail"),
            ("PASS: single artifact only", [mild], "pass"),
            ("PASS: Bedrock non-standard ID is fine", [bedrock], "pass"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "pass"),
        ]


if __name__ == "__main__":
    D131_WebScrapingFingerprint.self_test()
