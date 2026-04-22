"""D93 ResponseTokenPadding -- detect whitespace padding in completions.

Dishonest routers may pad the visible response with trailing whitespace
(spaces, newlines, tabs) to inflate token billing.  This detector sends
a simple arithmetic prompt expecting a tiny answer and checks for
excessive trailing whitespace in the response.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

MAX_TRAILING_WS_CHARS = 50
MAX_WS_RATIO = 0.50
MAX_TOKEN_PER_CHAR_RATIO = 3.0


@detector
class D93_ResponseTokenPadding(BaseDetector):
    detector_id = "D93"
    detector_name = "ResponseTokenPadding"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect trailing whitespace padding in response content"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 10,
                "messages": [{
                    "role": "user",
                    "content": "What is 2+2? Reply with just the number.",
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D93 token padding probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content
        if not content:
            return self._inconclusive("empty content")

        stripped = content.rstrip()
        trailing_ws = len(content) - len(stripped)
        total_len = len(content)
        ws_ratio = trailing_ws / total_len if total_len > 0 else 0.0

        # Also check token-to-char inflation
        usage = r.usage
        reported_tokens = 0
        if usage:
            reported_tokens = (
                usage.get("completion_tokens")
                or usage.get("output_tokens")
                or 0
            )
        visible_chars = len(stripped)
        token_char_ratio = (
            reported_tokens / max(visible_chars, 1) if reported_tokens else 0.0
        )

        evidence = {
            "content_preview": content[:80].replace("\n", "\\n"),
            "trailing_whitespace_chars": trailing_ws,
            "total_length": total_len,
            "ws_ratio": f"{ws_ratio:.2%}",
            "reported_completion_tokens": reported_tokens,
            "token_char_ratio": f"{token_char_ratio:.2f}",
        }

        if trailing_ws > MAX_TRAILING_WS_CHARS:
            return self._fail(
                f"excessive trailing whitespace: {trailing_ws} chars",
                evidence,
            )
        if ws_ratio > MAX_WS_RATIO and total_len > 5:
            return self._fail(
                f"whitespace ratio {ws_ratio:.0%} exceeds 50%",
                evidence,
            )
        if token_char_ratio > MAX_TOKEN_PER_CHAR_RATIO and reported_tokens > 5:
            # Reasoning/thinking models (o1, o3, qwen3, deepseek-r1) include
            # internal reasoning tokens in completion_tokens — the visible
            # output is intentionally much shorter than the reported count.
            model_lower = self.config.claimed_model.lower()
            _REASONING_INDICATORS = ("o1", "o3", "o4", "thinking", "reasoning", "qwen3", "deepseek-r1", "grok-3-mini")
            if any(ind in model_lower for ind in _REASONING_INDICATORS):
                return self._pass(evidence | {
                    "note": "high ratio expected for reasoning model "
                            "(completion_tokens includes internal reasoning)",
                })
            return self._fail(
                f"token/char ratio {token_char_ratio:.1f} suspiciously high",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str, comp_tokens: int = 5) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                    "usage": {
                        "prompt_tokens": 15,
                        "completion_tokens": comp_tokens,
                        "total_tokens": 15 + comp_tokens,
                    },
                },
            )

        return [
            ("PASS: clean response",
             [_resp("4")],
             "pass"),
            ("FAIL: padded with newlines",
             [_resp("4" + "\n" * 200)],
             "fail"),
            ("FAIL: high token/char ratio",
             [_resp("4", comp_tokens=50)],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [_resp("")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D93_ResponseTokenPadding.self_test()
