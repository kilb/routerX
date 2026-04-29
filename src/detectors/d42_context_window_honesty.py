"""D42 ContextWindowHonesty -- compare reported vs local prompt_tokens.

A compliant router should either:
  (a) return ``usage.prompt_tokens`` close to the local tiktoken count, OR
  (b) reject the request with a 4xx ``context_length_exceeded`` error.

Fraud modes caught:
  - router silently trims the prompt and reports the trimmed count as full
  - router fabricates a plausible-looking number unrelated to the payload
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProviderType,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector
from ..tokenizer import token_counter

# ~15k tokens of VARIED filler: uses diverse sentences to prevent tokenizer
# compression from skewing the ratio. Repeated text like "The quick brown fox"
# x 1500 compresses very differently across tokenizers (BPE vs SentencePiece),
# causing massive ratio divergence that looks like truncation but isn't.
_FILLER_SENTENCES = [
    "The ancient lighthouse stood on a rocky cliff overlooking the harbor.",
    "A golden retriever chased seagulls along the sandy beach at dawn.",
    "The baker kneaded fresh dough while listening to classical music.",
    "Heavy rain drummed against the tin roof of the small cottage.",
    "A fleet of cargo ships waited in the channel for the tide to turn.",
    "The professor scribbled equations across three chalkboards in succession.",
    "Wildflowers bloomed in unexpected patches along the highway median.",
    "The clockmaker adjusted the tiny springs with a jeweler's loupe.",
    "A troupe of street performers drew a large crowd near the fountain.",
    "The astronomer pointed her telescope toward the constellation Orion.",
    "Fresh snow blanketed the mountain village overnight without warning.",
    "The old typewriter still produced crisp letters on onion-skin paper.",
    "A squadron of pelicans glided low over the glassy morning lake.",
    "The carpenter measured each plank twice before making a single cut.",
    "Dense fog rolled through the valley and settled over the vineyards.",
]
# ~15k tokens: cycle through 15 varied sentences ~100 times each.
_FILLER = " ".join(
    _FILLER_SENTENCES[i % len(_FILLER_SENTENCES)] for i in range(1500)
)
_TAIL_MARKER = "ENDMARKER_9F7A2C"

# Fallback used by ``self_test`` when ``send_probes`` never ran.
_TEST_FALLBACK_LOCAL = 15000

# Ratios on reported/local prompt_tokens. Non-OpenAI providers use a
# different tokenizer than tiktoken, so allow wider divergence to avoid
# false positives from legitimate tokenizer differences (~15-25%).
# Even with varied text, SentencePiece (Gemini) and tiktoken still diverge
# by 20-40%, so thresholds must be generous.
MIN_OK_RATIO_OPENAI = 0.50
MIN_OK_RATIO_OTHER = 0.25
MARKER_GATE_RATIO_OPENAI = 0.85
# Marker missing is a weak signal — many models ignore "reply only the marker".
# Only FAIL when token ratio is also clearly low, not from tokenizer drift.
MARKER_GATE_RATIO_OTHER = 0.25


@detector
class D42_ContextWindowHonesty(BaseDetector):
    detector_id = "D42"
    detector_name = "ContextWindowHonesty"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = (
        "Detect silent input truncation or fabricated prompt_tokens by "
        "comparing router-reported usage against local tokenizer count."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = (
            f"{_FILLER}\nThe last marker in this document is: `{_TAIL_MARKER}`.\n"
            "Reply with ONLY the marker, nothing else."
        )
        self._local_count = token_counter.count(
            prompt, model=self.config.claimed_model,
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 20,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D42 long-context probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})

        # 4xx with context-length signalling is a legitimate refusal -> PASS.
        if 400 <= r.status_code < 500:
            body_str = (r.raw_text or "").lower()
            if any(kw in body_str for kw in (
                "context_length", "context length", "too long",
                "too many tokens", "maximum context",
            )):
                return self._pass({
                    "note": "legitimate 4xx refusal",
                    "status": r.status_code,
                })
            return self._pass({"note": r.error_detail})
        if r.status_code != 200:
            return self._pass({"note": r.error_detail})

        content = r.content or ""
        usage = r.usage or {}
        reported = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
        local = getattr(self, "_local_count", None) or _TEST_FALLBACK_LOCAL
        ev = {
            "reported_prompt_tokens": reported,
            "local_count": local,
            "content_excerpt": content[:200],
        }

        if reported == 0:
            return self._pass({"note": "router omitted prompt_tokens"})

        marker_echoed = _TAIL_MARKER in content
        ratio = reported / max(local, 1)
        is_openai = self.config.claimed_provider == ProviderType.OPENAI
        min_ok = MIN_OK_RATIO_OPENAI if is_openai else MIN_OK_RATIO_OTHER
        marker_gate = MARKER_GATE_RATIO_OPENAI if is_openai else MARKER_GATE_RATIO_OTHER

        if ratio < min_ok:
            return self._fail(
                f"reported prompt_tokens ({reported}) is < {min_ok:.0%} of local "
                f"count ({local}) -- router likely trimmed input",
                ev,
            )
        if not marker_echoed:
            if ratio < min_ok:
                # Already handled above; defensive guard.
                return self._fail(
                    f"tail marker missing AND ratio {ratio:.2f} < {min_ok:.0%}",
                    ev,
                )
            if ratio < marker_gate:
                return self._fail(
                    f"tail marker missing AND reported ({reported}) / local "
                    f"({local}) ratio {ratio:.2f} < {marker_gate:.0%} -- "
                    "truncation suspected",
                    ev,
                )
            # Marker missing but prompt_tokens looks full (ratio >= min_ok).
            # Could be model non-compliance rather than truncation.
            return self._pass({"note": f"tail marker missing but ratio {ratio:.2f} >= {min_ok:.0%} "
                "-- may be model non-compliance, not truncation"})
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str, prompt_tokens: int) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"content": content},
                        "finish_reason": "stop",
                    }],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": 10,
                    },
                },
            )

        pass_case = mk(f"`{_TAIL_MARKER}`", 14800)
        truncated = mk("Sorry, I don't see a marker.", 2000)
        err_4xx = ProbeResponse(
            status_code=400,
            raw_text='{"error": {"message": "context_length_exceeded"}}',
            body={"error": {"message": "context_length_exceeded"}},
        )
        net = ProbeResponse(status_code=0, error="TIMEOUT")

        # Marker missing but ratio looks full (model non-compliance)
        marker_missing_high_ratio = mk("Sorry, I don't see a marker.", 14500)

        return [
            ("PASS: marker echoed, count matches", [pass_case], "pass"),
            ("FAIL: trimmed input (low ratio)", [truncated], "fail"),
            ("PASS: 4xx context_length_exceeded", [err_4xx], "pass"),
            ("PASS: marker missing but ratio looks full",
             [marker_missing_high_ratio], "pass"),
            ("PASS: network error", [net], "pass"),
        ]


if __name__ == "__main__":
    D42_ContextWindowHonesty.self_test()
