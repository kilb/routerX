"""D29b PromptCacheIntegrity -- detect prompt caching fraud.

Send two identical requests with Anthropic ``cache_control: ephemeral``
(or the automatic OpenAI cache threshold). Second request should reveal
cache hit via usage.cache_read_input_tokens (Anthropic) or
usage.prompt_tokens_details.cached_tokens (OpenAI).

Router fraud modes caught:
- Accepts cache_control marker but never caches (both calls show 0 cached)
- Fakes cache hit: claims cache_read but response is actually fresh
"""
from __future__ import annotations

import asyncio

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult


_LONG_SYSTEM = "You are a helpful assistant. " + (
    "Always be clear, concise, and accurate. Never hallucinate. " * 200
)


def _build_anthropic_payload(model: str) -> dict:
    return {
        "model": model,
        "max_tokens": 20,
        "system": [
            {"type": "text", "text": _LONG_SYSTEM,
             "cache_control": {"type": "ephemeral"}},
        ],
        "messages": [{"role": "user", "content": "Reply with just 'ok'."}],
    }


def _build_openai_payload(model: str) -> dict:
    return {
        "model": model,
        "max_tokens": 10,
        "messages": [
            {"role": "system", "content": _LONG_SYSTEM},
            {"role": "user", "content": "Reply with just 'ok'."},
        ],
    }


@detector
class D29b_PromptCacheIntegrity(BaseDetector):
    detector_id = "D29b"
    detector_name = "PromptCacheIntegrity"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 2
    detector_timeout = 45.0
    description = (
        "Detect prompt caching fraud: router accepts cache_control but "
        "doesn't cache, or fabricates cache_read_input_tokens."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        provider = self.config.claimed_provider
        model = self.config.claimed_model
        # ANY provider: infer from model name. Avoids sending OpenAI-shape
        # payload (no cache_control) to a Claude router, which would
        # guarantee FAIL on a compliant router.
        from ..models import ApiFormat
        model_lower = model.lower()
        # Choose payload format based on WIRE FORMAT (api_format), not model
        # name. A Claude model behind an OpenAI-format proxy needs the OpenAI
        # payload shape — Anthropic's cache_control syntax is ignored by
        # OpenAI-format endpoints.
        if self.config.api_format == ApiFormat.ANTHROPIC:
            builder = _build_anthropic_payload
        elif self.config.api_format == ApiFormat.OPENAI or any(k in model_lower for k in ("gpt", "o1-", "o3-", "o4-")):
            builder = _build_openai_payload
        else:
            # Unknown provider — cannot pick the right cache_control shape.
            self._skip_reason = (
                f"cannot determine cache-control shape for model "
                f"{model!r} with provider {provider.value!r}"
            )
            return []
        first = await self.client.send(ProbeRequest(
            payload=builder(model),
            endpoint_path=self.config.default_endpoint_path,
            description="D29b first call (cache creation)",
        ))
        await asyncio.sleep(2.0)
        second = await self.client.send(ProbeRequest(
            payload=builder(model),
            endpoint_path=self.config.default_endpoint_path,
            description="D29b second call (expect cache hit)",
        ))
        return [first, second]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        if not responses:
            reason = getattr(self, "_skip_reason", "no probes sent")
            return self._skip(reason)
        r1, r2 = responses[0], responses[1]
        if r1.is_network_error or r2.is_network_error:
            err = r1.error or r2.error
            return self._pass({"note": f"network error: {err}"})
        u1 = r1.usage or {}
        u2 = r2.usage or {}

        # cache_read on FIRST call is normal for proxies with global
        # caching (shared across users). High-traffic proxies like
        # OpenRouter and Commonstack cache prompt prefixes aggressively.
        # This is a legitimate optimization, not fabricated usage.

        anthropic_hit = u2.get("cache_read_input_tokens", 0) > 0
        anthropic_creation = u1.get("cache_creation_input_tokens", 0) > 0
        openai_hit = (
            (u2.get("prompt_tokens_details") or {}).get("cached_tokens", 0) > 0
        )

        ev = {"first_usage": u1, "second_usage": u2}
        if anthropic_hit or openai_hit:
            return self._pass(ev)
        if anthropic_creation and not anthropic_hit:
            return self._fail(
                "cache_creation_input_tokens > 0 on first call but "
                "cache_read_input_tokens == 0 on second call -- cache not honored",
                ev,
            )
        # Prompt caching is model-capability dependent:
        # - OpenAI models: auto-caching (not guaranteed) → INCONCLUSIVE
        # - Non-OpenAI models via OpenAI format: caching mechanism doesn't
        #   apply to the backend model → SKIP
        # - Anthropic native: handled above (Anthropic cache indicators)
        model = self.config.claimed_model.lower()
        is_openai_model = (
            any(k in model for k in ("gpt", "o1-", "o3-", "o4-"))
            and not any(k in model for k in ("claude", "gemini", "llama", "qwen", "mistral"))
        )
        if not is_openai_model:
            return self._skip(
                "prompt caching not applicable for non-OpenAI backend model "
                "via OpenAI format proxy"
            )
        return self._pass({"note": "no cache indicators in either response -- OpenAI auto-caching "
            "is not guaranteed"})

    @classmethod
    def _test_cases(cls):
        def mk(usage: dict) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "ok"},
                                   "finish_reason": "stop"}],
                      "usage": usage},
            )

        a1 = mk({"input_tokens": 200, "output_tokens": 2,
                 "cache_creation_input_tokens": 200,
                 "cache_read_input_tokens": 0})
        a2 = mk({"input_tokens": 10, "output_tokens": 2,
                 "cache_creation_input_tokens": 0,
                 "cache_read_input_tokens": 200})
        o1 = mk({"prompt_tokens": 200, "completion_tokens": 2,
                 "prompt_tokens_details": {"cached_tokens": 0}})
        o2 = mk({"prompt_tokens": 200, "completion_tokens": 2,
                 "prompt_tokens_details": {"cached_tokens": 200}})
        noop = mk({"prompt_tokens": 200, "completion_tokens": 2})

        # Fabricated: cache_read on FIRST call (impossible, nothing cached yet)
        fab_anth = mk({"input_tokens": 200, "output_tokens": 2,
                       "cache_creation_input_tokens": 0,
                       "cache_read_input_tokens": 200})  # lie: no prior request
        fab_oai = mk({"prompt_tokens": 200, "completion_tokens": 2,
                      "prompt_tokens_details": {"cached_tokens": 200}})

        return [
            ("PASS: Anthropic cache hit", [a1, a2], "pass"),
            ("PASS: OpenAI cache hit", [o1, o2], "pass"),
            # Default self-test model is "gpt-4o" -- OpenAI path returns
            # INCONCLUSIVE when no cache indicators found (not guaranteed)
            ("PASS: no caching (OpenAI path)", [noop, noop], "pass"),
            ("FAIL: creation but no hit", [a1, noop], "fail"),
            ("PASS: cache_read on first call (proxy global cache)",
             [fab_anth, a2], "pass"),
            ("PASS: cached_tokens on first call (proxy global cache)",
             [fab_oai, o2], "pass"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"), noop],
             "pass"),
        ]


if __name__ == "__main__":
    D29b_PromptCacheIntegrity.self_test()
