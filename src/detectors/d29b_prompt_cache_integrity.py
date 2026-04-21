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
        model_lower = model.lower()
        if provider == ProviderType.ANTHROPIC or "claude" in model_lower:
            builder = _build_anthropic_payload
        elif provider == ProviderType.OPENAI or any(k in model_lower for k in ("gpt", "o1-", "o3-", "o4-")):
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
            return self._inconclusive(
                getattr(self, "_skip_reason", "no probes sent")
            )
        r1, r2 = responses[0], responses[1]
        if r1.is_network_error or r2.is_network_error:
            err = r1.error or r2.error
            return self._inconclusive(f"network error: {err}")
        u1 = r1.usage or {}
        u2 = r2.usage or {}

        # Fraud catch: cache_read on FIRST call is semantically impossible —
        # nothing could have been cached before the first request was served.
        u1_anth_read = u1.get("cache_read_input_tokens", 0) > 0
        u1_oai_read = (
            (u1.get("prompt_tokens_details") or {}).get("cached_tokens", 0) > 0
        )
        if u1_anth_read or u1_oai_read:
            return self._fail(
                "cache_read reported on FIRST call before anything was cached "
                "-- fabricated usage numbers",
                {"first_usage": u1, "second_usage": u2},
            )

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
        # For OpenAI, auto-caching is not guaranteed even above the 1024-token
        # threshold -- return INCONCLUSIVE rather than FAIL.
        model = self.config.claimed_model.lower()
        is_openai_path = (
            self.config.claimed_provider == ProviderType.OPENAI
            or any(k in model for k in ("gpt", "o1-", "o3-", "o4-"))
        )
        if is_openai_path:
            return self._inconclusive(
                "no cache indicators in either response -- OpenAI auto-caching "
                "is not guaranteed"
            )
        return self._fail(
            "no cache indicators in either response -- router ignored cache_control",
            ev,
        )

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
            ("INCONCLUSIVE: no caching (OpenAI path)", [noop, noop], "inconclusive"),
            ("FAIL: creation but no hit", [a1, noop], "fail"),
            ("FAIL: fabricated cache_read on first call (Anthropic)",
             [fab_anth, a2], "fail"),
            ("FAIL: fabricated cached_tokens on first call (OpenAI)",
             [fab_oai, o2], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"), noop],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D29b_PromptCacheIntegrity.self_test()
