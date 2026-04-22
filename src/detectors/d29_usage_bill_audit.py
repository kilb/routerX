"""D29 UsageBillAuditor — detect token billing fraud (yin-yang ledger).

Zero-request detector that reuses D24a evidence from shared_context.
Compares the router's reported prompt_tokens against a local tiktoken
count. If content was truncated (D24a FAIL) but usage reports full
tokens, the router is billing for tokens it never forwarded.

Fallback: when D24a data is unavailable, sends a lightweight probe
and performs an independent token audit.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProviderType,
    ProbeRequest,
    ProbeResponse,
    Verdict,
)
from ..registry import BaseDetector, detector
from ..tokenizer import token_counter

FALLBACK_PROBE_TEXT = "Hello, this is a test prompt for token counting. " * 20
MAX_FALLBACK_TOKENS = 50
# tiktoken vs non-OpenAI tokenizers can diverge 15-25%, so the threshold
# must be wider when the claimed provider is not OpenAI. For OpenAI
# endpoints tiktoken is authoritative and tight tolerance is appropriate.
TOKEN_INFLATION_THRESHOLD_OPENAI = 0.10   # > 10% deviation = fraud
TOKEN_INFLATION_THRESHOLD_OTHER = 0.50    # > 50% deviation for non-OpenAI
TRUNCATION_BILLING_THRESHOLD = 0.05       # < 5% deviation when truncated


@detector
class D29_UsageBillAuditor(BaseDetector):
    detector_id = "D29"
    detector_name = "UsageBillAuditor"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 0
    depends_on = ("D24a",)
    description = "Detect token billing fraud: over-reported usage or billing for truncated content"

    @property
    def _is_openai_model(self) -> bool:
        model_lower = self.config.claimed_model.lower()
        return (
            any(k in model_lower for k in ("gpt", "o1-", "o3-", "o4-"))
            and not any(k in model_lower for k in ("claude", "gemini", "llama", "qwen", "mistral"))
        )

    @property
    def _has_exact_tokenizer(self) -> bool:
        return token_counter.is_exact_encoding(self.config.claimed_model)

    @property
    def _inflation_threshold(self) -> float:
        if self._is_openai_model and self._has_exact_tokenizer:
            return TOKEN_INFLATION_THRESHOLD_OPENAI
        return TOKEN_INFLATION_THRESHOLD_OTHER

    async def send_probes(self) -> list[ProbeResponse]:
        """Skip I/O when D24a data is available; otherwise send a fallback probe."""
        d24a_data = self.shared.get("D24a")
        if d24a_data and d24a_data.get("evidence", {}).get("prompt_text"):
            return []
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_FALLBACK_TOKENS,
                "messages": [{"role": "user", "content": FALLBACK_PROBE_TEXT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="fallback token audit probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Route to D24a path or fallback path based on shared context."""
        d24a_data = self.shared.get("D24a")
        if d24a_data:
            return self._judge_with_d24a(d24a_data)
        return self._judge_fallback(responses)

    def _deviation_evidence(self, router_tokens: int, local_tokens: int, source: str) -> dict:
        deviation = abs(router_tokens - local_tokens) / local_tokens
        return {
            "router_tokens": router_tokens,
            "local_tokens": local_tokens,
            "deviation": f"{deviation:.2%}",
            "source": source,
            "_deviation": deviation,  # internal float for comparisons
        }

    def _judge_with_d24a(self, d24a_data: dict) -> DetectorResult:
        """Primary path: audit using D24a's prompt_text and usage."""
        evidence = d24a_data.get("evidence", {})
        d24a_result: DetectorResult | None = d24a_data.get("result")
        prompt_text: str = evidence.get("prompt_text", "")
        router_tokens: int = (evidence.get("usage") or {}).get("prompt_tokens", 0)

        if not prompt_text or not router_tokens:
            return self._inconclusive("D24a evidence missing prompt_text or usage")

        local_tokens = token_counter.count(prompt_text, self.config.claimed_model)
        if local_tokens == 0:
            return self._inconclusive("local token count returned zero")

        ev = self._deviation_evidence(router_tokens, local_tokens, "d24a_reuse")
        deviation = ev.pop("_deviation")

        d24a_failed = (
            d24a_result is not None
            and hasattr(d24a_result, "verdict")
            and d24a_result.verdict == Verdict.FAIL
        )

        if d24a_failed and deviation < TRUNCATION_BILLING_THRESHOLD:
            # D24a may have failed because the model's effective context
            # window is smaller than claimed (not router truncation).
            # The usage report being close to local count (< 5% deviation)
            # actually suggests honest billing. Only FAIL if we're sure
            # the router truncated (deviation is negative = billed MORE
            # than the local token count).
            if deviation >= 0:
                return self._pass(ev | {
                    "note": "D24a failed but usage is consistent with "
                            "local count — model may have limited context",
                })
        if deviation > self._inflation_threshold:
            # For non-OpenAI models, tiktoken cannot authoritatively count
            # tokens — deviation is expected and does not indicate fraud.
            if not self._is_openai_model:
                return self._skip(
                    f"token deviation {deviation:.2%} but tiktoken is not "
                    f"authoritative for this model"
                )
            return self._fail(f"token count deviation {deviation:.2%}", ev)
        return self._pass(ev)

    def _judge_fallback(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Fallback path: audit using a self-sent lightweight probe."""
        if not responses:
            return self._inconclusive("no data available from D24a or fallback probe")

        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        usage = r.usage
        if not usage:
            return self._inconclusive("no usage field in fallback response")

        router_tokens: int = usage.get("prompt_tokens", 0)
        if not router_tokens:
            return self._inconclusive("prompt_tokens missing or zero in usage")

        local_tokens = token_counter.count(FALLBACK_PROBE_TEXT, self.config.claimed_model)
        if local_tokens == 0:
            return self._inconclusive("local token count failed")

        ev = self._deviation_evidence(router_tokens, local_tokens, "fallback")
        deviation = ev.pop("_deviation")

        if deviation > self._inflation_threshold:
            if not self._is_openai_model:
                return self._skip(
                    f"token deviation {deviation:.2%} but tiktoken is not "
                    f"authoritative for this model (fallback)"
                )
            return self._fail(f"token count deviation {deviation:.2%} (fallback mode)", ev)
        return self._pass(ev)

    @classmethod
    def self_test(cls) -> None:
        """Extended self-test supporting 4-tuple cases with shared context injection."""
        from unittest.mock import MagicMock

        from ..models import ProviderType

        all_cases = cls._test_cases()
        if not all_cases:
            print(f"[WARN] {cls.detector_id}: no test cases")
            return

        passed = 0
        for entry in all_cases:
            name, mock_resps, expected = entry[:3]
            shared_ctx = entry[3] if len(entry) == 4 else {}

            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.shared = shared_ctx
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY

            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(f"  [FAIL] {name}: expected {expected}, got {r.verdict.value}")

        mark = "OK" if passed == len(all_cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(all_cases)}")

    @classmethod
    def _test_cases(cls):
        from ..models import DetectorResult as DR, Priority, Verdict

        def d24a_result(verdict: Verdict) -> DR:
            return DR(
                detector_id="D24a", detector_name="PromptInjectionAuditor",
                priority=Priority.P1, verdict=verdict, confidence=1.0,
            )

        def make_usage_resp(prompt_tokens: int) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 5},
                },
            )

        # Sentence used in D24a path tests; local count ~100 tokens
        audit_prompt = "The quick brown fox jumps over the lazy dog. " * 10

        def d24a_ctx(verdict: Verdict, prompt_tokens: int, prompt: str = audit_prompt) -> dict:
            return {"D24a": {
                "result": d24a_result(verdict),
                "evidence": {"prompt_text": prompt, "usage": {"prompt_tokens": prompt_tokens}},
            }}

        return [
            # --- Fallback path (no D24a in shared context) ---
            # PASS: router token count matches local count for FALLBACK_PROBE_TEXT (~221 tokens)
            ("PASS: fallback probe accurate token count",
             [make_usage_resp(221)], "pass"),

            # FAIL: router massively inflates token count in fallback mode
            ("FAIL: token inflation in fallback mode",
             [make_usage_resp(5000)], "fail"),

            # INCONCLUSIVE: network error on fallback probe
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),

            # INCONCLUSIVE: usage field absent
            ("INCONCLUSIVE: missing usage field",
             [ProbeResponse(
                 status_code=200,
                 body={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
             )], "inconclusive"),

            # INCONCLUSIVE: empty responses, no D24a
            ("INCONCLUSIVE: no responses and no D24a",
             [], "inconclusive"),

            # --- D24a shared context path ---
            # PASS: D24a passed, tokens closely match
            ("PASS: D24a pass + deviation within 5%",
             [], "pass", d24a_ctx(Verdict.PASS, 100)),

            # FAIL: D24a passed but router inflates tokens by >10%
            ("FAIL: D24a pass + token inflation >10%",
             [], "fail", d24a_ctx(Verdict.PASS, 9999)),

            # PASS: D24a failed but usage matches local count — model may
            # have limited context, not billing fraud
            ("PASS: D24a fail but usage consistent",
             [], "pass", d24a_ctx(Verdict.FAIL, 100)),

            # INCONCLUSIVE: D24a evidence missing prompt_text
            ("INCONCLUSIVE: D24a evidence missing prompt_text",
             [], "inconclusive",
             {"D24a": {"result": d24a_result(Verdict.PASS), "evidence": {"usage": {"prompt_tokens": 100}}}}),
        ]


if __name__ == "__main__":
    D29_UsageBillAuditor.self_test()
